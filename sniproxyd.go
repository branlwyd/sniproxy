package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"strings"
	"time"

	"github.com/golang/protobuf/proto"
	"golang.org/x/sync/errgroup"

	pb "github.com/BranLwyd/sniproxy/sniproxy_go_proto"
)

var (
	config = flag.String("config", "", "Location of config file.")

	// Config data.
	mapping        = map[string]string{} // Hostname -> destination address
	initialTimeout = 20 * time.Second    // time allowed to parse headers
	dialTimeout    = 10 * time.Second    // time allowed to dial server
	dataTimeout    = 240 * time.Second   // once connection is established, allowed idle time before connection is closed
)

func main() {
	// Parse & verify flags.
	flag.Parse()
	if *config == "" {
		log.Fatalf("--config is required")
	}

	// Read, parse, & verify config.
	cfgBytes, err := ioutil.ReadFile(*config)
	if err != nil {
		log.Fatalf("Could not read config file %q: %v", *config, err)
	}
	cfg := &pb.Config{}
	if err := proto.UnmarshalText(string(cfgBytes), cfg); err != nil {
		log.Fatalf("Could not parse config file %q: %v", *config, err)
	}
	if len(cfg.Mapping) == 0 {
		log.Fatalf("Config contains no mappings")
	}
	for i, m := range cfg.Mapping {
		if m.HostName == "" {
			log.Fatalf("Mapping at index %d has no hostname", i)
		}
		if m.Destination == "" {
			log.Fatalf("Mapping for hostname %q has no destination", m.HostName)
		}
		if _, ok := mapping[m.HostName]; ok {
			log.Fatalf("Duplicate mapping for hostname %q", m.HostName)
		}
		mapping[m.HostName] = m.Destination
	}
	if cfg.InitialTimeoutS > 0 {
		initialTimeout = time.Duration(cfg.InitialTimeoutS * float64(time.Second))
	}
	if cfg.DialTimeoutS > 0 {
		dialTimeout = time.Duration(cfg.DialTimeoutS * float64(time.Second))
	}
	if cfg.DataTimeoutS > 0 {
		dataTimeout = time.Duration(cfg.DataTimeoutS * float64(time.Second))
	}

	// Main loop: accept & handle connections
	go acceptHTTPConnections()
	acceptHTTPSConnections()
}

func acceptHTTPConnections() {
	l, err := net.Listen("tcp", ":http")
	if err != nil {
		log.Fatalf("Could not listen for HTTP connections: %v", err)
	}
	log.Printf("Accepting HTTP connections")
	for {
		c, err := l.Accept()
		if err != nil {
			log.Fatalf("Could not accept HTTPS connection: %v", err)
		}
		go handleHTTPConnection(c.(*net.TCPConn))
	}
}

var hostHeaderPrefix = []byte("Host:")

func handleHTTPConnection(c *net.TCPConn) {
	log.Printf("[%s] Accepted HTTP connection", c.RemoteAddr())
	c.SetDeadline(time.Now().Add(initialTimeout))
	defer func() {
		c.Close()
		log.Printf("[%s] Connection closed", c.RemoteAddr())
	}()
	var buf bytes.Buffer // stores bytes read while parsing headers
	s := bufio.NewScanner(io.TeeReader(c, &buf))
	s.Scan() // skip request line
	var found bool
	var hostName string
	for s.Scan() {
		ln := s.Bytes()
		if len(ln) == 0 {
			break
		}
		if bytes.HasPrefix(ln, hostHeaderPrefix) {
			found, hostName = true, string(bytes.TrimSpace(bytes.TrimPrefix(ln, hostHeaderPrefix)))
			break
		}
	}
	if err := s.Err(); err != nil {
		log.Printf("[%s] Error reading request: %v", c.RemoteAddr(), err)
		return
	}
	if !found {
		log.Printf("[%s] No host header", c.RemoteAddr())
		return
	}
	dest := mapping[hostName]
	if dest == "" {
		log.Printf("[%s] Client sent unknown hostname in Host header: %q", c.RemoteAddr(), hostName)
		return
	}
	log.Printf("[%s] Client sent hostname %q in Host header, proxying to %q", c.RemoteAddr(), hostName, dest)
	dest = net.JoinHostPort(dest, "http")
	srvConn, err := net.DialTimeout("tcp", dest, dialTimeout)
	if err != nil {
		log.Printf("[%s] Could not dial %q: %v", c.RemoteAddr(), dest, err)
		return
	}
	// No need to defer srvConn.Close() since the proxy calls below will ensure that it is closed.

	// Begin proxying.
	var eg errgroup.Group
	eg.Go(func() error { return proxy(newWriteConn(srvConn.(*net.TCPConn)), newReadConnWithPrefixedData(c, &buf)) })
	eg.Go(func() error { return proxy(newWriteConn(c), newReadConn(srvConn.(*net.TCPConn))) })
	if err := eg.Wait(); err != nil {
		log.Printf("[%s] Could not proxy to %s: %v", c.RemoteAddr(), dest, err)
	}
}

func acceptHTTPSConnections() {
	l, err := net.Listen("tcp", ":https")
	if err != nil {
		log.Fatalf("Could not listen for HTTPS connections: %v", err)
	}
	log.Printf("Accepting HTTPS connections")
	for {
		c, err := l.Accept()
		if err != nil {
			log.Fatalf("Could not accept HTTPS connection: %v", err)
		}
		go handleHTTPSConnection(c.(*net.TCPConn))
	}
}

const contentTypeHandshake = 22

func handleHTTPSConnection(c *net.TCPConn) {
	log.Printf("[%s] Accepted HTTPS connection", c.RemoteAddr())
	c.SetDeadline(time.Now().Add(initialTimeout))
	defer func() {
		c.Close()
		log.Printf("[%s] Connection closed", c.RemoteAddr())
	}()
	var buf bytes.Buffer // stores bytes read while parsing handshake message
	r := bufio.NewReader(io.TeeReader(c, &buf))
	rec, err := readRecordHeader(r) // TODO: do not assume ClientHello fits in a single record
	if err != nil {
		log.Printf("[%s] Could not read handshake record: %v", c.RemoteAddr(), err)
		return
	}
	if rec.contentType != contentTypeHandshake {
		log.Printf("[%s] Did not receive handshake record", c.RemoteAddr())
		return
	}

	hostName, err := readSNIHostNameFromHandshakeMessage(io.LimitReader(r, int64(rec.dataLength)))
	if err != nil {
		log.Printf("[%s] Could not get SNI hostname from ClientHello: %v", c.RemoteAddr(), err)
		return
	}
	dest := mapping[hostName]
	if dest == "" {
		log.Printf("[%s] Client sent unknown SNI hostname %q", c.RemoteAddr(), hostName)
		return
	}
	log.Printf("[%s] Client sent SNI hostname %q, proxying to %q", c.RemoteAddr(), hostName, dest)
	dest = net.JoinHostPort(dest, "https")
	srvConn, err := net.DialTimeout("tcp", dest, dialTimeout)
	if err != nil {
		log.Printf("[%s] Could not dial %q: %v", c.RemoteAddr(), dest, err)
		return
	}
	// No need to defer srvConn.Close() since the proxy calls below will ensure that it is closed.

	// Begin proxying.
	var eg errgroup.Group
	eg.Go(func() error { return proxy(newWriteConn(srvConn.(*net.TCPConn)), newReadConnWithPrefixedData(c, &buf)) })
	eg.Go(func() error { return proxy(newWriteConn(c), newReadConn(srvConn.(*net.TCPConn))) })
	if err := eg.Wait(); err != nil {
		log.Printf("[%s] Could not proxy to %s: %v", c.RemoteAddr(), dest, err)
	}
}

const maxRecordSize = 1 << 14

type recordHeader struct {
	contentType  byte
	majorVersion byte
	minorVersion byte
	dataLength   uint16
}

func readRecordHeader(r io.Reader) (recordHeader, error) {
	var hdr [5]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return recordHeader{}, fmt.Errorf("could not read header: %v", err)
	}
	dl := binary.BigEndian.Uint16(hdr[3:5])
	if dl > maxRecordSize {
		return recordHeader{}, fmt.Errorf("record too large: %d > %d", dl, maxRecordSize)
	}
	return recordHeader{
		contentType:  hdr[0],
		majorVersion: hdr[1],
		minorVersion: hdr[2],
		dataLength:   dl,
	}, nil
}

const handshakeTypeClientHello = 1

func readSNIHostNameFromHandshakeMessage(r io.Reader) (string, error) {
	// Handshake message type.
	hTyp, err := readUint8(r)
	if err != nil {
		return "", fmt.Errorf("could not read msg_type: %v", err)
	}
	if hTyp != handshakeTypeClientHello {
		return "", fmt.Errorf("handshake message not a ClientHello (type %d, expected %d)", hTyp, handshakeTypeClientHello)
	}

	// Handshake message length.
	hLen, err := readUint24(r)
	if err != nil {
		return "", fmt.Errorf("could not read handshake message length: %v", err)
	}
	r = io.LimitReader(r, int64(hLen))

	// ProtocolVersion (2 bytes) & Random (32 bytes)
	if err := skip(r, 34); err != nil {
		return "", fmt.Errorf("could not skip client_version & random: %v", err)
	}

	// Session ID.
	if err := skipVec8(r); err != nil {
		return "", fmt.Errorf("could not skip session_id: %v", err)
	}

	// Cipher suites.
	if err := skipVec16(r); err != nil {
		return "", fmt.Errorf("could not skip cipher_suites: %v", err)
	}

	// Compression methods.
	if err := skipVec8(r); err != nil {
		return "", fmt.Errorf("could not skip compression_methods: %v", err)
	}

	// Extensions.
	eLen, err := readUint16(r)
	if err == io.EOF {
		return "", errors.New("no extensions")
	}
	if err != nil {
		return "", fmt.Errorf("could not read extensions length: %v", err)
	}
	r = io.LimitReader(r, int64(eLen))
	for {
		eTyp, err := readUint16(r)
		if err == io.EOF {
			return "", errors.New("no SNI extension")
		}
		if err != nil {
			return "", fmt.Errorf("could not read extension_type: %v", err)
		}
		eLen, err := readUint16(r)
		if err != nil {
			return "", fmt.Errorf("could not read extension_data length: %v", err)
		}

		const extensionTypeSNI = 0
		if eTyp != extensionTypeSNI {
			// This is not an SNI extension; skip it.
			if err := skip(r, int64(eLen)); err != nil {
				return "", fmt.Errorf("could not skip extension_data: %v", err)
			}
			continue
		}
		extR := io.LimitReader(r, int64(eLen))

		// ServerNameList length.
		snlLen, err := readUint16(extR)
		if err != nil {
			return "", fmt.Errorf("could not read server_name_list length: %v", err)
		}
		extR = io.LimitReader(r, int64(snlLen))
		for {
			// NameType & length.
			nTyp, err := readUint8(extR)
			if err == io.EOF {
				return "", errors.New("SNI extension has no ServerName of type host_name")
			}
			if err != nil {
				return "", fmt.Errorf("could not read name_type: %v", err)
			}

			const nameTypeHostName = 0
			if nTyp != nameTypeHostName {
				// This is not a host_name-typed ServerName. Skip this ServerName.
				if err := skipVec16(r); err != nil {
					return "", fmt.Errorf("could not skip server_name_list entry: %v", err)
				}
				continue
			}

			// This is a host_name-typed ServerName. Read the hostname and return it.
			nLen, err := readUint16(extR)
			if err != nil {
				return "", fmt.Errorf("could not read host_name length: %v", err)
			}
			var b strings.Builder
			if _, err := io.CopyN(&b, extR, int64(nLen)); err != nil {
				return "", fmt.Errorf("could not read HostName: %v", err)
			}
			return b.String(), nil
		}
	}
}

func readUint8(r io.Reader) (uint8, error) {
	var buf [1]byte
	if _, err := io.ReadFull(r, buf[:]); err != nil {
		return 0, err
	}
	return buf[0], nil
}

// readUint16 interprets data as big-endian.
func readUint16(r io.Reader) (uint16, error) {
	var buf [2]byte
	if _, err := io.ReadFull(r, buf[:]); err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint16(buf[:]), nil
}

// readUint24 interprets data as big-endian.
func readUint24(r io.Reader) (uint32, error) {
	var buf [3]byte
	if _, err := io.ReadFull(r, buf[:]); err != nil {
		return 0, err
	}
	return uint32(buf[0])<<16 | uint32(buf[1])<<8 | uint32(buf[2]), nil
}

func skip(r io.Reader, sz int64) error {
	_, err := io.CopyN(ioutil.Discard, r, sz)
	return err
}

func skipVec8(r io.Reader) error {
	vl, err := readUint8(r)
	if err != nil {
		return fmt.Errorf("could not read length: %v", err)
	}
	if err := skip(r, int64(vl)); err != nil {
		return fmt.Errorf("could not skip content: %v", err)
	}
	return nil
}

func skipVec16(r io.Reader) error {
	vl, err := readUint16(r)
	if err != nil {
		return fmt.Errorf("could not read length: %v", err)
	}
	if err := skip(r, int64(vl)); err != nil {
		return fmt.Errorf("could not skip content: %v", err)
	}
	return nil
}

type readConn struct {
	io.Reader
	ResetTimeout func()
	Close        func() error
	RemoteAddr   func() net.Addr
}

func newReadConn(c *net.TCPConn) readConn {
	return readConn{
		Reader:       c,
		ResetTimeout: func() { c.SetReadDeadline(time.Now().Add(dataTimeout)) },
		Close:        c.CloseRead,
		RemoteAddr:   c.RemoteAddr,
	}
}

func newReadConnWithPrefixedData(c *net.TCPConn, prefix io.Reader) readConn {
	return readConn{
		Reader:       io.MultiReader(prefix, c),
		ResetTimeout: func() { c.SetReadDeadline(time.Now().Add(dataTimeout)) },
		Close:        c.CloseRead,
		RemoteAddr:   c.RemoteAddr,
	}
}

type writeConn struct {
	io.Writer
	ResetTimeout func()
	Close        func() error
	RemoteAddr   func() net.Addr
}

func newWriteConn(c *net.TCPConn) writeConn {
	return writeConn{
		Writer:       c,
		ResetTimeout: func() { c.SetWriteDeadline(time.Now().Add(dataTimeout)) },
		Close:        c.CloseWrite,
		RemoteAddr:   c.RemoteAddr,
	}
}

func proxy(dst writeConn, src readConn) error {
	defer func() {
		// Cleanup only: errchecked close is below.
		src.Close()
		dst.Close()
	}()

	var buf [4096]byte
	src.ResetTimeout()
	dst.ResetTimeout()
	for {
		n, rdErr := src.Read(buf[:])
		if n > 0 {
			src.ResetTimeout()
			if _, err := dst.Write(buf[:n]); err != nil {
				return fmt.Errorf("could not write to %q: %v", dst.RemoteAddr(), err)
			}
			dst.ResetTimeout()
		}
		if rdErr == io.EOF {
			if err := dst.Close(); err != nil {
				return fmt.Errorf("could not close %q: %v", dst.RemoteAddr(), err)
			}
			return nil
		}
		if rdErr != nil {
			return fmt.Errorf("error reading from %q: %v", src.RemoteAddr(), rdErr)
		}
	}
}
