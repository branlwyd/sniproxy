package main

import (
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
	port   = flag.Int("port", 443, "Port to listen on.")
	config = flag.String("config", "", "Location of config file.")

	// Config data.
	mapping        = map[string]string{} // SNI hostname -> destination address
	initialTimeout = 5 * time.Second
	dialTimeout    = 5 * time.Second
	dataTimeout    = 10 * time.Second
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
		// TODO: append ":https" to destinations without a port specified
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
	l, err := net.Listen("tcp", fmt.Sprintf(":%d", *port))
	if err != nil {
		log.Fatalf("Could not listen on port %d: %v", *port, err)
	}
	log.Printf("Accepting connections on port %d", *port)
	for {
		c, err := l.Accept()
		if err != nil {
			log.Fatalf("Could not accept connection: %v", err)
		}
		go handleConn(c)
	}
}

const contentTypeHandshake = 22

func handleConn(c net.Conn) {
	log.Printf("[%s] Accepted connection", c.RemoteAddr())
	c.SetDeadline(time.Now().Add(initialTimeout))
	defer func() {
		if err := c.Close(); err != nil {
			log.Printf("[%s] Could not close connection: %v", c.RemoteAddr(), err)
		} else {
			log.Printf("[%s] Connection closed", c.RemoteAddr())
		}
	}()
	var buf bytes.Buffer // stores bytes read while parsing handshake message
	r := io.TeeReader(c, &buf)
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
	srvConn, err := net.DialTimeout("tcp", dest, dialTimeout)
	if err != nil {
		log.Printf("[%s] Could not dial %q: %v", c.RemoteAddr(), dest, err)
		return
	}
	defer func() {
		if err := srvConn.Close(); err != nil {
			log.Printf("[%s] Could not close connection to %q: %v", c.RemoteAddr(), dest, err)
		}
	}()

	// Begin proxying.
	var eg errgroup.Group
	eg.Go(func() error { return proxy(newWriteConn(srvConn), newReadConnWithPrefixedData(c, buf.Bytes())) })
	eg.Go(func() error { return proxy(newWriteConn(c), newReadConn(srvConn)) })
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
	var buf [4]byte

	// Handshake message type.
	if _, err := io.ReadFull(r, buf[:1]); err != nil {
		return "", fmt.Errorf("could not read handshake message type: %v", err)
	}
	if buf[0] != handshakeTypeClientHello {
		return "", fmt.Errorf("handshake message not a ClientHello (type %d, expected %d)", buf[0], handshakeTypeClientHello)
	}

	// Handshake message length.
	hl, err := uint24(r)
	if err != nil {
		return "", fmt.Errorf("could not read handshake message length: %v", err)
	}
	r = io.LimitReader(r, int64(hl))

	// ProtocolVersion & Random
	if _, err := io.CopyN(ioutil.Discard, r, 34); err != nil {
		return "", fmt.Errorf("could not skip ProtocolVersion & Random: %v", err)
	}

	// Session ID.
	if _, err := io.ReadFull(r, buf[:1]); err != nil {
		return "", fmt.Errorf("could not read SessionID length: %v", err)
	}
	if _, err := io.CopyN(ioutil.Discard, r, int64(buf[1])); err != nil {
		return "", fmt.Errorf("could not skip SessionID: %v", err)
	}

	// Cipher suites.
	if _, err := io.ReadFull(r, buf[:2]); err != nil {
		return "", fmt.Errorf("could not read CipherSuite length: %v", err)
	}
	if _, err := io.CopyN(ioutil.Discard, r, int64(binary.BigEndian.Uint16(buf[:2]))); err != nil {
		return "", fmt.Errorf("could not skip CipherSuite: %v", err)
	}

	// Compression methods.
	if _, err := io.ReadFull(r, buf[:1]); err != nil {
		return "", fmt.Errorf("could not read CompressionMethod length: %v", err)
	}
	if _, err := io.CopyN(ioutil.Discard, r, int64(buf[0])); err != nil {
		return "", fmt.Errorf("could not skip CompressionMethod: %v", err)
	}

	// Extensions.
	_, err = io.ReadFull(r, buf[:2])
	if err == io.EOF {
		return "", errors.New("no extensions")
	}
	if err != nil {
		return "", fmt.Errorf("could not read Extensions length: %v", err)
	}
	r = io.LimitReader(r, int64(binary.BigEndian.Uint16(buf[:2])))
	for {
		_, err := io.ReadFull(r, buf[:4])
		if err == io.EOF {
			return "", errors.New("no SNI extension")
		}
		if err != nil {
			return "", fmt.Errorf("could not read Extension type & length: %v", err)
		}
		typ, l := binary.BigEndian.Uint16(buf[0:2]), binary.BigEndian.Uint16(buf[2:4])

		const extensionTypeSNI = 0
		if typ != extensionTypeSNI {
			// This is not an SNI extension; skip it.
			if _, err := io.CopyN(ioutil.Discard, r, int64(l)); err != nil {
				return "", fmt.Errorf("could not skip extension: %v", err)
			}
			continue
		}
		extR := io.LimitReader(r, int64(l))

		// ServerNameList length.
		if _, err := io.ReadFull(extR, buf[:2]); err != nil {
			return "", fmt.Errorf("could not read ServerNameList length: %v", err)
		}
		extR = io.LimitReader(r, int64(binary.BigEndian.Uint16(buf[:2])))
		for {
			// NameType & length.
			_, err := io.ReadFull(extR, buf[:3])
			if err == io.EOF {
				return "", errors.New("SNI extension has no host_name NameType")
			}
			if err != nil {
				return "", fmt.Errorf("could not read NameType & length: %v", err)
			}
			typ, l := buf[0], binary.BigEndian.Uint16(buf[1:3])

			const nameTypeHostName = 0
			if typ != nameTypeHostName {
				// This is not a host_name-typed ServerName. Skip this ServerName.
				if _, err := io.CopyN(ioutil.Discard, extR, int64(l)); err != nil {
					return "", fmt.Errorf("could not skip ServerName: %v", err)
				}
			}

			var b strings.Builder
			if _, err := io.CopyN(&b, extR, int64(l)); err != nil {
				return "", fmt.Errorf("could not read HostName: %v", err)
			}
			return b.String(), nil
		}
	}
}

// uint24 interprets data as big-endian
func uint24(r io.Reader) (uint32, error) {
	var buf [3]byte
	if _, err := io.ReadFull(r, buf[:]); err != nil {
		return 0, err
	}
	return uint32(buf[0])<<16 | uint32(buf[1])<<8 | uint32(buf[2]), nil
}

type readConn struct {
	io.Reader
	ResetTimeout func()
	Close        func() error
	RemoteAddr   func() net.Addr
}

func newReadConn(c net.Conn) readConn {
	return readConn{
		Reader:       c,
		ResetTimeout: func() { c.SetReadDeadline(time.Now().Add(dataTimeout)) },
		Close:        c.Close,
		RemoteAddr:   c.RemoteAddr,
	}
}

func newReadConnWithPrefixedData(c net.Conn, prefixed []byte) readConn {
	return readConn{
		Reader:       io.MultiReader(bytes.NewReader(prefixed), c),
		ResetTimeout: func() { c.SetReadDeadline(time.Now().Add(dataTimeout)) },
		Close:        c.Close,
		RemoteAddr:   c.RemoteAddr,
	}
}

type writeConn struct {
	io.Writer
	ResetTimeout func()
	Close        func() error
	RemoteAddr   func() net.Addr
}

func newWriteConn(c net.Conn) writeConn {
	return writeConn{
		Writer:       c,
		ResetTimeout: func() { c.SetWriteDeadline(time.Now().Add(dataTimeout)) },
		Close:        c.Close,
		RemoteAddr:   c.RemoteAddr,
	}
}

func proxy(dst writeConn, src readConn) (retErr error) {
	defer func() {
		if retErr != nil {
			src.Close()
			dst.Close()
		}
	}()

	var buf [32 * 1024]byte
	src.ResetTimeout()
	dst.ResetTimeout()
	for {
		n, rdErr := src.Read(buf[:])
		if n > 0 {
			src.ResetTimeout()
			if _, err := dst.Write(buf[:n]); err != nil {
				return fmt.Errorf("could not write to %s: %q", dst.RemoteAddr(), err)
			}
			dst.ResetTimeout()
		}
		if rdErr == io.EOF {
			if err := dst.Close(); err != nil {
				return fmt.Errorf("could not close %s: %q", dst.RemoteAddr(), err)
			}
			return nil
		}
		if rdErr != nil {
			return fmt.Errorf("error reading from %s: %q", src.RemoteAddr(), rdErr)
		}
	}
}
