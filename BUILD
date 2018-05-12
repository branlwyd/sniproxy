load("@io_bazel_rules_go//go:def.bzl", "go_binary", "go_prefix")
load("@io_bazel_rules_go//proto:def.bzl", "go_proto_library")

go_prefix("github.com/BranLwyd/sniproxy")

##
## Binaries
##
go_binary(
    name = "sniproxyd",
    srcs = ["sniproxyd.go"],
    pure = "on",
    deps = [
        ":sniproxy_go_proto",
        "@com_github_golang_protobuf//proto:go_default_library",
        "@com_github_thomaso-mirodin_intmath//i64:go_default_library",
        "@org_golang_x_sync//errgroup:go_default_library",
    ],
)

##
## Protobuf
##
proto_library(
    name = "sniproxy_proto",
    srcs = ["sniproxy.proto"],
)

go_proto_library(
    name = "sniproxy_go_proto",
    proto = ":sniproxy_proto",
)
