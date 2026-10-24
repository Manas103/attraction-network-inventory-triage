#pragma once
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace inlineid {

// Result of a single decode attempt against a flow's reassembled bytes
// (one direction at a time; the caller tries both).
struct DecodeResult {
    std::string protocol;  // "HTTP" | "TLS" | "DNS" | "SSH" | "SMB"
    std::string detail;    // SNI for TLS, qname for DNS, empty otherwise
    std::string ja3_lite;  // non-empty only for TLS
};

// Each function validates the buffer's structure against (a small, honest
// subset of) the protocol's own spec, not just a magic-byte sniff:
//   - HTTP: a real request-line grammar (METHOD SP request-target SP
//     HTTP-version CRLF) or a real status-line, both over one of the
//     methods/registered status codes this project recognizes.
//   - TLS: a real TLS record header (type, version, length) wrapping a
//     real ClientHello/ServerHello handshake structure, walking its own
//     length-prefixed fields (session id, cipher suites, extensions)
//     rather than assuming fixed offsets.
//   - DNS: a real 12-byte header (opcode, QR, counts) plus a real
//     length-prefixed QNAME.
//   - SSH: the literal version-exchange banner grammar from RFC 4253
//     ("SSH-" protoversion "-" ...).
//   - SMB: the real SMB2 header magic plus a plausible StructureSize/Command.
std::optional<DecodeResult> try_http(const uint8_t* data, size_t len);
std::optional<DecodeResult> try_tls_client_hello(const uint8_t* data, size_t len);
std::optional<DecodeResult> try_tls_server_hello(const uint8_t* data, size_t len);
std::optional<DecodeResult> try_dns(const uint8_t* data, size_t len);
std::optional<DecodeResult> try_ssh(const uint8_t* data, size_t len);
std::optional<DecodeResult> try_smb2(const uint8_t* data, size_t len);

// Tries every decoder in a fixed, documented precedence order (TLS and
// SMB have unambiguous magic bytes and go first; HTTP and SSH are
// text-grammar checks and go last, since a crafted payload could
// otherwise coincidentally look like printable text). Returns nullopt if
// nothing recognized the bytes.
std::optional<DecodeResult> identify(const uint8_t* data, size_t len);

}  // namespace inlineid
