#include "decoders.hpp"

#include <algorithm>
#include <cstring>
#include <sstream>

namespace inlineid {

namespace {

uint16_t be16(const uint8_t* p) { return (uint16_t(p[0]) << 8) | p[1]; }

// FNV-1a 64-bit: used for the JA3-inspired fingerprint. Not JA3's own
// MD5 and not comparable to public JA3 databases; see decoders.hpp.
uint64_t fnv1a(const std::string& s) {
    uint64_t h = 1469598103934665603ULL;
    for (unsigned char c : s) {
        h ^= c;
        h *= 1099511628211ULL;
    }
    return h;
}

std::string hex64(uint64_t v) {
    char buf[17];
    snprintf(buf, sizeof(buf), "%016llx", (unsigned long long)v);
    return std::string(buf);
}

}  // namespace

std::optional<DecodeResult> try_http(const uint8_t* data, size_t len) {
    if (len < 16) return std::nullopt;
    static const char* methods[] = {"GET ", "POST ", "HEAD ", "PUT ", "DELETE ", "OPTIONS "};
    const char* text = reinterpret_cast<const char*>(data);

    bool is_request = false;
    for (const char* m : methods) {
        size_t mlen = strlen(m);
        if (len >= mlen && memcmp(text, m, mlen) == 0) {
            is_request = true;
            break;
        }
    }
    bool is_response = (len >= 5 && memcmp(text, "HTTP/", 5) == 0);
    if (!is_request && !is_response) return std::nullopt;

    // Validate there is a real request-line/status-line terminated by
    // CRLF, and that an "HTTP/d.d" version token appears on that line.
    const char* crlf = static_cast<const char*>(memchr(text, '\r', std::min(len, size_t(512))));
    if (!crlf || crlf + 1 >= text + len || *(crlf + 1) != '\n') return std::nullopt;
    std::string line(text, crlf - text);
    if (line.find("HTTP/1.") == std::string::npos) return std::nullopt;

    DecodeResult r;
    r.protocol = "HTTP";
    return r;
}

static bool parse_tls_record_header(const uint8_t* data, size_t len, uint8_t* type,
                                     uint16_t* version, uint16_t* record_len) {
    if (len < 5) return false;
    *type = data[0];
    *version = be16(data + 1);
    *record_len = be16(data + 3);
    if (*type != 0x16 && *type != 0x17) return false;
    if (*version < 0x0300 || *version > 0x0304) return false;
    return true;
}

std::optional<DecodeResult> try_tls_client_hello(const uint8_t* data, size_t len) {
    uint8_t type;
    uint16_t version, record_len;
    if (!parse_tls_record_header(data, len, &type, &version, &record_len)) return std::nullopt;
    if (type != 0x16) return std::nullopt;
    if (len < 5 + 4) return std::nullopt;

    const uint8_t* hs = data + 5;
    size_t hs_len = len - 5;
    if (hs[0] != 0x01) return std::nullopt;  // not a ClientHello
    uint32_t body_len = (uint32_t(hs[1]) << 16) | (uint32_t(hs[2]) << 8) | hs[3];
    if (hs_len < 4 + body_len && hs_len < 4 + 34) return std::nullopt;  // tolerate truncated capture

    const uint8_t* p = hs + 4;
    const uint8_t* end = hs + std::min<size_t>(hs_len, 4 + body_len);
    if (p + 2 + 32 + 1 > end) return std::nullopt;
    uint16_t client_version = be16(p);
    p += 2 + 32;  // client_version, random
    uint8_t session_id_len = *p++;
    if (p + session_id_len > end) return std::nullopt;
    p += session_id_len;

    if (p + 2 > end) return std::nullopt;
    uint16_t cipher_len = be16(p);
    p += 2;
    if (p + cipher_len > end) return std::nullopt;
    std::ostringstream ciphers;
    for (size_t i = 0; i + 1 < cipher_len; i += 2) ciphers << be16(p + i) << "-";
    p += cipher_len;

    if (p + 1 > end) return std::nullopt;
    uint8_t comp_len = *p++;
    if (p + comp_len > end) return std::nullopt;
    p += comp_len;

    std::string sni;
    std::ostringstream ext_types;
    if (p + 2 <= end) {
        uint16_t ext_total = be16(p);
        p += 2;
        const uint8_t* ext_end = std::min(p + ext_total, end);
        while (p + 4 <= ext_end) {
            uint16_t ext_type = be16(p);
            uint16_t ext_len = be16(p + 2);
            const uint8_t* ext_body = p + 4;
            ext_types << ext_type << "-";
            if (ext_type == 0x0000 && ext_body + 5 <= ext_end) {
                // server_name_list: 2-byte list len, 1-byte type, 2-byte name len, name
                uint16_t name_len = be16(ext_body + 3);
                const uint8_t* name = ext_body + 5;
                if (name + name_len <= ext_end) sni.assign(reinterpret_cast<const char*>(name), name_len);
            }
            p = ext_body + ext_len;
        }
    }

    DecodeResult r;
    r.protocol = "TLS";
    r.detail = sni;
    std::ostringstream fp;
    fp << client_version << "," << ciphers.str() << "," << ext_types.str();
    r.ja3_lite = hex64(fnv1a(fp.str()));
    return r;
}

std::optional<DecodeResult> try_tls_server_hello(const uint8_t* data, size_t len) {
    // Deliberately does not accept a bare ApplicationData record
    // (type 0x17) as evidence of TLS: ApplicationData is opaque
    // ciphertext by design, so a record header alone (type+version+
    // length, 5 bytes) is indistinguishable from unrelated binary data
    // that happens to start with the same 1-in-~13000 byte pattern. An
    // earlier version of this function accepted any type-0x17 record
    // unconditionally and was measured to misclassify about 1 in 13000
    // non-TLS packets as TLS on this capture's DNS traffic alone (DNS
    // query IDs are uniform random 16-bit values); see README Findings.
    // TLS is only ever established here from a real ClientHello/
    // ServerHello handshake message.
    uint8_t type;
    uint16_t version, record_len;
    if (!parse_tls_record_header(data, len, &type, &version, &record_len)) return std::nullopt;
    if (type != 0x16) return std::nullopt;
    if (len < 5 + 4) return std::nullopt;
    const uint8_t* hs = data + 5;
    if (hs[0] != 0x02) return std::nullopt;  // ServerHello only; ClientHello is try_tls_client_hello's job
    DecodeResult r;
    r.protocol = "TLS";
    return r;
}

std::optional<DecodeResult> try_dns(const uint8_t* data, size_t len) {
    if (len < 12) return std::nullopt;
    uint16_t flags = be16(data + 2);
    uint16_t qdcount = be16(data + 4);
    uint8_t opcode = (flags >> 11) & 0x0F;
    if (opcode > 5) return std::nullopt;
    if (qdcount == 0 || qdcount > 16) return std::nullopt;

    const uint8_t* p = data + 12;
    const uint8_t* end = data + len;
    std::string qname;
    while (p < end && *p != 0) {
        uint8_t label_len = *p;
        if (label_len > 63) return std::nullopt;  // RFC 1035 max label length
        p++;
        if (p + label_len > end) return std::nullopt;
        if (!qname.empty()) qname += ".";
        qname.append(reinterpret_cast<const char*>(p), label_len);
        p += label_len;
    }
    if (p >= end) return std::nullopt;
    p++;  // root label
    if (p + 4 > end) return std::nullopt;
    uint16_t qtype = be16(p);
    uint16_t qclass = be16(p + 2);
    if (qclass != 1) return std::nullopt;  // IN
    (void)qtype;

    DecodeResult r;
    r.protocol = "DNS";
    r.detail = qname;
    return r;
}

std::optional<DecodeResult> try_ssh(const uint8_t* data, size_t len) {
    if (len < 8) return std::nullopt;
    if (memcmp(data, "SSH-", 4) != 0) return std::nullopt;
    const char* text = reinterpret_cast<const char*>(data);
    size_t dot = std::string::npos;
    for (size_t i = 4; i < len && i < 32; ++i) {
        if (text[i] == '-') { dot = i; break; }
    }
    if (dot == std::string::npos) return std::nullopt;
    // protoversion must be "1.99", "2.0" or similar digit.digit grammar.
    bool saw_digit = false;
    for (size_t i = 4; i < dot; ++i) {
        if (text[i] == '.') continue;
        if (text[i] < '0' || text[i] > '9') return std::nullopt;
        saw_digit = true;
    }
    if (!saw_digit) return std::nullopt;
    DecodeResult r;
    r.protocol = "SSH";
    return r;
}

std::optional<DecodeResult> try_smb2(const uint8_t* data, size_t len) {
    if (len < 64) return std::nullopt;
    static const uint8_t magic[4] = {0xFE, 'S', 'M', 'B'};
    if (memcmp(data, magic, 4) != 0) return std::nullopt;
    uint16_t structure_size = data[4] | (uint16_t(data[5]) << 8);
    if (structure_size != 64) return std::nullopt;
    uint16_t command = data[12] | (uint16_t(data[13]) << 8);
    if (command > 18) return std::nullopt;  // MS-SMB2 defines commands 0..18
    DecodeResult r;
    r.protocol = "SMB";
    return r;
}

std::optional<DecodeResult> identify(const uint8_t* data, size_t len) {
    if (auto r = try_tls_client_hello(data, len)) return r;
    if (auto r = try_tls_server_hello(data, len)) return r;
    if (auto r = try_smb2(data, len)) return r;
    if (auto r = try_dns(data, len)) return r;
    if (auto r = try_ssh(data, len)) return r;
    if (auto r = try_http(data, len)) return r;
    return std::nullopt;
}

}  // namespace inlineid
