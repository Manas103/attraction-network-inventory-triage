// Hand-rolled main() check suite (no GoogleTest dependency needed for a
// handful of deterministic, single-threaded checks). Builds minimal,
// spec-correct byte sequences for each protocol independently of
// protocol_bytes.py (this tests the decoders against the spec, not
// against the Python generator) and checks both the positive and a
// negative case per decoder, plus policy and flow-table behavior.
#include <arpa/inet.h>

#include <cstring>
#include <iostream>
#include <vector>

#include "../src/decoders.hpp"
#include "../src/flow_table.hpp"
#include "../src/policy.hpp"

using namespace inlineid;

static int g_pass = 0, g_fail = 0;

#define CHECK(cond, msg)                                               \
    do {                                                               \
        if (cond) {                                                    \
            g_pass++;                                                  \
        } else {                                                        \
            g_fail++;                                                   \
            std::cerr << "FAIL: " << msg << " (" << __FILE__ << ":" << __LINE__ << ")\n"; \
        }                                                                \
    } while (0)

static std::vector<uint8_t> str_bytes(const std::string& s) {
    return std::vector<uint8_t>(s.begin(), s.end());
}

static void test_http() {
    auto good = str_bytes("GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n");
    auto r = try_http(good.data(), good.size());
    CHECK(r.has_value() && r->protocol == "HTTP", "valid HTTP request recognized");

    auto bad = str_bytes("GET /index.html NOTHTTP garbage without a crlf line at all");
    auto r2 = try_http(bad.data(), bad.size());
    CHECK(!r2.has_value(), "malformed HTTP-looking text rejected");

    auto resp = str_bytes("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi");
    auto r3 = try_http(resp.data(), resp.size());
    CHECK(r3.has_value() && r3->protocol == "HTTP", "valid HTTP response recognized");
}

static void append_be16(std::vector<uint8_t>& v, uint16_t x) { v.push_back(x >> 8); v.push_back(x & 0xFF); }

static std::vector<uint8_t> build_client_hello(const std::string& sni) {
    std::vector<uint8_t> body;
    append_be16(body, 0x0303);                  // client_version
    for (int i = 0; i < 32; i++) body.push_back(i);  // random
    body.push_back(0);                           // session_id_len
    std::vector<uint16_t> ciphers = {0xC02F, 0x1301};
    append_be16(body, ciphers.size() * 2);
    for (auto c : ciphers) append_be16(body, c);
    body.push_back(1);                            // compression len
    body.push_back(0);                            // compression method: null

    std::vector<uint8_t> sni_ext_body;
    append_be16(sni_ext_body, 1 + 2 + sni.size());
    sni_ext_body.push_back(0x00);
    append_be16(sni_ext_body, sni.size());
    for (char c : sni) sni_ext_body.push_back((uint8_t)c);

    std::vector<uint8_t> extensions;
    append_be16(extensions, 0x0000);
    append_be16(extensions, sni_ext_body.size());
    extensions.insert(extensions.end(), sni_ext_body.begin(), sni_ext_body.end());

    append_be16(body, extensions.size());
    body.insert(body.end(), extensions.begin(), extensions.end());

    std::vector<uint8_t> handshake;
    handshake.push_back(0x01);  // ClientHello
    uint32_t hlen = body.size();
    handshake.push_back((hlen >> 16) & 0xFF);
    handshake.push_back((hlen >> 8) & 0xFF);
    handshake.push_back(hlen & 0xFF);
    handshake.insert(handshake.end(), body.begin(), body.end());

    std::vector<uint8_t> record;
    record.push_back(0x16);
    append_be16(record, 0x0303);
    append_be16(record, handshake.size());
    record.insert(record.end(), handshake.begin(), handshake.end());
    return record;
}

static void test_tls() {
    auto ch = build_client_hello("secure.example.com");
    auto r = try_tls_client_hello(ch.data(), ch.size());
    CHECK(r.has_value() && r->protocol == "TLS", "valid ClientHello recognized");
    CHECK(r.has_value() && r->detail == "secure.example.com", "SNI extracted correctly");
    CHECK(r.has_value() && !r->ja3_lite.empty(), "ja3_lite fingerprint computed");

    std::vector<uint8_t> not_tls = {0x00, 0x01, 0x02, 0x03, 0x04};
    auto r2 = try_tls_client_hello(not_tls.data(), not_tls.size());
    CHECK(!r2.has_value(), "non-TLS bytes rejected by TLS decoder");
}

static void test_dns() {
    std::vector<uint8_t> pkt;
    append_be16(pkt, 0x1234);  // id
    append_be16(pkt, 0x0100);  // flags: standard query
    append_be16(pkt, 1);       // qdcount
    append_be16(pkt, 0);
    append_be16(pkt, 0);
    append_be16(pkt, 0);
    for (const std::string& label : {std::string("host1"), std::string("example"), std::string("com")}) {
        pkt.push_back((uint8_t)label.size());
        for (char c : label) pkt.push_back((uint8_t)c);
    }
    pkt.push_back(0);
    append_be16(pkt, 1);  // A
    append_be16(pkt, 1);  // IN

    auto r = try_dns(pkt.data(), pkt.size());
    CHECK(r.has_value() && r->protocol == "DNS", "valid DNS query recognized");
    CHECK(r.has_value() && r->detail == "host1.example.com", "qname decoded correctly");

    std::vector<uint8_t> bad = {0x00, 0x01, 0x02};
    auto r2 = try_dns(bad.data(), bad.size());
    CHECK(!r2.has_value(), "truncated bytes rejected by DNS decoder");
}

static void test_ssh() {
    auto good = str_bytes("SSH-2.0-OpenSSH_8.9p1\r\n");
    auto r = try_ssh(good.data(), good.size());
    CHECK(r.has_value() && r->protocol == "SSH", "valid SSH banner recognized");

    auto bad = str_bytes("SSH-nope-not a version grammar at all");
    auto r2 = try_ssh(bad.data(), bad.size());
    CHECK(!r2.has_value(), "malformed SSH-looking text rejected");
}

static void test_smb() {
    std::vector<uint8_t> hdr(64, 0);
    hdr[0] = 0xFE; hdr[1] = 'S'; hdr[2] = 'M'; hdr[3] = 'B';
    hdr[4] = 64; hdr[5] = 0;  // structure size = 64
    hdr[12] = 5; hdr[13] = 0;  // command = 5 (valid)
    auto r = try_smb2(hdr.data(), hdr.size());
    CHECK(r.has_value() && r->protocol == "SMB", "valid SMB2 header recognized");

    std::vector<uint8_t> bad(64, 0);
    bad[0] = 'X';
    auto r2 = try_smb2(bad.data(), bad.size());
    CHECK(!r2.has_value(), "wrong magic rejected by SMB2 decoder");
}

static void test_policy() {
    uint32_t mgmt_ip = inet_addr("10.20.0.5");
    uint32_t other_ip = inet_addr("198.51.100.5");
    CHECK(evaluate_policy("SMB", mgmt_ip) == Decision::ALLOW, "SMB from mgmt subnet allowed");
    CHECK(evaluate_policy("SMB", other_ip) == Decision::BLOCK, "SMB from outside mgmt subnet blocked");
    CHECK(evaluate_policy("HTTP", other_ip) == Decision::ALLOW, "HTTP always allowed");
    CHECK(port_based_acl_decision(445) == Decision::BLOCK, "port ACL blocks port 445 directly");
    CHECK(port_based_acl_decision(8445) == Decision::ALLOW,
          "port ACL allows SMB moved to a non-standard port (the evasion this project catches)");
}

static void test_flow_table_tunneling() {
    FlowTable table;
    uint32_t attacker_ip = inet_addr("198.51.100.9");
    uint32_t server_ip = inet_addr("198.51.100.200");

    auto http_req = str_bytes("GET /x HTTP/1.1\r\nHost: looks-legit.example\r\n\r\n");
    table.on_payload(6, attacker_ip, 44500, server_ip, 80, http_req.data(), http_req.size(), 1000);

    auto ssh_banner = str_bytes("SSH-2.0-synthetic_client_1.0\r\n");
    FlowKey key = table.on_payload(6, server_ip, 80, attacker_ip, 44500, ssh_banner.data(),
                                    ssh_banner.size(), 2000);

    const auto& st = table.flows().at(key);
    CHECK(st.first_protocol == "HTTP", "flow's first observed protocol was HTTP");
    CHECK(st.current_protocol == "SSH", "flow's current protocol updated to the real one, SSH");
    CHECK(st.tunneling_detected, "mid-stream protocol change flagged as tunneling");

    Decision d = evaluate_policy(st.current_protocol, st.originator_ip);
    CHECK(d == Decision::BLOCK, "the tunneled SSH flow is blocked once correctly identified");
}

static void test_flow_table_server_speaks_first_origin() {
    // SSH's own banner exchange has the server send first; a client with
    // no SYN visibility would misattribute the flow's origin to the
    // server. This is the exact bug README Findings documents.
    FlowTable table;
    uint32_t mgmt_client_ip = inet_addr("10.20.0.5");
    uint32_t server_ip = inet_addr("10.30.0.10");

    table.on_syn(6, mgmt_client_ip, 42005, server_ip, 22, 1000);
    auto server_banner = str_bytes("SSH-2.0-OpenSSH_8.9p1\r\n");
    FlowKey key = table.on_payload(6, server_ip, 22, mgmt_client_ip, 42005, server_banner.data(),
                                    server_banner.size(), 2000);

    const auto& st = table.flows().at(key);
    CHECK(st.originator_ip == mgmt_client_ip,
          "origin attributed to the real SYN sender, not the server that spoke first");
    CHECK(evaluate_policy(st.current_protocol, st.originator_ip) == Decision::ALLOW,
          "correctly-attributed mgmt-subnet SSH flow is allowed");

    FlowTable no_syn_table;
    uint32_t other_client_ip = inet_addr("10.20.0.6");
    FlowKey key2 = no_syn_table.on_payload(6, server_ip, 22, other_client_ip, 42006,
                                            server_banner.data(), server_banner.size(), 2000);
    const auto& st2 = no_syn_table.flows().at(key2);
    CHECK(st2.originator_ip == server_ip,
          "without a SYN, origin falls back to whoever sent the first payload (documented limitation)");
}

int main() {
    test_http();
    test_tls();
    test_dns();
    test_ssh();
    test_smb();
    test_policy();
    test_flow_table_tunneling();
    test_flow_table_server_speaks_first_origin();

    std::cout << g_pass << " passed, " << g_fail << " failed\n";
    return g_fail == 0 ? 0 : 1;
}
