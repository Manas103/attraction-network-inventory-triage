// Reads a pcap file with libpcap, reassembles each flow, identifies its
// application from the payload bytes (never the port number), enforces
// the management-subnet policy (policy.hpp) on the identified
// application, and reports:
//   - every flow's verdict (for reference_decoder.py to diff against),
//   - throughput (processing one core, single-threaded),
//   - per-flow decision latency percentiles,
//   - how many of the 40 seeded evasion flows were caught, versus what a
//     port-only ACL would have allowed.
#include <arpa/inet.h>
#include <netinet/in.h>
#include <pcap.h>

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

#include "flow_table.hpp"
#include "policy.hpp"

using namespace inlineid;
using Clock = std::chrono::steady_clock;

namespace {

struct EthHeader {
    uint8_t dst[6];
    uint8_t src[6];
    uint16_t ethertype;
} __attribute__((packed));

std::string ip_str(uint32_t ip_net) {
    struct in_addr a;
    a.s_addr = ip_net;
    char buf[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &a, buf, sizeof(buf));
    return std::string(buf);
}

}  // namespace

int main(int argc, char** argv) {
    if (argc < 3) {
        std::cerr << "usage: inline_id <capture.pcap> <verdicts_out.csv> [summary_out.txt]\n";
        return 2;
    }
    const char* pcap_path = argv[1];
    const char* verdicts_path = argv[2];
    const char* summary_path = argc > 3 ? argv[3] : nullptr;

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_offline(pcap_path, errbuf);
    if (!handle) {
        std::cerr << "pcap_open_offline failed: " << errbuf << "\n";
        return 1;
    }

    FlowTable table;
    std::vector<double> decision_latencies_us;
    decision_latencies_us.reserve(1'000'000);

    uint64_t total_packets = 0;
    uint64_t total_bytes = 0;  // wire bytes (frame length), for the throughput claim

    struct pcap_pkthdr* hdr;
    const u_char* data;
    int rc;

    auto t_start = Clock::now();

    while ((rc = pcap_next_ex(handle, &hdr, &data)) == 1) {
        total_packets++;
        total_bytes += hdr->len;

        if (hdr->caplen < sizeof(EthHeader)) continue;
        const EthHeader* eth = reinterpret_cast<const EthHeader*>(data);
        if (ntohs(eth->ethertype) != 0x0800) continue;  // IPv4 only

        const uint8_t* ip_base = data + sizeof(EthHeader);
        size_t remaining = hdr->caplen - sizeof(EthHeader);
        if (remaining < 20) continue;
        uint8_t ihl = (ip_base[0] & 0x0F) * 4;
        if (ihl < 20 || remaining < ihl) continue;
        uint8_t ip_proto = ip_base[9];
        uint32_t src_ip, dst_ip;
        memcpy(&src_ip, ip_base + 12, 4);
        memcpy(&dst_ip, ip_base + 16, 4);

        const uint8_t* l4 = ip_base + ihl;
        size_t l4_len = remaining - ihl;

        uint16_t src_port = 0, dst_port = 0;
        const uint8_t* payload = nullptr;
        size_t payload_len = 0;

        if (ip_proto == IPPROTO_TCP) {
            if (l4_len < 20) continue;
            src_port = (uint16_t(l4[0]) << 8) | l4[1];
            dst_port = (uint16_t(l4[2]) << 8) | l4[3];
            uint8_t tcp_flags = l4[13];
            uint8_t data_offset = ((l4[12] >> 4) & 0x0F) * 4;
            if (data_offset < 20 || l4_len < data_offset) continue;
            payload = l4 + data_offset;
            payload_len = l4_len - data_offset;

            constexpr uint8_t SYN = 0x02, ACK = 0x10;
            if ((tcp_flags & SYN) && !(tcp_flags & ACK)) {
                uint64_t syn_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(
                                       Clock::now().time_since_epoch())
                                       .count();
                table.on_syn(ip_proto, src_ip, src_port, dst_ip, dst_port, syn_ns);
            }
        } else if (ip_proto == IPPROTO_UDP) {
            if (l4_len < 8) continue;
            src_port = (uint16_t(l4[0]) << 8) | l4[1];
            dst_port = (uint16_t(l4[2]) << 8) | l4[3];
            payload = l4 + 8;
            payload_len = l4_len - 8;
        } else {
            continue;
        }

        if (payload_len == 0) continue;

        uint64_t now_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(
                               Clock::now().time_since_epoch())
                               .count();

        auto t0 = Clock::now();
        table.on_payload(ip_proto, src_ip, src_port, dst_ip, dst_port, payload, payload_len, now_ns);
        auto t1 = Clock::now();
        double us = std::chrono::duration<double, std::micro>(t1 - t0).count();
        decision_latencies_us.push_back(us);
    }
    auto t_end = Clock::now();
    pcap_close(handle);

    double wall_seconds = std::chrono::duration<double>(t_end - t_start).count();
    double gbps = (total_bytes * 8.0) / wall_seconds / 1e9;
    double pps = total_packets / wall_seconds;

    std::sort(decision_latencies_us.begin(), decision_latencies_us.end());
    auto pct = [&](double p) -> double {
        if (decision_latencies_us.empty()) return 0.0;
        size_t idx = static_cast<size_t>(decision_latencies_us.size() * p);
        if (idx >= decision_latencies_us.size()) idx = decision_latencies_us.size() - 1;
        return decision_latencies_us[idx];
    };

    // Verdicts CSV: flow 5-tuple, identified protocol, our policy decision,
    // the port-ACL decision, and whether this flow's protocol changed
    // mid-stream (tunneling detected).
    std::ofstream out(verdicts_path);
    out << "src_ip,dst_ip,src_port,dst_port,proto_l4,identified_protocol,first_protocol,"
           "tunneling_detected,our_decision,port_acl_decision,sni_or_qname,ja3_lite\n";
    uint64_t caught_evasions = 0;
    uint64_t total_evasion_like = 0;
    for (const auto& [key, st] : table.flows()) {
        Decision ours = evaluate_policy(st.current_protocol, st.originator_ip);
        Decision port_acl = port_based_acl_decision(st.dst_port);
        bool port_evasion = (st.dst_port != 445 && st.dst_port != 22) &&
                             (st.current_protocol == "SMB" || st.current_protocol == "SSH");
        bool tunneled_evasion = st.tunneling_detected &&
                                (st.current_protocol == "SMB" || st.current_protocol == "SSH");
        if (port_evasion || tunneled_evasion) {
            total_evasion_like++;
            if (ours == Decision::BLOCK && port_acl == Decision::ALLOW) caught_evasions++;
        }
        out << ip_str(key.src_ip) << "," << ip_str(key.dst_ip) << "," << key.src_port << ","
            << key.dst_port << "," << int(key.proto) << "," << st.current_protocol << ","
            << st.first_protocol << "," << (st.tunneling_detected ? "1" : "0") << ","
            << decision_name(ours) << "," << decision_name(port_acl) << "," << st.sni_or_qname
            << "," << st.ja3_lite << "\n";
    }
    out.close();

    std::ostringstream summary;
    summary << "total_packets=" << total_packets << "\n";
    summary << "total_bytes=" << total_bytes << "\n";
    summary << "wall_seconds=" << wall_seconds << "\n";
    summary << "throughput_gbps=" << gbps << "\n";
    summary << "throughput_pps=" << pps << "\n";
    summary << "total_flows=" << table.flows().size() << "\n";
    summary << "decision_latency_p50_us=" << pct(0.50) << "\n";
    summary << "decision_latency_p95_us=" << pct(0.95) << "\n";
    summary << "decision_latency_p99_us=" << pct(0.99) << "\n";
    summary << "decision_latency_max_us=" << (decision_latencies_us.empty() ? 0.0 : decision_latencies_us.back()) << "\n";
    summary << "evasion_like_flows_found=" << total_evasion_like << "\n";
    summary << "evasion_flows_caught=" << caught_evasions << "\n";

    std::cout << summary.str();
    if (summary_path) {
        std::ofstream sf(summary_path);
        sf << summary.str();
    }
    return 0;
}
