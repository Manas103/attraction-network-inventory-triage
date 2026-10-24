#pragma once
#include <cstdint>
#include <string>
#include <unordered_map>

#include "flow_key.hpp"
#include "policy.hpp"

namespace inlineid {

// One flow's running identification state. Per-flow reassembly here means
// tracking every packet of the flow (bytes, direction, packet count) and
// treating each TCP segment as a candidate protocol-data-unit boundary,
// which is true for every flow this project's capture generator builds
// (see capture_gen.py: every protocol unit it writes is its own segment).
// It does not do generic stream reframing (e.g. HTTP Content-Length-based
// body skipping across segment boundaries); see README Limitations.
struct FlowState {
    uint32_t originator_ip = 0;  // network byte order: the TCP SYN sender, or (for UDP) whoever sent first
    uint16_t dst_port = 0;       // the responder's port, for the port-ACL comparison
    bool origin_locked = false;  // true once set from a real TCP SYN, so a
                                  // server-speaks-first protocol's first
                                  // payload packet can never overwrite it
    uint64_t packets = 0;
    uint64_t bytes = 0;
    uint64_t payload_packets_inspected = 0;
    std::string first_protocol;
    std::string current_protocol;
    std::string sni_or_qname;
    std::string ja3_lite;
    bool tunneling_detected = false;
    uint64_t first_seen_ns = 0;
    uint64_t decided_at_ns = 0;  // when current_protocol last changed
};

constexpr uint64_t kInspectCapPerFlow = 24;  // bound per-flow decode cost regardless of flow length

class FlowTable {
   public:
    // Called for a bare TCP SYN (no ACK, no payload): the only reliable
    // way to know which side actually opened the connection. Protocols
    // where the server speaks first on the wire (SSH's banner) would
    // otherwise get attributed backwards if origin were inferred from
    // whichever side sent the first payload byte instead; see README
    // Findings for the real bug this fixes.
    void on_syn(uint8_t proto, uint32_t src_ip, uint16_t src_port,
                uint32_t dst_ip, uint16_t dst_port, uint64_t now_ns);

    // Called once per packet with a non-empty L4 payload. `src_ip`/`src_port`
    // are the packet's own source (not normalized). If no SYN was seen
    // for this flow (e.g. UDP), the first payload packet's source is used
    // as the origin instead. Returns the flow key used.
    FlowKey on_payload(uint8_t proto, uint32_t src_ip, uint16_t src_port,
                        uint32_t dst_ip, uint16_t dst_port_pkt,
                        const uint8_t* payload, size_t len, uint64_t now_ns);

    const std::unordered_map<FlowKey, FlowState>& flows() const { return flows_; }

   private:
    std::unordered_map<FlowKey, FlowState> flows_;
};

}  // namespace inlineid
