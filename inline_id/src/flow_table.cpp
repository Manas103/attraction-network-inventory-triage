#include "flow_table.hpp"

#include "decoders.hpp"

namespace inlineid {

void FlowTable::on_syn(uint8_t proto, uint32_t src_ip, uint16_t src_port,
                        uint32_t dst_ip, uint16_t dst_port, uint64_t now_ns) {
    bool src_is_initiator_side;
    FlowKey key = normalize(proto, src_ip, src_port, dst_ip, dst_port, &src_is_initiator_side);
    auto it = flows_.find(key);
    if (it == flows_.end()) {
        FlowState st;
        st.first_seen_ns = now_ns;
        it = flows_.emplace(key, st).first;
    }
    FlowState& st = it->second;
    st.originator_ip = src_ip;
    st.dst_port = dst_port;
    st.origin_locked = true;
}

FlowKey FlowTable::on_payload(uint8_t proto, uint32_t src_ip, uint16_t src_port,
                               uint32_t dst_ip, uint16_t dst_port_pkt,
                               const uint8_t* payload, size_t len, uint64_t now_ns) {
    bool src_is_initiator_side;
    FlowKey key = normalize(proto, src_ip, src_port, dst_ip, dst_port_pkt, &src_is_initiator_side);

    auto it = flows_.find(key);
    if (it == flows_.end()) {
        FlowState st;
        st.originator_ip = src_ip;
        st.dst_port = dst_port_pkt;
        st.first_seen_ns = now_ns;
        it = flows_.emplace(key, st).first;
    }
    FlowState& st = it->second;
    if (!st.origin_locked) {
        // No SYN seen yet for this flow (true for every UDP "flow", and
        // for any TCP flow whose SYN fell outside the capture): fall back
        // to "whoever sent the first payload", same as before, but only
        // while nothing more authoritative has claimed it.
        if (st.packets == 0) {
            st.originator_ip = src_ip;
            st.dst_port = dst_port_pkt;
        }
    }
    st.packets++;
    st.bytes += len;

    if (st.payload_packets_inspected >= kInspectCapPerFlow || len == 0) {
        return key;
    }
    st.payload_packets_inspected++;

    auto result = identify(payload, len);
    if (!result.has_value()) {
        return key;  // this segment didn't match any decoder; keep the prior verdict
    }

    if (st.current_protocol.empty()) {
        st.first_protocol = result->protocol;
        st.current_protocol = result->protocol;
        st.decided_at_ns = now_ns;
    } else if (result->protocol != st.current_protocol) {
        st.tunneling_detected = true;
        st.current_protocol = result->protocol;
        st.decided_at_ns = now_ns;
    }
    if (!result->detail.empty()) st.sni_or_qname = result->detail;
    if (!result->ja3_lite.empty()) st.ja3_lite = result->ja3_lite;

    return key;
}

}  // namespace inlineid
