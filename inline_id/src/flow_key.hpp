#pragma once
#include <cstdint>
#include <functional>
#include <string>

namespace inlineid {

struct FlowKey {
    uint8_t proto;  // IPPROTO_TCP or IPPROTO_UDP
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;

    bool operator==(const FlowKey& o) const {
        return proto == o.proto && src_ip == o.src_ip && dst_ip == o.dst_ip &&
               src_port == o.src_port && dst_port == o.dst_port;
    }
};

// Flows are bidirectional: normalize so (A->B) and (B->A) packets of the
// same conversation hash to the same key, with direction tracked
// separately by the caller.
inline FlowKey normalize(uint8_t proto, uint32_t ip_a, uint16_t port_a,
                          uint32_t ip_b, uint16_t port_b, bool* a_is_initiator_side) {
    if (ip_a < ip_b || (ip_a == ip_b && port_a <= port_b)) {
        *a_is_initiator_side = true;
        return FlowKey{proto, ip_a, ip_b, port_a, port_b};
    }
    *a_is_initiator_side = false;
    return FlowKey{proto, ip_b, ip_a, port_b, port_a};
}

std::string ip_to_string(uint32_t ip_network_order);

}  // namespace inlineid

namespace std {
template <>
struct hash<inlineid::FlowKey> {
    size_t operator()(const inlineid::FlowKey& k) const noexcept {
        size_t h = std::hash<uint32_t>()(k.src_ip);
        h ^= std::hash<uint32_t>()(k.dst_ip) << 1;
        h ^= std::hash<uint16_t>()(k.src_port) << 2;
        h ^= std::hash<uint16_t>()(k.dst_port) << 3;
        h ^= std::hash<uint8_t>()(k.proto) << 4;
        return h;
    }
};
}  // namespace std
