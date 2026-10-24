#include "policy.hpp"

#include <arpa/inet.h>

namespace inlineid {

bool is_management_subnet(uint32_t ip_network_order) {
    uint32_t ip_host = ntohl(ip_network_order);
    uint32_t subnet = (uint32_t(10) << 24) | (uint32_t(20) << 16);  // 10.20.0.0/24
    return (ip_host & 0xFFFFFF00u) == subnet;
}

Decision evaluate_policy(const std::string& protocol, uint32_t originator_ip) {
    if (protocol == "SMB" || protocol == "SSH") {
        return is_management_subnet(originator_ip) ? Decision::ALLOW : Decision::BLOCK;
    }
    if (protocol == "HTTP" || protocol == "TLS" || protocol == "DNS") {
        return Decision::ALLOW;
    }
    return Decision::UNKNOWN_PROTOCOL;
}

Decision port_based_acl_decision(uint16_t dst_port) {
    if (dst_port == 445 || dst_port == 22) return Decision::BLOCK;
    return Decision::ALLOW;
}

const char* decision_name(Decision d) {
    switch (d) {
        case Decision::ALLOW: return "ALLOW";
        case Decision::BLOCK: return "BLOCK";
        default: return "UNKNOWN";
    }
}

}  // namespace inlineid
