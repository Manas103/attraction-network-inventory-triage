#pragma once
#include <cstdint>
#include <string>

namespace inlineid {

// The policy this whole extension measures against: SMB and SSH are only
// permitted from the management subnet; everything else (HTTP, TLS, DNS)
// is always allowed. This is deliberately small and content-based, the
// opposite of a port-based ACL, which is the naive baseline it is
// compared against in main.cpp's report.
bool is_management_subnet(uint32_t ip_network_order);

enum class Decision { ALLOW, BLOCK, UNKNOWN_PROTOCOL };

// `originator_ip` is the IP that sent the first packet of the flow (the
// TCP SYN sender, or the first UDP datagram's sender), network byte
// order.
Decision evaluate_policy(const std::string& protocol, uint32_t originator_ip);

// What a port-only ACL (checking only the destination port, never the
// payload) would have decided for the same flow: blocks exactly
// dst_port in {445, 22}, regardless of what is actually inside.
Decision port_based_acl_decision(uint16_t dst_port);

const char* decision_name(Decision d);

}  // namespace inlineid
