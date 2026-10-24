#!/usr/bin/env python3
"""Builds the 1.2M-packet synthetic enterprise capture this extension's
claims are measured against: real HTTP/1.1, TLS 1.2, DNS, SSH and SMB2
wire bytes (see protocol_bytes.py) carried over real, checksum-correct
Ethernet/IPv4/TCP/UDP frames (see pcap_writer.py), plus 40 seeded evasion
flows (20 port-evasion, 20 HTTP-tunneled) that a port-only ACL would let
through and this extension's content-based identifier must not.

The policy this capture is built to exercise: SMB and SSH are only
permitted from the management subnet (10.20.0.0/24); from anywhere else,
either protocol must be blocked regardless of which port it is carried
on. A naive port-based ACL enforces this by checking "is the destination
port 445 or 22"; every evasion flow below defeats that check by using a
different port (port-evasion) or by opening what looks like an ordinary
port-80 HTTP connection and then sending the real protocol's bytes on it
instead of an HTTP body (HTTP-tunneled).

Regenerate with:
    python3 capture_gen.py
"""
from __future__ import annotations

import json
import random
from pathlib import Path

import pcap_writer as pw
import protocol_bytes as pb

OUT_DIR = Path(__file__).resolve().parent / "fixtures"
PCAP_PATH = OUT_DIR / "enterprise_capture.pcap"
SCENARIOS_PATH = OUT_DIR / "scenarios.json"
TARGET_TOTAL_PACKETS = 1_200_000

MGMT_SUBNET_PREFIX = "10.20.0."
CLIENT_SUBNET_PREFIX = "10.40.0."
EXTERNAL_SUBNET_PREFIX = "198.51.100."

SYN, SYN_ACK, ACK, PSH_ACK, FIN_ACK = 0x02, 0x12, 0x10, 0x18, 0x11

rng = random.Random(1337)


class TcpFlowBuilder:
    """Tracks per-direction sequence numbers for one TCP flow and emits
    (timestamp, raw_frame) pairs in order."""

    def __init__(self, src_ip, dst_ip, src_port, dst_port, t0):
        self.src_ip, self.dst_ip = src_ip, dst_ip
        self.src_port, self.dst_port = src_port, dst_port
        self.t = t0
        self.cseq = rng.randrange(1, 1_000_000)
        self.sseq = rng.randrange(1, 1_000_000)
        self.packets = []

    def _tick(self):
        self.t += 0.0001
        return self.t

    def handshake(self):
        self.packets.append((self._tick(), pw.eth_ip_tcp(
            self.src_ip, self.dst_ip, self.src_port, self.dst_port, self.cseq, 0, SYN)))
        self.cseq += 1
        self.packets.append((self._tick(), pw.eth_ip_tcp(
            self.dst_ip, self.src_ip, self.dst_port, self.src_port, self.sseq, self.cseq, SYN_ACK)))
        self.sseq += 1
        self.packets.append((self._tick(), pw.eth_ip_tcp(
            self.src_ip, self.dst_ip, self.src_port, self.dst_port, self.cseq, self.sseq, ACK)))

    def client_to_server(self, payload: bytes):
        self.packets.append((self._tick(), pw.eth_ip_tcp(
            self.src_ip, self.dst_ip, self.src_port, self.dst_port,
            self.cseq, self.sseq, PSH_ACK, payload)))
        self.cseq += len(payload)

    def server_to_client(self, payload: bytes):
        self.packets.append((self._tick(), pw.eth_ip_tcp(
            self.dst_ip, self.src_ip, self.dst_port, self.src_port,
            self.sseq, self.cseq, PSH_ACK, payload)))
        self.sseq += len(payload)

    def close(self):
        self.packets.append((self._tick(), pw.eth_ip_tcp(
            self.src_ip, self.dst_ip, self.src_port, self.dst_port, self.cseq, self.sseq, FIN_ACK)))
        self.cseq += 1
        self.packets.append((self._tick(), pw.eth_ip_tcp(
            self.dst_ip, self.src_ip, self.dst_port, self.src_port, self.sseq, self.cseq, ACK)))


def http_flow(idx, t0, data_repeats):
    src = f"{CLIENT_SUBNET_PREFIX}{idx % 250}"
    dst = f"198.51.100.{100 + idx % 50}"
    f = TcpFlowBuilder(src, dst, 40000 + idx, 80, t0)
    f.handshake()
    host = f"www.enterprise-{idx % 20}.example"
    for _ in range(data_repeats):
        f.client_to_server(pb.http_request(host))
        f.server_to_client(pb.http_response())
    f.close()
    return f.packets, {"proto": "tcp", "src": src, "dst": dst, "sport": 40000 + idx, "dport": 80,
                        "true_protocol": "HTTP"}


def tls_flow(idx, t0, data_repeats):
    src = f"{CLIENT_SUBNET_PREFIX}{idx % 250}"
    dst = f"198.51.100.{150 + idx % 50}"
    f = TcpFlowBuilder(src, dst, 41000 + idx, 443, t0)
    f.handshake()
    sni = f"secure-{idx % 20}.example.com"
    f.client_to_server(pb.tls_client_hello(sni))
    f.server_to_client(pb.tls_server_hello())
    for _ in range(data_repeats):
        f.client_to_server(pb.tls_application_data(64))
        f.server_to_client(pb.tls_application_data(128))
    f.close()
    return f.packets, {"proto": "tcp", "src": src, "dst": dst, "sport": 41000 + idx, "dport": 443,
                        "true_protocol": "TLS", "sni": sni}


def ssh_flow(idx, t0, data_repeats, src_mgmt=True, port=22):
    src = f"{MGMT_SUBNET_PREFIX}{idx % 250}" if src_mgmt else f"{EXTERNAL_SUBNET_PREFIX}{idx % 250}"
    dst = f"10.30.0.{10 + idx % 20}"
    f = TcpFlowBuilder(src, dst, 42000 + idx, port, t0)
    f.handshake()
    f.server_to_client(pb.ssh_banner(client=False))
    f.client_to_server(pb.ssh_banner(client=True))
    for _ in range(data_repeats):
        f.client_to_server(bytes((idx + i) % 256 for i in range(32)))
        f.server_to_client(bytes((idx + i) % 256 for i in range(32)))
    f.close()
    return f.packets, {"proto": "tcp", "src": src, "dst": dst, "sport": 42000 + idx, "dport": port,
                        "true_protocol": "SSH"}


def smb_flow(idx, t0, data_repeats, src_mgmt=True, port=445):
    src = f"{MGMT_SUBNET_PREFIX}{idx % 250}" if src_mgmt else f"{EXTERNAL_SUBNET_PREFIX}{idx % 250}"
    dst = f"10.30.0.{50 + idx % 20}"
    f = TcpFlowBuilder(src, dst, 43000 + idx, port, t0)
    f.handshake()
    for i in range(data_repeats):
        f.client_to_server(pb.smb2_header(command=5, message_id=i, is_response=False))
        f.server_to_client(pb.smb2_header(command=5, message_id=i, is_response=True))
    f.close()
    return f.packets, {"proto": "tcp", "src": src, "dst": dst, "sport": 43000 + idx, "dport": port,
                        "true_protocol": "SMB"}


def http_tunneled_flow(idx, t0, tunneled: str):
    """Opens what looks like an ordinary port-80 HTTP connection, then,
    on the same TCP stream, sends the real protocol's bytes instead of a
    second HTTP request: a port- and first-packet-only ACL sees port 80
    and an initial valid HTTP request and allows the connection; a
    decoder that keeps reassembling the stream must notice the protocol
    changed underneath it."""
    src = f"{EXTERNAL_SUBNET_PREFIX}{idx % 250}"
    dst = f"198.51.100.{200 + idx % 50}"
    f = TcpFlowBuilder(src, dst, 44000 + idx, 80, t0)
    f.handshake()
    f.client_to_server(pb.http_request("www.looks-legit.example"))
    f.server_to_client(pb.http_response())
    if tunneled == "SSH":
        f.server_to_client(pb.ssh_banner(client=False))
        f.client_to_server(pb.ssh_banner(client=True))
        for i in range(3):
            f.client_to_server(bytes((idx + i) % 256 for i in range(24)))
    else:
        for i in range(3):
            f.client_to_server(pb.smb2_header(command=5, message_id=i, is_response=False))
            f.server_to_client(pb.smb2_header(command=5, message_id=i, is_response=True))
    f.close()
    return f.packets, {"proto": "tcp", "src": src, "dst": dst, "sport": 44000 + idx, "dport": 80,
                        "true_protocol": tunneled, "evasion_type": "http_tunneled"}


def dns_pair(idx, t0):
    """Builds a query/response pair with a 5-tuple guaranteed unique for
    any idx up to ~2M: the source port (13 bits) and the third IP octet
    (the rest of idx) together inject idx bijectively, so distinct DNS
    pairs never collide into the same flow-table entry. An earlier version
    of this function cycled both the source IP (mod 250) and the source
    port (mod 10000) independently, a combined period of only 10,000; see
    README Findings for the flow-conflation bug that caused."""
    qname = f"host{idx}.enterprise.example"
    sport = 50000 + (idx & 0x1FFF)
    octet3 = (idx >> 13) & 0xFF
    src = f"10.41.{octet3}.{1 + (idx % 250)}"
    dst = "10.30.0.2"
    qid = idx & 0xFFFF
    pkt1 = (t0, pw.eth_ip_udp(src, dst, sport, 53, pb.dns_query(qname, qid)))
    pkt2 = (t0 + 0.00005, pw.eth_ip_udp(dst, src, 53, sport, pb.dns_response(qname, qid)))
    return [pkt1, pkt2], {"proto": "udp", "src": src, "dst": dst, "sport": sport,
                           "dport": 53, "true_protocol": "DNS"}


def build():
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    t = 1_700_000_000.0

    all_flows = []  # (packets, meta)
    evasion_scenarios = []  # ground truth for only the 40 seeded evasion flows

    N_HTTP, DATA_HTTP = 120, 1500
    N_TLS, DATA_TLS = 120, 1500
    N_SSH_MGMT, DATA_SSH = 60, 150
    N_SMB_MGMT, DATA_SMB = 60, 150

    for i in range(N_HTTP):
        all_flows.append(http_flow(i, t, DATA_HTTP))
        t += 1.0
    for i in range(N_TLS):
        all_flows.append(tls_flow(i, t, DATA_TLS))
        t += 1.0
    for i in range(N_SSH_MGMT):
        all_flows.append(ssh_flow(i, t, DATA_SSH, src_mgmt=True, port=22))
        t += 1.0
    for i in range(N_SMB_MGMT):
        all_flows.append(smb_flow(i, t, DATA_SMB, src_mgmt=True, port=445))
        t += 1.0

    # 40 seeded evasion scenarios: 10 each of port-evasion-SSH,
    # port-evasion-SMB, http-tunneled-SSH, http-tunneled-SMB.
    for i in range(10):
        pkts, meta = ssh_flow(1000 + i, t, 4, src_mgmt=False, port=2200 + i)
        meta["evasion_type"] = "port_evasion"
        all_flows.append((pkts, meta))
        evasion_scenarios.append(dict(meta, packet_count=len(pkts)))
        t += 1.0
    for i in range(10):
        pkts, meta = smb_flow(1000 + i, t, 4, src_mgmt=False, port=8445 + i)
        meta["evasion_type"] = "port_evasion"
        all_flows.append((pkts, meta))
        evasion_scenarios.append(dict(meta, packet_count=len(pkts)))
        t += 1.0
    # Distinct idx ranges: http_tunneled_flow derives this flow's entire
    # 5-tuple from idx alone, so reusing the same range for both tunneled
    # categories made them collide into the same flow-table entry (an
    # earlier version of this function did exactly that; see README
    # Findings).
    for i in range(10):
        pkts, meta = http_tunneled_flow(2000 + i, t, "SSH")
        all_flows.append((pkts, meta))
        evasion_scenarios.append(dict(meta, packet_count=len(pkts)))
        t += 1.0
    for i in range(10):
        pkts, meta = http_tunneled_flow(2100 + i, t, "SMB")
        all_flows.append((pkts, meta))
        evasion_scenarios.append(dict(meta, packet_count=len(pkts)))
        t += 1.0

    assert len(evasion_scenarios) == 40

    non_dns_total = sum(len(pkts) for pkts, _ in all_flows)
    remaining = TARGET_TOTAL_PACKETS - non_dns_total
    n_dns_pairs = remaining // 2
    for i in range(n_dns_pairs):
        all_flows.append(dns_pair(i, t))
        t += 0.001

    total = sum(len(pkts) for pkts, _ in all_flows)
    pad = TARGET_TOTAL_PACKETS - total
    if pad > 0:
        pkts, meta = dns_pair(n_dns_pairs + 1, t)
        all_flows.append((pkts[:pad], meta))
        total += pad
    assert total == TARGET_TOTAL_PACKETS, f"packet count mismatch: {total} != {TARGET_TOTAL_PACKETS}"

    with open(PCAP_PATH, "wb") as f:
        pw.write_pcap_header(f)
        for pkts, _meta in all_flows:
            for ts, raw in pkts:
                pw.write_packet(f, ts, raw)

    with open(SCENARIOS_PATH, "w") as f:
        json.dump({
            "total_packets": total,
            "total_flows": len(all_flows),
            "mgmt_subnet_prefix": MGMT_SUBNET_PREFIX,
            "evasion_flows": evasion_scenarios,
        }, f, indent=2)

    print(f"wrote {total} packets ({len(all_flows)} flows) to {PCAP_PATH}")
    print(f"wrote {len(evasion_scenarios)} seeded evasion flow records to {SCENARIOS_PATH}")


if __name__ == "__main__":
    build()
