"""A minimal, fast, wire-valid pcap writer.

The industrial half of this repo builds packets with Scapy (see
capture_gen.py at the repo root); for the 1.2M-packet enterprise capture
this extension needs, Scapy's per-packet object construction is too slow
to be practical (measured well under 10,000 pkts/sec on this machine).
This module instead struct.packs real Ethernet/IPv4/TCP/UDP headers
directly, computing real IPv4 and TCP/UDP checksums, so the output is
still a genuine, wire-valid pcap (any real pcap reader, including
Wireshark, parses it correctly), just built without Scapy's overhead.
"""
from __future__ import annotations

import socket
import struct
from typing import BinaryIO

PCAP_MAGIC = 0xA1B2C3D4
ETHERTYPE_IPV4 = 0x0800
PROTO_TCP = 6
PROTO_UDP = 17

SRC_MAC = bytes.fromhex("0a0000000001")
DST_MAC = bytes.fromhex("0a0000000002")


def write_pcap_header(f: BinaryIO) -> None:
    f.write(struct.pack("<IHHiIII", PCAP_MAGIC, 2, 4, 0, 0, 65535, 1))


def write_packet(f: BinaryIO, ts: float, data: bytes) -> None:
    ts_sec = int(ts)
    ts_usec = int((ts - ts_sec) * 1_000_000)
    f.write(struct.pack("<IIII", ts_sec, ts_usec, len(data), len(data)))
    f.write(data)


def _ipv4_checksum(header: bytes) -> int:
    if len(header) % 2:
        header += b"\x00"
    total = sum(struct.unpack("!%dH" % (len(header) // 2), header))
    total = (total & 0xFFFF) + (total >> 16)
    total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def ip_to_bytes(ip: str) -> bytes:
    return socket.inet_aton(ip)


def build_ipv4_header(total_length: int, ident: int, proto: int, src_ip: bytes, dst_ip: bytes) -> bytes:
    ver_ihl = (4 << 4) | 5
    header = struct.pack(
        "!BBHHHBBH4s4s",
        ver_ihl, 0, total_length, ident & 0xFFFF, 0x4000, 64, proto, 0, src_ip, dst_ip,
    )
    checksum = _ipv4_checksum(header)
    return header[:10] + struct.pack("!H", checksum) + header[12:]


def _l4_checksum(src_ip: bytes, dst_ip: bytes, proto: int, l4_segment: bytes) -> int:
    pseudo = src_ip + dst_ip + struct.pack("!BBH", 0, proto, len(l4_segment))
    body = pseudo + l4_segment
    if len(body) % 2:
        body += b"\x00"
    total = sum(struct.unpack("!%dH" % (len(body) // 2), body))
    total = (total & 0xFFFF) + (total >> 16)
    total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def build_tcp_segment(src_port: int, dst_port: int, seq: int, ack: int, flags: int,
                       payload: bytes, src_ip: bytes, dst_ip: bytes) -> bytes:
    data_offset = (5 << 4)
    header_no_cksum = struct.pack(
        "!HHIIBBHHH",
        src_port, dst_port, seq & 0xFFFFFFFF, ack & 0xFFFFFFFF,
        data_offset, flags, 65535, 0, 0,
    )
    segment = header_no_cksum + payload
    checksum = _l4_checksum(src_ip, dst_ip, PROTO_TCP, segment)
    return header_no_cksum[:16] + struct.pack("!H", checksum) + header_no_cksum[18:] + payload


def build_udp_segment(src_port: int, dst_port: int, payload: bytes, src_ip: bytes, dst_ip: bytes) -> bytes:
    length = 8 + len(payload)
    header_no_cksum = struct.pack("!HHHH", src_port, dst_port, length, 0)
    segment = header_no_cksum + payload
    checksum = _l4_checksum(src_ip, dst_ip, PROTO_UDP, segment)
    if checksum == 0:
        checksum = 0xFFFF
    return header_no_cksum[:6] + struct.pack("!H", checksum) + payload


_ident_counter = [0]


def _next_ident() -> int:
    _ident_counter[0] = (_ident_counter[0] + 1) & 0xFFFF
    return _ident_counter[0]


def eth_ip_tcp(src_ip: str, dst_ip: str, src_port: int, dst_port: int,
               seq: int, ack: int, flags: int, payload: bytes = b"") -> bytes:
    src_b, dst_b = ip_to_bytes(src_ip), ip_to_bytes(dst_ip)
    tcp = build_tcp_segment(src_port, dst_port, seq, ack, flags, payload, src_b, dst_b)
    ip = build_ipv4_header(20 + len(tcp), _next_ident(), PROTO_TCP, src_b, dst_b)
    eth = DST_MAC + SRC_MAC + struct.pack("!H", ETHERTYPE_IPV4)
    return eth + ip + tcp


def eth_ip_udp(src_ip: str, dst_ip: str, src_port: int, dst_port: int, payload: bytes) -> bytes:
    src_b, dst_b = ip_to_bytes(src_ip), ip_to_bytes(dst_ip)
    udp = build_udp_segment(src_port, dst_port, payload, src_b, dst_b)
    ip = build_ipv4_header(20 + len(udp), _next_ident(), PROTO_UDP, src_b, dst_b)
    eth = DST_MAC + SRC_MAC + struct.pack("!H", ETHERTYPE_IPV4)
    return eth + ip + udp
