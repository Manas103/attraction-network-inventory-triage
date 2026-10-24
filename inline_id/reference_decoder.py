#!/usr/bin/env python3
"""Independent reference oracle for the claim "matched an independent
Python reference decoder on every verdict". Reads the same pcap file
inline_id reads, with its own from-scratch Ethernet/IPv4/TCP/UDP parser
(no shared code with pcap_writer.py, protocol_bytes.py, or the C++
decoders in src/), reassembles flows the same conceptual way (per-segment
PDU boundaries, a bounded inspection budget), and independently decides
each flow's protocol and policy verdict. compare_verdicts.py diffs this
output against inline_id's verdicts.csv.

Run with:
    python3 reference_decoder.py fixtures/enterprise_capture.pcap out.csv
"""
from __future__ import annotations

import socket
import struct
import sys

INSPECT_CAP = 24
MGMT_PREFIX = (10, 20, 0)


def ip_bytes_to_str(b: bytes) -> str:
    return socket.inet_ntoa(b)


def is_mgmt(ip_bytes: bytes) -> bool:
    return tuple(ip_bytes[0:3]) == MGMT_PREFIX


def identify(payload: bytes):
    """Returns (protocol, detail) or None. Independently re-derives each
    protocol's structure from its own spec, the same decisions
    src/decoders.cpp makes, written from scratch in Python."""
    if len(payload) >= 5 and payload[0] == 0x16 and 0x0300 <= (payload[1] << 8 | payload[2]) <= 0x0304:
        hs_type = payload[5] if len(payload) > 5 else None
        if hs_type == 0x01:
            return ("TLS", _tls_sni(payload))
        if hs_type == 0x02:
            return ("TLS", "")
    if len(payload) >= 64 and payload[0:4] == b"\xfeSMB":
        structure_size = payload[4] | (payload[5] << 8)
        command = payload[12] | (payload[13] << 8)
        if structure_size == 64 and command <= 18:
            return ("SMB", "")
    if len(payload) >= 12:
        flags = payload[2] << 8 | payload[3]
        qdcount = payload[4] << 8 | payload[5]
        opcode = (flags >> 11) & 0x0F
        if opcode <= 5 and 1 <= qdcount <= 16:
            qname = _dns_qname(payload)
            if qname is not None:
                return ("DNS", qname)
    if len(payload) >= 8 and payload[0:4] == b"SSH-":
        dash = payload.find(b"-", 4)
        if dash != -1:
            version_part = payload[4:dash]
            if version_part and all(c in b"0123456789." for c in version_part):
                return ("SSH", "")
    if len(payload) >= 16:
        for method in (b"GET ", b"POST ", b"HEAD ", b"PUT ", b"DELETE ", b"OPTIONS "):
            if payload.startswith(method):
                if _has_http_version_line(payload):
                    return ("HTTP", "")
        if payload.startswith(b"HTTP/"):
            if _has_http_version_line(payload):
                return ("HTTP", "")
    return None


def _has_http_version_line(payload: bytes) -> bool:
    idx = payload.find(b"\r\n")
    if idx == -1:
        return False
    line = payload[:idx]
    return b"HTTP/1." in line


def _tls_sni(payload: bytes):
    try:
        body_len = (payload[6] << 16) | (payload[7] << 8) | payload[8]
        p = 9
        end = min(len(payload), 9 + body_len)
        p += 2 + 32  # client_version, random
        session_id_len = payload[p]
        p += 1 + session_id_len
        cipher_len = payload[p] << 8 | payload[p + 1]
        p += 2 + cipher_len
        comp_len = payload[p]
        p += 1 + comp_len
        ext_total = payload[p] << 8 | payload[p + 1]
        p += 2
        ext_end = min(p + ext_total, end)
        while p + 4 <= ext_end:
            ext_type = payload[p] << 8 | payload[p + 1]
            ext_len = payload[p + 2] << 8 | payload[p + 3]
            body = p + 4
            if ext_type == 0 and body + 5 <= ext_end:
                name_len = payload[body + 3] << 8 | payload[body + 4]
                name = payload[body + 5: body + 5 + name_len]
                return name.decode(errors="replace")
            p = body + ext_len
    except (IndexError, ValueError):
        return ""
    return ""


def _dns_qname(payload: bytes):
    p = 12
    labels = []
    try:
        while p < len(payload) and payload[p] != 0:
            n = payload[p]
            if n > 63:
                return None
            p += 1
            labels.append(payload[p:p + n].decode(errors="replace"))
            p += n
    except IndexError:
        return None
    return ".".join(labels)


class Flow:
    __slots__ = ("originator", "dst_port", "inspected", "first_proto", "cur_proto", "tunneling")

    def __init__(self):
        self.originator = None
        self.dst_port = None
        self.inspected = 0
        self.first_proto = ""
        self.cur_proto = ""
        self.tunneling = False


def normalize_key(proto, ip_a, port_a, ip_b, port_b):
    a = (ip_a, port_a)
    b = (ip_b, port_b)
    return (proto,) + (a + b if a <= b else b + a)


def parse_pcap(path):
    with open(path, "rb") as f:
        global_hdr = f.read(24)
        if len(global_hdr) < 24:
            return
        while True:
            rec_hdr = f.read(16)
            if len(rec_hdr) < 16:
                break
            ts_sec, ts_usec, incl_len, _orig_len = struct.unpack("<IIII", rec_hdr)
            frame = f.read(incl_len)
            if len(frame) < incl_len:
                break
            yield frame


def main():
    pcap_path = sys.argv[1]
    out_path = sys.argv[2]

    flows: dict = {}

    for frame in parse_pcap(pcap_path):
        if len(frame) < 14:
            continue
        ethertype = frame[12] << 8 | frame[13]
        if ethertype != 0x0800:
            continue
        ip = frame[14:]
        if len(ip) < 20:
            continue
        ihl = (ip[0] & 0x0F) * 4
        if ihl < 20 or len(ip) < ihl:
            continue
        proto = ip[9]
        src_ip = ip[12:16]
        dst_ip = ip[16:20]
        l4 = ip[ihl:]

        if proto == 6:  # TCP
            if len(l4) < 20:
                continue
            src_port = l4[0] << 8 | l4[1]
            dst_port = l4[2] << 8 | l4[3]
            data_offset = ((l4[12] >> 4) & 0x0F) * 4
            flags = l4[13]
            if data_offset < 20 or len(l4) < data_offset:
                continue
            payload = l4[data_offset:]

            key = normalize_key(proto, src_ip, src_port, dst_ip, dst_port)
            is_syn = (flags & 0x02) and not (flags & 0x10)
            if is_syn:
                st = flows.setdefault(key, Flow())
                st.originator = src_ip
                st.dst_port = dst_port
        elif proto == 17:  # UDP
            if len(l4) < 8:
                continue
            src_port = l4[0] << 8 | l4[1]
            dst_port = l4[2] << 8 | l4[3]
            payload = l4[8:]
            key = normalize_key(proto, src_ip, src_port, dst_ip, dst_port)
        else:
            continue

        if not payload:
            continue
        st = flows.setdefault(key, Flow())
        if st.originator is None:
            st.originator = src_ip
            st.dst_port = dst_port
        if st.inspected >= INSPECT_CAP:
            continue
        st.inspected += 1
        result = identify(bytes(payload))
        if result is None:
            continue
        proto_name, _detail = result
        if not st.cur_proto:
            st.first_proto = proto_name
            st.cur_proto = proto_name
        elif proto_name != st.cur_proto:
            st.tunneling = True
            st.cur_proto = proto_name

    with open(out_path, "w") as out:
        out.write("src_ip,dst_ip,src_port,dst_port,proto_l4,identified_protocol,first_protocol,"
                   "tunneling_detected,our_decision,port_acl_decision\n")
        for key, st in flows.items():
            proto_l4, ip_a, port_a, ip_b, port_b = key
            if st.cur_proto in ("SMB", "SSH"):
                our = "ALLOW" if is_mgmt(st.originator) else "BLOCK"
            elif st.cur_proto in ("HTTP", "TLS", "DNS"):
                our = "ALLOW"
            else:
                our = "UNKNOWN"
            port_acl = "BLOCK" if st.dst_port in (445, 22) else "ALLOW"
            src_disp = ip_bytes_to_str(ip_a) if isinstance(ip_a, bytes) else ""
            dst_disp = ip_bytes_to_str(ip_b) if isinstance(ip_b, bytes) else ""
            out.write(
                f"{src_disp},{dst_disp},{port_a},{port_b},{proto_l4},{st.cur_proto},"
                f"{st.first_proto},{1 if st.tunneling else 0},{our},{port_acl}\n"
            )
    print(f"wrote {len(flows)} flow verdicts to {out_path}")


if __name__ == "__main__":
    main()
