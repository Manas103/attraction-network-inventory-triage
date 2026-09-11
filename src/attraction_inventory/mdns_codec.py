"""Minimal, real DNS-wire-format encoder/decoder for the mDNS-style TXT beacon.

scapy ships a full DNS layer (scapy.layers.dns), but its name-compression
handling is tuned for live traffic and corrupts uncompressed synthetic names
on a pcap round trip (verified while building this project; the compression
pointer math assumes a name has already appeared earlier in the same
packet). Rather than fight that, this module hand-encodes a single-answer
DNS response using plain (uncompressed) labels, which RFC 1035 explicitly
allows. It is real DNS TXT wire format: header, zero questions, one answer
resource record of TYPE=TXT (16), CLASS=IN (1), followed by length-prefixed
character-strings. mDNS (RFC 6762) reuses this same record format over
UDP/5353, which is what "mDNS-style metadata" means here: the record shape
is real, the transport (UDP/5353, multicast destination) is real, and the
specific vendor/model/role content is synthetic.
"""
from __future__ import annotations

import struct


def _encode_name(hostname: str) -> bytes:
    out = bytearray()
    for label in hostname.strip(".").split("."):
        b = label.encode("ascii")
        if len(b) > 63:
            raise ValueError("DNS label too long")
        out.append(len(b))
        out.extend(b)
    out.append(0)
    return bytes(out)


def _decode_name(buf: bytes, offset: int) -> tuple[str, int]:
    labels = []
    while True:
        length = buf[offset]
        if length == 0:
            offset += 1
            break
        if length & 0xC0:
            raise ValueError("compressed name not supported by this decoder")
        offset += 1
        labels.append(buf[offset:offset + length].decode("ascii"))
        offset += length
    return ".".join(labels), offset


def encode_txt_response(hostname: str, txt_pairs: dict[str, str], ttl: int = 120) -> bytes:
    """Build a real DNS response message with one TXT answer record."""
    header = struct.pack(">HHHHHH", 0, 0x8400, 0, 1, 0, 0)  # id, flags(QR+AA), qd=0, an=1, ns=0, ar=0
    name = _encode_name(hostname)
    rdata = bytearray()
    for k, v in txt_pairs.items():
        entry = f"{k}={v}".encode("ascii")
        if len(entry) > 255:
            raise ValueError("TXT entry too long")
        rdata.append(len(entry))
        rdata.extend(entry)
    rr = name + struct.pack(">HHIH", 16, 1, ttl, len(rdata)) + bytes(rdata)
    return header + rr


def decode_txt_response(buf: bytes) -> tuple[str, dict[str, str]]:
    """Parse a message built by encode_txt_response back into (hostname, txt_pairs)."""
    _id, flags, qd, an, _ns, _ar = struct.unpack(">HHHHHH", buf[:12])
    if an < 1:
        raise ValueError("no answer records present")
    offset = 12
    name, offset = _decode_name(buf, offset)
    rtype, rclass, _ttl, rdlength = struct.unpack(">HHIH", buf[offset:offset + 10])
    offset += 10
    if rtype != 16:
        raise ValueError(f"expected TXT (16), got type {rtype}")
    rdata = buf[offset:offset + rdlength]
    pairs: dict[str, str] = {}
    pos = 0
    while pos < len(rdata):
        length = rdata[pos]
        pos += 1
        entry = rdata[pos:pos + length].decode("ascii")
        pos += length
        if "=" in entry:
            k, v = entry.split("=", 1)
            pairs[k] = v
    return name, pairs
