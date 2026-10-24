"""Builds real, structurally valid protocol payloads for the five
enterprise protocols this extension's capture needs: HTTP/1.1, TLS 1.2
(ClientHello/ServerHello/ApplicationData records), DNS, the SSH version
banner, and an SMB2 header. These are small, spec-shaped encoders, not
full client/server implementations: each produces exactly the bytes a
protocol decoder needs to recognize and validate the protocol from, which
is also exactly what inline_id/src/decoders.cpp and reference_decoder.py
each independently parse back out.
"""
from __future__ import annotations

import struct

# ---------------------------------------------------------------------------
# HTTP/1.1
# ---------------------------------------------------------------------------


def http_request(host: str, path: str = "/index.html") -> bytes:
    return (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"User-Agent: synthetic-enterprise-capture/1.0\r\n"
        f"Accept: */*\r\n\r\n"
    ).encode()


def http_response(body: str = "Hello, world!") -> bytes:
    body_b = body.encode()
    return (
        f"HTTP/1.1 200 OK\r\n"
        f"Content-Type: text/plain\r\n"
        f"Content-Length: {len(body_b)}\r\n\r\n"
    ).encode() + body_b


# ---------------------------------------------------------------------------
# TLS 1.2 (RFC 5246 record/handshake shapes)
# ---------------------------------------------------------------------------

TLS_HANDSHAKE = 0x16
TLS_APPLICATION_DATA = 0x17
TLS_VERSION_1_2 = 0x0303


def _tls_record(record_type: int, body: bytes) -> bytes:
    return struct.pack("!BHH", record_type, TLS_VERSION_1_2, len(body)) + body


def tls_client_hello(sni: str, cipher_suites=(0xC02F, 0xC030, 0x009E, 0x1301, 0x1302)) -> bytes:
    random_bytes = bytes(range(32))
    session_id = b""
    cipher_bytes = b"".join(struct.pack("!H", c) for c in cipher_suites)
    compression = b"\x00"

    sni_name = sni.encode()
    server_name_list = struct.pack("!BH", 0x00, len(sni_name)) + sni_name
    sni_ext_body = struct.pack("!H", len(server_name_list)) + server_name_list
    sni_ext = struct.pack("!HH", 0x0000, len(sni_ext_body)) + sni_ext_body
    extensions = sni_ext

    body = (
        struct.pack("!H", TLS_VERSION_1_2)
        + random_bytes
        + struct.pack("!B", len(session_id)) + session_id
        + struct.pack("!H", len(cipher_bytes)) + cipher_bytes
        + struct.pack("!B", len(compression)) + compression
        + struct.pack("!H", len(extensions)) + extensions
    )
    handshake = struct.pack("!B", 0x01) + struct.pack("!I", len(body))[1:] + body
    return _tls_record(TLS_HANDSHAKE, handshake)


def tls_server_hello(cipher_suite=0xC02F) -> bytes:
    random_bytes = bytes(range(32, 64))
    session_id = b""
    body = (
        struct.pack("!H", TLS_VERSION_1_2)
        + random_bytes
        + struct.pack("!B", len(session_id)) + session_id
        + struct.pack("!H", cipher_suite)
        + struct.pack("!B", 0x00)
    )
    handshake = struct.pack("!B", 0x02) + struct.pack("!I", len(body))[1:] + body
    return _tls_record(TLS_HANDSHAKE, handshake)


def tls_application_data(n: int = 128) -> bytes:
    return _tls_record(TLS_APPLICATION_DATA, bytes((i % 256) for i in range(n)))


# ---------------------------------------------------------------------------
# DNS (RFC 1035)
# ---------------------------------------------------------------------------


def _encode_qname(name: str) -> bytes:
    out = b""
    for label in name.split("."):
        out += struct.pack("!B", len(label)) + label.encode()
    return out + b"\x00"


def dns_query(qname: str, qid: int) -> bytes:
    header = struct.pack("!HHHHHH", qid, 0x0100, 1, 0, 0, 0)
    question = _encode_qname(qname) + struct.pack("!HH", 1, 1)  # A, IN
    return header + question


def dns_response(qname: str, qid: int, answer_ip: str = "10.30.0.50") -> bytes:
    header = struct.pack("!HHHHHH", qid, 0x8180, 1, 1, 0, 0)
    question = _encode_qname(qname) + struct.pack("!HH", 1, 1)
    answer = (
        b"\xc0\x0c"  # name pointer back to the question
        + struct.pack("!HHIH", 1, 1, 300, 4)
        + bytes(int(o) for o in answer_ip.split("."))
    )
    return header + question + answer


# ---------------------------------------------------------------------------
# SSH (RFC 4253 version banner)
# ---------------------------------------------------------------------------


def ssh_banner(client: bool) -> bytes:
    if client:
        return b"SSH-2.0-synthetic_client_1.0\r\n"
    return b"SSH-2.0-OpenSSH_8.9p1\r\n"


# ---------------------------------------------------------------------------
# SMB2 (MS-SMB2 header, 64 bytes)
# ---------------------------------------------------------------------------

SMB2_MAGIC = b"\xfeSMB"


def smb2_header(command: int, message_id: int, is_response: bool) -> bytes:
    """MS-SMB2 2.2.1: every multi-byte field in the header is little-
    endian, unlike every other protocol this module builds (TLS, DNS,
    HTTP's ASCII grammar, TCP/IP itself), which are all big-endian/network
    order. An earlier version of this function packed these fields with
    struct's "!" (big-endian) format, which inline_id/src/decoders.cpp's
    try_smb2 (correctly little-endian, per spec) could never parse; see
    README Findings."""
    structure_size = 64
    credit_charge = 1
    status = 0
    credit = 1
    flags = 0x00000001 if is_response else 0x00000000
    next_command = 0
    reserved = 0
    tree_id = 0
    session_id = 1
    signature = b"\x00" * 16
    return (
        SMB2_MAGIC
        + struct.pack("<H", structure_size)
        + struct.pack("<H", credit_charge)
        + struct.pack("<I", status)
        + struct.pack("<H", command)
        + struct.pack("<H", credit)
        + struct.pack("<I", flags)
        + struct.pack("<I", next_command)
        + struct.pack("<Q", message_id)
        + struct.pack("<I", reserved)
        + struct.pack("<I", tree_id)
        + struct.pack("<Q", session_id)
        + signature
    )
