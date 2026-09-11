"""Passive fingerprinting parser.

Reads a pcap from disk with Scapy's rdpcap and dissects each packet's
existing fields. It never constructs or sends a packet, and it never talks
to a live host; the only network I/O anywhere in this module is a file read.
That is what "passive identification from capture alone" means here.

Four sources are fused per asset, exactly as a real passive OT fingerprinter
would do it:
  - ARP replies: MAC <-> IP binding (every asset sends one)
  - EtherNet/IP List Identity (TCP/44818): CIP identity object fields
  - Modbus/TCP Read Device Identification (TCP/502, function 0x2B/0x0E): vendor/product/model strings
  - mDNS-style TXT record (UDP/5353): vendor/model/role/zone for devices with no ICS protocol footprint
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from scapy.all import ARP, IP, TCP, UDP, rdpcap
from scapy.contrib import enipTCP as enip
from scapy.contrib import modbus as mb

from .mdns_codec import decode_txt_response


@dataclass
class FingerprintedAsset:
    mac: str
    ip: Optional[str] = None
    vendor: Optional[str] = None
    model: Optional[str] = None
    role: Optional[str] = None
    zone: Optional[int] = None
    protocol: Optional[str] = None  # "enip", "modbus", "passive"
    port: Optional[int] = None
    cip_vendor_id: Optional[int] = None
    cip_device_type: Optional[int] = None
    cip_product_code: Optional[int] = None
    cip_revision: Optional[str] = None
    mb_revision: Optional[str] = None
    sources: list[str] = field(default_factory=list)


_MODBUS_OBJ_IDS = {0x00: "vendor_name", 0x01: "product_code", 0x02: "revision", 0x05: "model_name"}


def _parse_modbus_objects(raw: bytes) -> dict[str, str]:
    """The ADU + PDU header is a fixed 13 bytes; the object chain follows.

    ADU (transId,protoId,len,unitId) = 7 bytes, PDU header
    (funcCode,MEIType,readCode,conformityLevel,more,nextObjId,objCount) = 7
    bytes but funcCode/MEIType belong to the PDU parsed by scapy already
    when dissected as a layer; here we reparse from raw bytes directly
    (an independent decode path from the CPE matchers' scapy-dissection
    path is not required here, this module always uses scapy dissection;
    the independent path lives in oracle.py).
    """
    pdu = mb.ModbusPDU2B0EReadDeviceIdentificationResponse(raw)
    result: dict[str, str] = {}
    layer = pdu.payload
    while layer and isinstance(layer, mb.ModbusObjectId):
        name = _MODBUS_OBJ_IDS.get(layer.id)
        if name:
            value = layer.value
            if isinstance(value, bytes):
                value = value.decode("ascii", "ignore")
            result[name] = value
        layer = layer.payload
    return result


def fingerprint_capture(pcap_path: str | Path) -> list[FingerprintedAsset]:
    packets = rdpcap(str(pcap_path))
    assets: dict[str, FingerprintedAsset] = {}

    def get(mac: str) -> FingerprintedAsset:
        if mac not in assets:
            assets[mac] = FingerprintedAsset(mac=mac)
        return assets[mac]

    for pkt in packets:
        if ARP in pkt and pkt[ARP].op == 2:
            a = get(pkt[ARP].hwsrc)
            a.ip = pkt[ARP].psrc
            a.sources.append("arp")
            continue

        if TCP in pkt and pkt[TCP].sport == 44818 and enip.ENIPTCP in pkt:
            a = get(pkt.src)
            a.ip = pkt[IP].src
            a.protocol = "enip"
            a.port = 44818
            a.sources.append("enip_list_identity")
            li = pkt[enip.ENIPTCP].payload
            if isinstance(li, enip.ENIPListIdentity) and li.items:
                item = li.items[0]
                a.vendor = _CIP_VENDOR_NAMES.get(item.vendorId, f"CIP vendor id {item.vendorId}")
                a.model = item.productName.decode("ascii", "ignore") if isinstance(item.productName, bytes) else item.productName
                a.cip_vendor_id = item.vendorId
                a.cip_device_type = item.deviceType
                a.cip_product_code = item.productCode
                a.cip_revision = f"{item.revisionMajor}.{item.revisionMinor}"
                a.role = _CIP_DEVICE_TYPE_ROLE.get(item.deviceType, "Unknown CIP Device")
            continue

        if TCP in pkt and pkt[TCP].sport == 502:
            a = get(pkt.src)
            a.ip = pkt[IP].src
            a.protocol = "modbus"
            a.port = 502
            a.sources.append("modbus_read_device_id")
            raw = bytes(pkt[TCP].payload)
            try:
                # Skip the 7-byte Modbus ADU header (transId, protoId, len, unitId)
                # to get to the PDU + device-identification object chain.
                fields = _parse_modbus_objects(raw[7:])
            except Exception:
                fields = {}
            a.vendor = fields.get("vendor_name")
            a.model = fields.get("model_name") or fields.get("product_code")
            a.mb_revision = fields.get("revision")
            a.role = "PLC"
            continue

        if UDP in pkt and pkt[UDP].sport == 5353 and pkt[UDP].dport == 5353:
            a = get(pkt.src)
            a.ip = pkt[IP].src
            a.protocol = a.protocol or "passive"
            a.port = 5353
            a.sources.append("mdns_txt")
            raw = bytes(pkt[UDP].payload)
            try:
                _hostname, pairs = decode_txt_response(raw)
            except Exception:
                pairs = {}
            a.vendor = pairs.get("vendor", a.vendor)
            a.model = pairs.get("model", a.model)
            a.role = pairs.get("role", a.role)
            if "zone" in pairs:
                a.zone = int(pairs["zone"])
            continue

    for a in assets.values():
        if a.zone is None and a.ip:
            try:
                a.zone = int(a.ip.split(".")[2])
            except (ValueError, IndexError):
                pass

    return list(assets.values())


# ODVA CIP vendor ID 1 (Rockwell Automation) is a real registered ODVA
# vendor ID. 260 (Alcorn McBride) is not a verified registered ODVA vendor
# ID from any source consulted for this project; it is a plausible-shaped
# placeholder assigned for this synthetic fleet, disclosed here rather than
# presented as a real registry lookup.
_CIP_VENDOR_NAMES = {
    1: "Rockwell Automation",
    260: "Alcorn McBride",
}

# Real ODVA CIP device type codes (from the EtherNet/IP object library) mapped
# to a short role label, restricted to the codes this project actually uses.
_CIP_DEVICE_TYPE_ROLE = {
    14: "PLC",
    24: "HMI",
    43: "Show Controller",
}
