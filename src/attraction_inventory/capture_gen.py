"""Synthetic pcap fixture generator.

Builds offline .pcapng-compatible pcap files with Scapy, then writes them to
disk. Nothing here ever opens a socket, sends a probe, or touches a real
device; every packet is constructed in memory and written with wrpcap. This
is honest offline capture generation, not live sniffing: the fingerprinting
stage (fingerprint.py) only ever reads these files back with rdpcap, exactly
like it would read a real capture handed to it by a network tap.

There is no real attraction, no real backstage network, and no real device
behind any of these packets; that is disclosed here and in the README.
"""
from __future__ import annotations

import random
from pathlib import Path

from scapy.all import ARP, DNS, Ether, IP, TCP, UDP, wrpcap
from scapy.contrib import enipTCP as enip
from scapy.contrib import modbus as mb

from .mdns_codec import encode_txt_response
from .roster import AssetSpec, build_roster

ENGINEERING_MAC = "02:00:04:ff:00:01"
ENGINEERING_IP = "10.42.4.2"


def _enip_list_identity_packet(asset: AssetSpec) -> Ether:
    item = enip.ENIPListIdentityItem(
        vendorId=asset.cip_vendor_id,
        deviceType=asset.cip_device_type,
        productCode=asset.cip_product_code,
        revisionMajor=asset.cip_revision_major,
        revisionMinor=asset.cip_revision_minor,
        serialNumber=asset.cip_serial,
        productName=asset.model.encode("ascii", "ignore")[:64],
        productNameLength=len(asset.model.encode("ascii", "ignore")[:64]),
        sinPort=asset.port,
        sinAddress=asset.ip,
    )
    li = enip.ENIPListIdentity(itemCount=1, items=[item])
    body = enip.ENIPTCP(commandId=0x63, session=0, status=0) / li
    return (
        Ether(src=asset.mac, dst=ENGINEERING_MAC)
        / IP(src=asset.ip, dst=ENGINEERING_IP)
        / TCP(sport=asset.port, dport=51000, flags="PA")
        / body
    )


def _modbus_device_id_packet(asset: AssetSpec) -> Ether:
    objs = [
        mb.ModbusObjectId(id=0x00, length=len(asset.mb_vendor_name), value=asset.mb_vendor_name.encode()),
        mb.ModbusObjectId(id=0x01, length=len(asset.mb_product_code), value=asset.mb_product_code.encode()),
        mb.ModbusObjectId(id=0x02, length=len(asset.mb_revision), value=asset.mb_revision.encode()),
        mb.ModbusObjectId(id=0x05, length=len(asset.mb_model_name), value=asset.mb_model_name.encode()),
    ]
    pdu = mb.ModbusPDU2B0EReadDeviceIdentificationResponse(
        readCode=0x01, conformityLevel=0x01, more=0x00, nextObjId=0x00, objCount=len(objs),
    )
    payload = bytes(pdu) + b"".join(bytes(o) for o in objs)
    adu = mb.ModbusADUResponse(transId=1, protoId=0, unitId=asset.mb_unit_id, len=len(payload) + 1)
    return (
        Ether(src=asset.mac, dst=ENGINEERING_MAC)
        / IP(src=asset.ip, dst=ENGINEERING_IP)
        / TCP(sport=asset.port, dport=51001, flags="PA")
        / (bytes(adu) + payload)
    )


def _mdns_txt_packet(asset: AssetSpec) -> Ether:
    txt = {"vendor": asset.vendor, "model": asset.model, "role": asset.role, "zone": str(asset.zone)}
    raw = encode_txt_response(asset.mdns_hostname, txt)
    return (
        Ether(src=asset.mac, dst="01:00:5e:00:00:fb")
        / IP(src=asset.ip, dst="224.0.0.251")
        / UDP(sport=5353, dport=5353)
        / raw
    )


def _arp_reply_packet(asset: AssetSpec) -> Ether:
    return (
        Ether(src=asset.mac, dst=ENGINEERING_MAC)
        / ARP(op=2, hwsrc=asset.mac, psrc=asset.ip, hwdst=ENGINEERING_MAC, pdst=ENGINEERING_IP)
    )


def build_packets_for_asset(asset: AssetSpec) -> list:
    packets = [_arp_reply_packet(asset)]
    if asset.protocol == "enip":
        packets.append(_enip_list_identity_packet(asset))
    elif asset.protocol == "modbus":
        packets.append(_modbus_device_id_packet(asset))
    else:
        packets.append(_mdns_txt_packet(asset))
    return packets


def generate_capture(assets: list[AssetSpec], out_path: str | Path, seed: int = 1) -> Path:
    """Write one interleaved, time-jittered pcap covering every asset in `assets`."""
    rng = random.Random(seed)
    all_packets = []
    t = 0.0
    order = list(range(len(assets)))
    rng.shuffle(order)
    for idx in order:
        asset = assets[idx]
        for pkt in build_packets_for_asset(asset):
            t += rng.uniform(0.001, 0.05)
            pkt.time = t
            all_packets.append(pkt)
    all_packets.sort(key=lambda p: p.time)
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    wrpcap(str(out_path), all_packets)
    return out_path


def generate_baseline_and_drift_captures(data_dir: str | Path, seed: int = 20260817) -> dict:
    """Regenerate both fixture captures used by the pipeline and the tests.

    Regenerate with:
        venv/Scripts/python.exe scripts/generate_fixtures.py
    """
    data_dir = Path(data_dir)
    baseline_roster = build_roster(seed=seed, extra_undocumented=0)
    drift_roster = build_roster(seed=seed, extra_undocumented=30)

    baseline_path = generate_capture(baseline_roster, data_dir / "baseline_capture.pcap", seed=seed)
    drift_path = generate_capture(drift_roster, data_dir / "drift_capture.pcap", seed=seed + 1)

    return {
        "baseline_roster": baseline_roster,
        "drift_roster": drift_roster,
        "baseline_path": baseline_path,
        "drift_path": drift_path,
    }
