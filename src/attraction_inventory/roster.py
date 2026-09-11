"""Ground-truth synthetic asset roster for a fictional attraction backstage network.

Everything here is synthetic and disclosed as such: there is no real device, no
real capture, and no real attraction. The vendor and model names are real
industrial-control-system products (chosen so the CPE/CVE matching stage has
something real to match against), but the specific network of 120 units is
invented for this project.

Zones follow an IEC 62443-style split:
  Zone 1  Ride Control     - PLCs, safety PLCs, HMIs that operate the ride
  Zone 2  Show Control     - show/media controllers (audio, animatronics, lighting cues)
  Zone 3  Network Infrastructure - the managed switches that carry the conduits
  Zone 4  Engineering      - engineering workstations used for maintenance

Regeneration: this module is pure and deterministic (seeded), so calling
build_roster() twice returns the identical 120-asset list. It is imported by
capture_gen.py; there is no separate CLI for it (see scripts/generate_fixtures.py).
"""
from __future__ import annotations

import random
from dataclasses import dataclass, field
from typing import Optional

ZONE_NAMES = {
    1: "Ride Control Zone",
    2: "Show Control Zone",
    3: "Network Infrastructure Zone",
    4: "Engineering Zone",
}

ZONE_SUBNET = {
    1: "10.42.1.0/24",
    2: "10.42.2.0/24",
    3: "10.42.3.0/24",
    4: "10.42.4.0/24",
}


@dataclass
class AssetSpec:
    asset_id: str
    zone: int
    role: str
    vendor: str
    model: str
    protocol: str  # "enip", "modbus", "passive"
    mac: str
    ip: str
    vendor_locked: bool
    port: Optional[int] = None
    # EtherNet/IP (CIP identity object) fields
    cip_vendor_id: Optional[int] = None
    cip_device_type: Optional[int] = None
    cip_product_code: Optional[int] = None
    cip_revision_major: Optional[int] = None
    cip_revision_minor: Optional[int] = None
    cip_serial: Optional[int] = None
    # Modbus device identification fields
    mb_vendor_name: Optional[str] = None
    mb_product_code: Optional[str] = None
    mb_model_name: Optional[str] = None
    mb_revision: Optional[str] = None
    mb_unit_id: Optional[int] = None
    # extra metadata carried in mDNS-style TXT for passive-only assets
    mdns_hostname: Optional[str] = None


# (count, zone, role, vendor, model, protocol, vendor_locked, extra)
_FLEET_PLAN = [
    (25, 1, "PLC", "Rockwell Automation", "1756-ENBT/A ControlLogix EtherNet/IP Bridge", "enip", True,
     dict(cip_vendor_id=1, cip_device_type=14, cip_product_code=1756)),
    (12, 1, "HMI", "Rockwell Automation", "PanelView Plus 6 700", "enip", True,
     dict(cip_vendor_id=1, cip_device_type=24, cip_product_code=2711)),
    (8, 1, "HMI", "Rockwell Automation", "PanelView 5510", "enip", True,
     dict(cip_vendor_id=1, cip_device_type=24, cip_product_code=5510)),
    (20, 1, "PLC", "Schneider Electric", "BMXP342020 Modicon M340 CPU / BMXNOE0100", "modbus", True,
     dict(mb_vendor_name="Schneider Electric", mb_product_code="BMXP342020", mb_model_name="Modicon M340")),
    (10, 1, "Safety PLC", "Schneider Electric", "BMXNOR0200 Modicon M340 Safety Module", "modbus", True,
     dict(mb_vendor_name="Schneider Electric", mb_product_code="BMXNOR0200", mb_model_name="Modicon M340 Safety")),
    (10, 2, "Show Controller", "Alcorn McBride", "V4X Show Controller", "enip", True,
     dict(cip_vendor_id=260, cip_device_type=43, cip_product_code=4)),
    (8, 3, "Managed Switch", "Belden/Hirschmann", "RS20 Managed Switch", "passive", True, dict()),
    (7, 3, "Managed Switch", "Belden/Hirschmann", "RSR20 Managed Switch", "passive", True, dict()),
    (5, 3, "Managed Switch", "Belden/Hirschmann", "OCTOPUS 16M Managed Switch", "passive", True, dict()),
    (8, 4, "Engineering Workstation", "Dell", "OptiPlex 7020 (Windows 11 IoT Enterprise LTSC)", "passive", False, dict()),
    (7, 4, "Engineering Workstation", "HP", "EliteDesk 805 G8 (Windows 11 IoT Enterprise LTSC)", "passive", False, dict()),
]

assert sum(p[0] for p in _FLEET_PLAN) == 120, "fleet plan must sum to exactly 120 ground-truth assets"

def _next_ip(counter: dict[int, int], zone: int) -> str:
    host = counter[zone]
    counter[zone] += 1
    if host > 250:
        raise ValueError(f"zone {zone} exhausted its /24 host range in this synthetic scheme")
    return f"10.42.{zone}.{host}"


def _next_mac(counter: dict[int, int], zone: int, role_code: int) -> str:
    idx = counter[zone]
    counter[zone] += 1
    return f"02:00:{zone:02x}:{role_code:02x}:{(idx >> 8) & 0xFF:02x}:{idx & 0xFF:02x}"


def build_roster(seed: int = 20260817, extra_undocumented: int = 0) -> list[AssetSpec]:
    """Build the deterministic 120-asset ground-truth roster.

    extra_undocumented: when > 0, appends that many additional, never-issued
    "rogue"/undocumented hosts (used to build the drift-detection follow-up
    capture). These are excluded from the 120-asset ground truth on purpose;
    they exist to be caught as drift, not to be part of the baseline count.

    IP and MAC counters are local to each call (not module-level state), so
    build_roster() is genuinely idempotent: calling it any number of times,
    in any order, with any extra_undocumented value, always returns the
    identical 120-asset ground truth for a given seed. An earlier version
    used module-level counter dicts that accumulated across calls and, after
    a handful of calls in the same process, overran a zone's /24 host range;
    see README.md, Findings.
    """
    rng = random.Random(seed)
    roster: list[AssetSpec] = []
    host_counter = {1: 10, 2: 10, 3: 10, 4: 10}
    mac_counter = {1: 1, 2: 1, 3: 1, 4: 1}
    role_code = 0
    for count, zone, role, vendor, model, protocol, vendor_locked, extra in _FLEET_PLAN:
        role_code += 1
        for i in range(count):
            asset_id = f"{role.upper().replace(' ', '-')}-{zone}-{i+1:03d}"
            mac = _next_mac(mac_counter, zone, role_code)
            ip = _next_ip(host_counter, zone)
            spec_kwargs = dict(
                asset_id=asset_id, zone=zone, role=role, vendor=vendor, model=model,
                protocol=protocol, mac=mac, ip=ip, vendor_locked=vendor_locked,
            )
            if protocol == "enip":
                spec_kwargs["port"] = 44818
                spec_kwargs["cip_vendor_id"] = extra["cip_vendor_id"]
                spec_kwargs["cip_device_type"] = extra["cip_device_type"]
                spec_kwargs["cip_product_code"] = extra["cip_product_code"]
                spec_kwargs["cip_revision_major"] = rng.choice([20, 21, 28, 33])
                spec_kwargs["cip_revision_minor"] = rng.randint(1, 15)
                spec_kwargs["cip_serial"] = rng.randint(0x10000000, 0xFFFFFFFF)
            elif protocol == "modbus":
                spec_kwargs["port"] = 502
                spec_kwargs["mb_vendor_name"] = extra["mb_vendor_name"]
                spec_kwargs["mb_product_code"] = extra["mb_product_code"]
                spec_kwargs["mb_model_name"] = extra["mb_model_name"]
                spec_kwargs["mb_revision"] = f"{rng.randint(2, 3)}.{rng.randint(0, 9)}"
                spec_kwargs["mb_unit_id"] = rng.randint(1, 247)
            else:  # passive: ARP + mDNS-style TXT beacon only, no ICS protocol
                spec_kwargs["port"] = 5353
                spec_kwargs["mdns_hostname"] = f"{role.lower().replace(' ', '-')}-{zone}-{i+1:03d}.local"
            roster.append(AssetSpec(**spec_kwargs))

    if extra_undocumented:
        roster.extend(_build_undocumented_hosts(extra_undocumented, seed=seed + 1))
    return roster


def _build_undocumented_hosts(n: int, seed: int) -> list[AssetSpec]:
    """Rogue/undocumented hosts seeded into the follow-up capture only.

    These simulate what a real drift-detection pass is meant to catch:
    engineering laptops and rogue access points left plugged into a
    backstage zone without being logged on any issued diagram.
    """
    rng = random.Random(seed)
    hosts = []
    templates = [
        ("Engineering Workstation", "Lenovo", "ThinkPad T14 (unmanaged)", 4),
        ("Rogue Access Point", "TP-Link", "TL-WR841N (unauthorized)", 1),
        ("Engineering Workstation", "Apple", "MacBook Pro (personal, unmanaged)", 4),
        ("Unmanaged Switch", "Netgear", "GS108 (unmanaged, unauthorized)", 3),
    ]
    for i in range(n):
        role, vendor, model, zone = templates[i % len(templates)]
        mac = f"02:00:{zone:02x}:ff:{(i >> 8) & 0xFF:02x}:{i & 0xFF:02x}"
        ip = f"10.42.{zone}.{200 + i}"
        hosts.append(AssetSpec(
            asset_id=f"UNDOCUMENTED-{zone}-{i+1:03d}",
            zone=zone, role=role, vendor=vendor, model=model, protocol="passive",
            mac=mac, ip=ip, vendor_locked=False, port=5353,
            mdns_hostname=f"undocumented-{zone}-{i+1:03d}.local",
        ))
    return hosts
