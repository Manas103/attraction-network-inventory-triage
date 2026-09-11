"""Vulnerability triage and IEC 62443 compensating controls.

For every fingerprinted, CPE-matched asset, looks up applicable CVEs from
the bundled offline CPE-to-CVE map (cpe_data.py). Assets flagged
vendor-locked (roster.py's vendor_locked field, carried through as
asset.vendor_locked on the FingerprintedAsset by inventory_db.py once it is
persisted) cannot simply be sent a patch ticket: they get a named
compensating control expressed in IEC 62443 zone/conduit terms instead.

IEC 62443 vocabulary used here: a "zone" groups assets that share a
security level; a "conduit" is the communication path connecting two zones,
which is where an allow-list segmentation control is actually enforced.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from .cpe_data import CveRecord, cve_lookup_by_cpe
from .cpe_match_exact import match_exact
from .roster import ZONE_NAMES, ZONE_SUBNET

_CVE_INDEX = cve_lookup_by_cpe()

ENGINEERING_ZONE = 4
INFRASTRUCTURE_ZONE = 3


@dataclass
class TriageResult:
    asset_id: str
    mac: str
    zone: int
    vendor: str
    model: str
    cpe23: str | None
    cves: list[CveRecord] = field(default_factory=list)
    vendor_locked: bool = False
    compensating_control: str | None = None


def _protocol_label(protocol: str | None, port: int | None) -> str:
    if protocol == "enip":
        return f"EtherNet/IP (TCP/{port or 44818})"
    if protocol == "modbus":
        return f"Modbus/TCP (TCP/{port or 502})"
    return "its discovery protocol"


def triage_asset(fp_asset, vendor_locked: bool) -> TriageResult:
    """fp_asset is a FingerprintedAsset (fingerprint.py)."""
    entry = match_exact(fp_asset)
    cves: list[CveRecord] = []
    if entry:
        seen = set()
        for cpe in entry.cpe23_ids:
            for rec in _CVE_INDEX.get(cpe, []):
                if rec.cve_id not in seen:
                    seen.add(rec.cve_id)
                    cves.append(rec)

    compensating_control = None
    if vendor_locked:
        zone = fp_asset.zone or 0
        zone_name = ZONE_NAMES.get(zone, f"Zone {zone}")
        proto_label = _protocol_label(fp_asset.protocol, fp_asset.port)
        cve_clause = (
            f"named CVEs: {', '.join(r.cve_id for r in cves)}"
            if cves else "no CVE present in this project's bundled CPE-to-CVE subset"
        )
        compensating_control = (
            f"IEC 62443 zone \"{zone_name}\" (Zone {zone}, {ZONE_SUBNET.get(zone, 'n/a')}), "
            f"conduit Zone {zone} <-> Zone {INFRASTRUCTURE_ZONE} (Network Infrastructure Zone backbone): "
            f"{fp_asset.vendor} {fp_asset.model} is vendor-locked firmware with no field-patchable update "
            f"path in this environment ({cve_clause}). Compensating control: network segmentation via a "
            f"dedicated conduit at the Zone {zone} boundary, allow-listing only {proto_label} traffic sourced "
            f"from the Zone {INFRASTRUCTURE_ZONE} engineering egress ({ZONE_SUBNET.get(ENGINEERING_ZONE, 'n/a')}), "
            f"default-deny for every other source and protocol at the conduit firewall, with conduit traffic "
            f"logged and alerted on any source outside the allow-list."
        )

    return TriageResult(
        asset_id=fp_asset.mac,
        mac=fp_asset.mac,
        zone=fp_asset.zone or 0,
        vendor=fp_asset.vendor or "unknown",
        model=fp_asset.model or "unknown",
        cpe23=entry.cpe23 if entry else None,
        cves=cves,
        vendor_locked=vendor_locked,
        compensating_control=compensating_control,
    )


def triage_all(fp_assets, vendor_locked_macs: set[str]) -> list[TriageResult]:
    return [triage_asset(a, a.mac in vendor_locked_macs) for a in fp_assets]
