"""A synthetic CVE/KEV/EPSS catalog for the corporate-estate extension.

This is NOT real NVD, CISA KEV, or FIRST EPSS data, unlike cpe_data.py's
genuinely real CPE/CVE subset for the OT fleet. KEV and EPSS are both
live, continuously updated feeds (FIRST recomputes EPSS daily); embedding
a frozen "real" snapshot here would silently go stale the moment it was
written and would misrepresent a point-in-time number as a durable fact.
Every identifier below uses the CORP-CVE- prefix specifically so it can
never be mistaken for a real NVD CVE id, and every field is synthetic but
shaped exactly like the real thing: a CVSS base score, a boolean KEV
membership flag, and an EPSS-style exploitation-probability float in
[0, 1], generated to be internally consistent (a KEV-listed entry always
carries a high EPSS score, because real KEV membership and high EPSS are
strongly correlated in practice, not independent coin flips).
"""
from __future__ import annotations

import random
from dataclasses import dataclass

CVSS_CRITICAL_THRESHOLD = 9.0


@dataclass(frozen=True)
class CorporateCveRecord:
    cve_id: str
    product: str
    vulnerable_versions: tuple[str, ...]
    cvss: float
    kev_listed: bool
    epss_score: float
    description: str

    @property
    def is_critical(self) -> bool:
        return self.cvss >= CVSS_CRITICAL_THRESHOLD


# 16 synthetic products a corporate estate plausibly runs, each with a small
# version lineage; "vulnerable_versions" below names the versions actually
# affected by that product's CVE record, not every version ever shipped.
SOFTWARE_CATALOG: dict[str, tuple[str, ...]] = {
    "AcmeOffice Suite": ("18.0", "18.2", "18.4", "19.0", "19.1"),
    "Harborline VPN Client": ("4.1", "4.3", "4.5", "5.0"),
    "Quillwork PDF Reader": ("11.2", "11.5", "11.8", "12.0"),
    "Ferrotype Backup Agent": ("6.0", "6.2", "6.4", "6.6"),
    "Bastion Endpoint Agent": ("3.9", "4.0", "4.1", "4.2"),
    "Cobblestone Web Server": ("2.4.1", "2.4.3", "2.4.5", "2.6.0"),
    "Meridian Mail Transfer Agent": ("8.1", "8.3", "8.5", "9.0"),
    "Driftwood File Sync": ("2.0", "2.1", "2.2", "2.3"),
    "Palisade Firewall Manager": ("5.5", "5.7", "5.9", "6.1"),
    "Stonebridge Database Driver": ("1.9", "2.0", "2.1", "2.2"),
    "Lanternfish Remote Desktop": ("7.0", "7.2", "7.4", "7.6"),
    "Copperline ERP Connector": ("3.3", "3.5", "3.7", "3.9"),
    "Wrenfield Identity Gateway": ("2.8", "3.0", "3.2", "3.4"),
    "Sablewood Virtualization Host Tools": ("1.4", "1.6", "1.8", "2.0"),
    "Tallowmere Print Spooler Driver": ("9.0", "9.2", "9.4", "9.6"),
    "Ironvale Secure Shell Daemon": ("1.0", "1.1", "1.2", "1.3"),
}


def _record(rng: random.Random, product: str, vulnerable_versions: tuple[str, ...], cvss: float, kev_listed: bool, index: int) -> CorporateCveRecord:
    # A real KEV entry is near-certainly exploited (FIRST's EPSS routinely
    # scores actively-exploited CVEs above 0.9); a non-KEV critical CVE
    # still spans a wide, realistic range rather than clustering near 0.
    epss = round(rng.uniform(0.90, 0.99), 4) if kev_listed else round(rng.uniform(0.02, 0.85), 4)
    return CorporateCveRecord(
        cve_id=f"CORP-CVE-2026-{1000 + index}",
        product=product,
        vulnerable_versions=vulnerable_versions,
        cvss=cvss,
        kev_listed=kev_listed,
        epss_score=epss,
        description=f"Remote-exploitable flaw in {product} affecting versions {', '.join(vulnerable_versions)}.",
    )


def build_cve_catalog(seed: int) -> list[CorporateCveRecord]:
    """One synthetic CVE per product (16 total): 10 CVSS-critical (>= 9.0,
    2 of which are KEV-listed), 6 below the critical threshold, so the
    estate's finding generator has both critical and non-critical signal
    to filter on, the same way cpe_data.py's partial coverage gives the
    matchers something to correctly return no match for."""
    rng = random.Random(seed)
    products = list(SOFTWARE_CATALOG.items())
    catalog: list[CorporateCveRecord] = []

    critical_kev_products = products[0:2]
    critical_non_kev_products = products[2:10]
    non_critical_products = products[10:16]

    # index is a running counter across all three groups, not a per-group offset,
    # specifically because a per-group hardcoded offset is what produced this
    # module's own real bug (see README Findings): shrinking critical_kev_products
    # from 4 to 2 products left critical_non_kev_products's "+4" offset stale,
    # colliding two different products onto the identical CORP-CVE id.
    index = 0
    for product, versions in critical_kev_products:
        catalog.append(_record(rng, product, versions[:1], round(rng.uniform(9.6, 10.0), 1), True, index))
        index += 1
    for product, versions in critical_non_kev_products:
        catalog.append(_record(rng, product, versions[:2], round(rng.uniform(9.0, 9.5), 1), False, index))
        index += 1
    for product, versions in non_critical_products:
        catalog.append(_record(rng, product, versions[:1], round(rng.uniform(6.0, 8.5), 1), False, index))
        index += 1

    return catalog
