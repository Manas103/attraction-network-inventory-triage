"""A synthetic corporate IT estate: workstations, servers and cloud instances
across business units, each running a small installed-software inventory
sampled from cve_catalog.SOFTWARE_CATALOG. Unlike roster.py's OT fleet
(fixed 120 assets, 4 IEC 62443 zones, built once for the whole project),
this estate exists only for the KEV/EPSS-weighted remediation-queue claim
and models a corporate population the ranking policy needs: business
units, internet exposure, and data sensitivity, none of which the OT
roster carries or needs."""
from __future__ import annotations

import random
from dataclasses import dataclass, field

from .cve_catalog import SOFTWARE_CATALOG

BUSINESS_UNITS = ("Finance", "Engineering", "Sales", "HR", "Support", "Operations")
ASSET_KINDS = ("workstation", "server", "cloud_instance")


@dataclass(frozen=True)
class CorporateAsset:
    asset_id: str
    kind: str
    business_unit: str
    internet_facing: bool
    handles_sensitive_data: bool
    business_criticality: str  # "high" | "medium" | "low"
    installed_software: tuple[tuple[str, str], ...] = field(default_factory=tuple)

    @property
    def exposure_score(self) -> int:
        """A documented, inspectable 0-100 exposure score: 40 points for
        internet-facing, 35 for handling sensitive data, up to 25 for
        business criticality. Not a model; an analyst can recompute it by
        hand from the three inputs, the same design choice
        correlation.py's fidelity_score makes elsewhere in the portfolio."""
        score = 0
        if self.internet_facing:
            score += 40
        if self.handles_sensitive_data:
            score += 35
        score += {"high": 25, "medium": 12, "low": 0}[self.business_criticality]
        return score


def build_corporate_estate(n_assets: int, seed: int) -> list[CorporateAsset]:
    rng = random.Random(seed)
    products = list(SOFTWARE_CATALOG.items())
    assets = []
    for i in range(n_assets):
        kind = rng.choice(ASSET_KINDS)
        business_unit = rng.choice(BUSINESS_UNITS)
        # Servers and cloud instances are internet-facing far more often than workstations.
        internet_facing = rng.random() < (0.35 if kind != "workstation" else 0.05)
        handles_sensitive_data = rng.random() < 0.30
        business_criticality = rng.choices(("high", "medium", "low"), weights=(0.2, 0.5, 0.3))[0]

        n_software = rng.randint(3, 6)
        chosen_products = rng.sample(products, k=min(n_software, len(products)))
        installed = []
        for product, versions in chosen_products:
            # 35% chance the asset is still on a vulnerable (early-lineage) version.
            version = versions[rng.randrange(0, 2)] if rng.random() < 0.35 else rng.choice(versions[2:])
            installed.append((product, version))

        assets.append(
            CorporateAsset(
                asset_id=f"CORP-{i:05d}",
                kind=kind,
                business_unit=business_unit,
                internet_facing=internet_facing,
                handles_sensitive_data=handles_sensitive_data,
                business_criticality=business_criticality,
                installed_software=tuple(installed),
            )
        )
    return assets
