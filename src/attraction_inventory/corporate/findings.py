"""Turns a corporate estate's installed-software inventory plus the CVE
catalog into one Finding per (asset, CVE) pair where the asset's installed
version is in the CVE's vulnerable_versions, exactly the join
triage.py already does for the OT fleet's CPE-to-CVE map, generalized to a
population large enough to produce a realistic fix-now queue."""
from __future__ import annotations

from dataclasses import dataclass

from .cve_catalog import CorporateCveRecord
from .estate import CorporateAsset


@dataclass(frozen=True)
class Finding:
    asset_id: str
    cve_id: str
    product: str
    installed_version: str
    cvss: float
    kev_listed: bool
    epss_score: float
    exposure_score: int
    business_unit: str

    @property
    def is_critical(self) -> bool:
        return self.cvss >= 9.0


def generate_findings(assets: list[CorporateAsset], catalog: list[CorporateCveRecord]) -> list[Finding]:
    by_product: dict[str, list[CorporateCveRecord]] = {}
    for record in catalog:
        by_product.setdefault(record.product, []).append(record)

    findings: list[Finding] = []
    for asset in assets:
        for product, version in asset.installed_software:
            for record in by_product.get(product, []):
                if version in record.vulnerable_versions:
                    findings.append(
                        Finding(
                            asset_id=asset.asset_id,
                            cve_id=record.cve_id,
                            product=product,
                            installed_version=version,
                            cvss=record.cvss,
                            kev_listed=record.kev_listed,
                            epss_score=record.epss_score,
                            exposure_score=asset.exposure_score,
                            business_unit=asset.business_unit,
                        )
                    )
    return findings


def critical_findings(findings: list[Finding]) -> list[Finding]:
    return [f for f in findings if f.is_critical]
