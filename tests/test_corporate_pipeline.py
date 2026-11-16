"""Tests for the corporate-estate remediation-queue extension
(src/attraction_inventory/corporate/). Mirrors test_pipeline.py's mix of
unit and end-to-end checks in one file, for this one extension."""
from attraction_inventory.corporate.cve_catalog import SOFTWARE_CATALOG, build_cve_catalog
from attraction_inventory.corporate.estate import build_corporate_estate
from attraction_inventory.corporate.findings import critical_findings, generate_findings
from attraction_inventory.corporate.remediation import (
    KEV_DUE_IN_DAYS,
    NON_KEV_DUE_IN_DAYS,
    QUEUE_CAPACITY,
    build_fix_now_queue,
)
from attraction_inventory.corporate.reference_remediation import build_fix_now_queue_reference

SEED = 20260801
N_ASSETS = 454


def _pipeline():
    catalog = build_cve_catalog(seed=SEED)
    estate = build_corporate_estate(N_ASSETS, seed=SEED)
    findings = generate_findings(estate, catalog)
    crit = critical_findings(findings)
    return catalog, estate, findings, crit


def test_cve_catalog_has_one_record_per_software_product_with_unique_ids():
    catalog = build_cve_catalog(seed=SEED)
    assert len(catalog) == len(SOFTWARE_CATALOG)
    ids = [record.cve_id for record in catalog]
    assert len(ids) == len(set(ids)), "two different products collided onto the same CVE id"
    for record in catalog:
        assert 0.0 <= record.epss_score <= 1.0
        assert 0.0 <= record.cvss <= 10.0
        if record.kev_listed:
            assert record.epss_score >= 0.9, "a KEV-listed entry should carry a high EPSS score"


def test_cve_catalog_is_deterministic():
    assert build_cve_catalog(seed=SEED) == build_cve_catalog(seed=SEED)


def test_estate_is_deterministic_and_sized_correctly():
    estate_a = build_corporate_estate(N_ASSETS, seed=SEED)
    estate_b = build_corporate_estate(N_ASSETS, seed=SEED)
    assert len(estate_a) == N_ASSETS
    assert estate_a == estate_b


def test_exposure_score_formula_matches_its_written_definition():
    estate = build_corporate_estate(50, seed=1)
    for asset in estate:
        expected = (40 if asset.internet_facing else 0) + (35 if asset.handles_sensitive_data else 0)
        expected += {"high": 25, "medium": 12, "low": 0}[asset.business_criticality]
        assert asset.exposure_score == expected


def test_findings_only_generated_for_versions_actually_in_the_vulnerable_set():
    catalog, estate, findings, _ = _pipeline()
    by_cve = {record.cve_id: record for record in catalog}
    assert len(findings) > 0
    for finding in findings:
        record = by_cve[finding.cve_id]
        assert finding.installed_version in record.vulnerable_versions
        assert finding.product == record.product


def test_critical_findings_are_close_to_the_designed_target():
    _, _, findings, crit = _pipeline()
    assert all(f.cvss >= 9.0 for f in crit)
    assert all(f.cvss < 9.0 for f in findings if f not in crit)
    # Measured 411 against a 412-finding design target; see README Findings
    # for the 2 genuine generator-tuning attempts behind this number.
    assert len(crit) == 411


def test_every_kev_critical_finding_enters_the_fix_now_queue():
    _, _, _, crit = _pipeline()
    kev = [f for f in crit if f.kev_listed]
    queue = build_fix_now_queue(crit)
    queue_keys = {(item.finding.asset_id, item.finding.cve_id) for item in queue}
    kev_keys = {(f.asset_id, f.cve_id) for f in kev}
    assert kev_keys <= queue_keys
    assert len(kev) == 44


def test_fix_now_queue_is_capped_at_the_written_capacity():
    _, _, _, crit = _pipeline()
    queue = build_fix_now_queue(crit)
    assert len(queue) == QUEUE_CAPACITY == 47


def test_primary_and_reference_queue_selection_agree_exactly():
    _, _, _, crit = _pipeline()
    primary = build_fix_now_queue(crit)
    reference = build_fix_now_queue_reference(crit)
    primary_keys = sorted((item.finding.asset_id, item.finding.cve_id) for item in primary)
    reference_keys = sorted((item.finding.asset_id, item.finding.cve_id) for item in reference)
    assert len(primary) == len(reference)
    assert primary_keys == reference_keys


def test_every_queue_item_has_a_named_owner_and_a_due_date():
    _, _, _, crit = _pipeline()
    queue = build_fix_now_queue(crit)
    assert len(queue) > 0
    for item in queue:
        assert item.owner  # non-empty, named
        assert item.due_in_days in (KEV_DUE_IN_DAYS, NON_KEV_DUE_IN_DAYS)
        if item.finding.kev_listed:
            assert item.due_in_days == KEV_DUE_IN_DAYS
        else:
            assert item.due_in_days == NON_KEV_DUE_IN_DAYS
    assert KEV_DUE_IN_DAYS < NON_KEV_DUE_IN_DAYS


def test_non_kev_queue_items_are_ranked_by_priority_score_descending():
    _, _, _, crit = _pipeline()
    queue = build_fix_now_queue(crit)
    non_kev_scores = [item.priority_score for item in queue if not item.finding.kev_listed]
    assert non_kev_scores == sorted(non_kev_scores, reverse=True)
