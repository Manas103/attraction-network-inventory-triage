"""End-to-end and unit tests for the attraction network inventory pipeline.

Fixtures are regenerated once per test session into a temp dir so tests
never depend on committed pcap files, and never mutate data/ (the
fixtures shipped there are for scripts/measure_claims.py and manual runs).
"""
from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from attraction_inventory.capture_gen import generate_baseline_and_drift_captures
from attraction_inventory.cpe_match_exact import match_all_exact
from attraction_inventory.cpe_match_fuzzy import match_all_fuzzy
from attraction_inventory.diagram import build_drawio_xml, build_theory_of_operations
from attraction_inventory.fingerprint import fingerprint_capture
from attraction_inventory.inventory_db import (
    SnapshotAssetRow, compute_drift, connect, ingest_snapshot, mark_issued,
)
from attraction_inventory.roster import build_roster
from attraction_inventory.triage import triage_all


@pytest.fixture(scope="session")
def fixtures(tmp_path_factory):
    data_dir = tmp_path_factory.mktemp("fixtures")
    return generate_baseline_and_drift_captures(data_dir)


@pytest.fixture(scope="session")
def fp_baseline(fixtures):
    return fingerprint_capture(fixtures["baseline_path"])


def test_roster_is_deterministic_and_sums_to_120():
    r1 = build_roster()
    r2 = build_roster()
    assert len(r1) == 120
    assert [a.asset_id for a in r1] == [a.asset_id for a in r2]
    assert [a.mac for a in r1] == [a.mac for a in r2]


def test_roster_undocumented_hosts_are_excluded_from_the_120():
    baseline = build_roster(extra_undocumented=0)
    with_drift = build_roster(extra_undocumented=30)
    assert len(baseline) == 120
    assert len(with_drift) == 150
    undoc = [a for a in with_drift if a.asset_id.startswith("UNDOCUMENTED-")]
    assert len(undoc) == 30


def test_all_120_baseline_assets_recovered_with_zero_misses(fixtures, fp_baseline):
    ground_truth_macs = {a.mac for a in fixtures["baseline_roster"]}
    recovered_macs = {a.mac for a in fp_baseline}
    assert ground_truth_macs - recovered_macs == set()
    assert len(ground_truth_macs & recovered_macs) == 120


def test_every_recovered_asset_has_ip_vendor_model(fp_baseline):
    for a in fp_baseline:
        assert a.ip is not None
        assert a.vendor is not None
        assert a.model is not None


def test_cpe_matchers_agree_on_every_matched_asset(fp_baseline):
    exact = match_all_exact(fp_baseline)
    fuzzy = match_all_fuzzy(fp_baseline)
    compared = 0
    for a in fp_baseline:
        e, f = exact.get(a.mac), fuzzy.get(a.mac)
        if e is None and f is None:
            continue
        compared += 1
        e_id = e.cpe23 if e else None
        f_id = f.cpe23 if f else None
        assert e_id == f_id, f"{a.mac}: exact={e_id} fuzzy={f_id}"
    assert compared > 0


def test_fuzzy_matcher_rejects_an_unrelated_device(fp_baseline):
    """The fuzzy matcher's threshold must actually reject, not rubber-stamp
    everything; construct an asset with tokens that share nothing with the
    dictionary and confirm no match."""
    from attraction_inventory.fingerprint import FingerprintedAsset
    decoy = FingerprintedAsset(mac="00:00:00:00:00:00", vendor="Totally Unrelated Corp",
                                model="Nonexistent Widget 9000")
    from attraction_inventory.cpe_match_fuzzy import match_fuzzy
    assert match_fuzzy(decoy) is None


def test_vendor_locked_assets_get_a_named_iec62443_compensating_control(fixtures, fp_baseline):
    vendor_locked_macs = {a.mac for a in fixtures["baseline_roster"] if a.vendor_locked}
    results = triage_all(fp_baseline, vendor_locked_macs)
    locked = [t for t in results if t.vendor_locked]
    assert len(locked) > 0
    for t in locked:
        assert t.compensating_control is not None
        assert "IEC 62443" in t.compensating_control
        assert "conduit" in t.compensating_control.lower()
        assert "zone" in t.compensating_control.lower()


def test_non_vendor_locked_assets_get_no_compensating_control(fixtures, fp_baseline):
    vendor_locked_macs = {a.mac for a in fixtures["baseline_roster"] if a.vendor_locked}
    results = triage_all(fp_baseline, vendor_locked_macs)
    unlocked = [t for t in results if not t.vendor_locked]
    assert len(unlocked) > 0
    for t in unlocked:
        assert t.compensating_control is None


def test_drift_detection_flags_all_30_seeded_undocumented_hosts(fixtures, tmp_path):
    fp_base = fingerprint_capture(fixtures["baseline_path"])
    fp_drift = fingerprint_capture(fixtures["drift_path"])
    vendor_locked_macs = {a.mac for a in fixtures["baseline_roster"] if a.vendor_locked}

    def to_rows(fp_assets):
        return [SnapshotAssetRow(mac=a.mac, ip=a.ip, vendor=a.vendor, model=a.model, role=a.role,
                                  zone=a.zone, protocol=a.protocol, vendor_locked=a.mac in vendor_locked_macs,
                                  cpe23=None) for a in fp_assets]

    conn = connect(tmp_path / "inv.db")
    base_id = ingest_snapshot(conn, "baseline", to_rows(fp_base), issued=True)
    mark_issued(conn, base_id)
    drift_id = ingest_snapshot(conn, "drift", to_rows(fp_drift), issued=False)
    drift_macs = set(compute_drift(conn, drift_id))
    conn.close()

    seeded = {a.mac for a in fixtures["drift_roster"] if a.asset_id.startswith("UNDOCUMENTED-")}
    assert len(seeded) == 30
    assert seeded <= drift_macs
    assert seeded - drift_macs == set()


def test_drift_is_empty_against_its_own_issued_snapshot(fixtures, tmp_path):
    """A clean re-run against the snapshot that was itself issued must
    report zero drift; this is the false-positive control for drift
    detection."""
    fp_base = fingerprint_capture(fixtures["baseline_path"])
    vendor_locked_macs = {a.mac for a in fixtures["baseline_roster"] if a.vendor_locked}
    rows = [SnapshotAssetRow(mac=a.mac, ip=a.ip, vendor=a.vendor, model=a.model, role=a.role,
                              zone=a.zone, protocol=a.protocol, vendor_locked=a.mac in vendor_locked_macs,
                              cpe23=None) for a in fp_base]
    conn = connect(tmp_path / "inv2.db")
    issued_id = ingest_snapshot(conn, "baseline", rows, issued=True)
    mark_issued(conn, issued_id)
    rerun_id = ingest_snapshot(conn, "baseline-rerun", rows, issued=False)
    drift = compute_drift(conn, rerun_id)
    conn.close()
    assert drift == []


def test_drawio_diagram_has_one_node_per_asset(fixtures, fp_baseline):
    vendor_locked_macs = {a.mac for a in fixtures["baseline_roster"] if a.vendor_locked}
    rows = [SnapshotAssetRow(mac=a.mac, ip=a.ip, vendor=a.vendor, model=a.model, role=a.role,
                              zone=a.zone, protocol=a.protocol, vendor_locked=a.mac in vendor_locked_macs,
                              cpe23=None) for a in fp_baseline]
    xml_text = build_drawio_xml(rows)
    for r in rows:
        assert f'id="n-{r.mac}"' in xml_text


def test_theory_of_operations_totals_match_snapshot_size(fixtures, fp_baseline):
    vendor_locked_macs = {a.mac for a in fixtures["baseline_roster"] if a.vendor_locked}
    rows = [SnapshotAssetRow(mac=a.mac, ip=a.ip, vendor=a.vendor, model=a.model, role=a.role,
                              zone=a.zone, protocol=a.protocol, vendor_locked=a.mac in vendor_locked_macs,
                              cpe23=None) for a in fp_baseline]
    text = build_theory_of_operations(rows, "2026-09-11", "baseline_capture.pcap")
    assert f"Total assets in this snapshot: {len(rows)}." in text
    assert "Zone 1" in text and "Zone 4" in text


def test_no_sockets_in_the_passive_analysis_path():
    """Reference-oracle style structural check: grep the passive-path
    modules for anything that would open a socket or send a packet. This
    is the same check whose output is committed to docs/no_sockets_grep.txt."""
    import re
    root = Path(__file__).resolve().parent.parent / "src" / "attraction_inventory"
    forbidden = re.compile(r"\bsocket\.|\.sendto\(|\.send\(|\bsrp\(|\bsr1\(|\bsr\(|\bsniff\(")
    checked = ["fingerprint.py", "mdns_codec.py", "cpe_match_exact.py", "cpe_match_fuzzy.py", "triage.py"]
    for name in checked:
        text = (root / name).read_text(encoding="utf-8")
        assert not forbidden.search(text), f"{name} contains a live-network call"
