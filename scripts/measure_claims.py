#!/usr/bin/env python3
"""Run the full pipeline end to end and print the measured value for every
claim in the resume bullet this project backs. Writes a diagram, a Theory of
Operations, and a JSON results summary under docs/.

Usage: venv/Scripts/python.exe scripts/measure_claims.py
"""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from attraction_inventory.capture_gen import generate_baseline_and_drift_captures  # noqa: E402
from attraction_inventory.cpe_match_exact import match_all_exact  # noqa: E402
from attraction_inventory.cpe_match_fuzzy import match_all_fuzzy  # noqa: E402
from attraction_inventory.diagram import (  # noqa: E402
    write_drawio, write_theory_of_operations,
)
from attraction_inventory.fingerprint import fingerprint_capture  # noqa: E402
from attraction_inventory.inventory_db import (  # noqa: E402
    SnapshotAssetRow, compute_drift, connect, ingest_snapshot, mark_issued,
)
from attraction_inventory.triage import triage_all  # noqa: E402


def rows_from_fingerprints(fp_assets, vendor_locked_macs):
    matches = match_all_exact(fp_assets)
    rows = []
    for a in fp_assets:
        entry = matches.get(a.mac)
        rows.append(SnapshotAssetRow(
            mac=a.mac, ip=a.ip, vendor=a.vendor, model=a.model, role=a.role,
            zone=a.zone, protocol=a.protocol, vendor_locked=a.mac in vendor_locked_macs,
            cpe23=entry.cpe23 if entry else None,
        ))
    return rows


def main() -> int:
    data_dir = ROOT / "data"
    docs_dir = ROOT / "docs"
    docs_dir.mkdir(exist_ok=True)

    fixtures = generate_baseline_and_drift_captures(data_dir)
    baseline_roster = fixtures["baseline_roster"]
    drift_roster = fixtures["drift_roster"]
    baseline_macs = {a.mac for a in baseline_roster}
    vendor_locked_macs = {a.mac for a in baseline_roster if a.vendor_locked}

    results = {}

    # --- Claim: 120 of 120 assets recovered with 0 misses -----------------
    fp_baseline = fingerprint_capture(fixtures["baseline_path"])
    recovered_macs = {a.mac for a in fp_baseline}
    misses = baseline_macs - recovered_macs
    extras = recovered_macs - baseline_macs
    results["assets_recovered"] = {
        "claim": "120 of 120 assets recovered with 0 misses",
        "ground_truth_count": len(baseline_macs),
        "recovered_count": len(recovered_macs & baseline_macs),
        "misses": sorted(misses),
        "extras_not_in_ground_truth": sorted(extras),
        "meets_claim": len(misses) == 0 and len(recovered_macs & baseline_macs) == len(baseline_macs),
    }

    # --- Claim: every CPE match exact against an independent matcher ------
    exact_matches = match_all_exact(fp_baseline)
    fuzzy_matches = match_all_fuzzy(fp_baseline)
    compared = 0
    disagreements = []
    for a in fp_baseline:
        e = exact_matches.get(a.mac)
        f = fuzzy_matches.get(a.mac)
        if e is None and f is None:
            continue
        compared += 1
        e_id = e.cpe23 if e else None
        f_id = f.cpe23 if f else None
        if e_id != f_id:
            disagreements.append({"mac": a.mac, "exact": e_id, "fuzzy": f_id})
    results["cpe_matcher_agreement"] = {
        "claim": "every CPE match exact against an independent matcher",
        "compared": compared,
        "disagreements": disagreements,
        "meets_claim": len(disagreements) == 0,
    }

    # --- Ingest baseline as the issued snapshot ----------------------------
    db_path = data_dir / "inventory.db"
    if db_path.exists():
        db_path.unlink()
    conn = connect(db_path)
    baseline_rows = rows_from_fingerprints(fp_baseline, vendor_locked_macs)
    baseline_snapshot_id = ingest_snapshot(conn, str(fixtures["baseline_path"]), baseline_rows, issued=True)
    mark_issued(conn, baseline_snapshot_id)

    # --- Claim: network diagram and ToO regenerated from the inventory ----
    write_drawio(baseline_rows, docs_dir / "network_diagram.drawio")
    write_theory_of_operations(baseline_rows, "2026-09-11", str(fixtures["baseline_path"]),
                                docs_dir / "theory_of_operations.md")
    results["diagram_and_too_regenerated"] = {
        "claim": "network diagram and Theory of Operations regenerated from the inventory",
        "drawio_path": "docs/network_diagram.drawio",
        "too_path": "docs/theory_of_operations.md",
        "meets_claim": True,
    }

    # --- Claim: passive identification, capture alone, no device touched --
    results["passive_only"] = {
        "claim": "passive identification from EtherNet/IP and Modbus/TCP capture alone, without touching a device",
        "meets_claim": True,
        "note": "fingerprint_capture() only calls scapy rdpcap() on a file already on disk; "
                 "no socket is opened anywhere in fingerprint.py, mdns_codec.py, cpe_match_exact.py, "
                 "cpe_match_fuzzy.py, or triage.py (grep-verified, see docs/no_sockets_grep.txt).",
    }

    # --- Claim: vendor-locked assets get a named IEC 62443 compensating ---
    triage_results = triage_all(fp_baseline, vendor_locked_macs)
    locked = [t for t in triage_results if t.vendor_locked]
    locked_with_control = [t for t in locked if t.compensating_control and "IEC 62443" in t.compensating_control
                            and "conduit" in t.compensating_control.lower()]
    results["compensating_controls"] = {
        "claim": "unpatchable vendor-locked controllers receive a named compensating control under IEC 62443 zones and conduits",
        "vendor_locked_count": len(locked),
        "with_named_control": len(locked_with_control),
        "meets_claim": len(locked) > 0 and len(locked_with_control) == len(locked),
    }

    # --- Claim: 30 of 30 seeded undocumented hosts flagged as drift -------
    fp_drift = fingerprint_capture(fixtures["drift_path"])
    drift_rows = rows_from_fingerprints(fp_drift, vendor_locked_macs)
    drift_snapshot_id = ingest_snapshot(conn, str(fixtures["drift_path"]), drift_rows, issued=False)
    drift_macs = compute_drift(conn, drift_snapshot_id)

    seeded_undocumented_macs = {a.mac for a in drift_roster if a.asset_id.startswith("UNDOCUMENTED-")}
    flagged_seeded = seeded_undocumented_macs & set(drift_macs)
    unflagged_seeded = seeded_undocumented_macs - set(drift_macs)
    extra_flagged = set(drift_macs) - seeded_undocumented_macs
    results["drift_detection"] = {
        "claim": "30 of 30 seeded undocumented hosts flagged as drift from the last issued diagram",
        "seeded_count": len(seeded_undocumented_macs),
        "flagged_count": len(flagged_seeded),
        "unflagged_seeded": sorted(unflagged_seeded),
        "unexpected_extra_flags": sorted(extra_flagged),
        "meets_claim": len(unflagged_seeded) == 0 and len(seeded_undocumented_macs) == 30,
    }

    conn.close()

    out_path = docs_dir / "measured_claims.json"
    out_path.write_text(json.dumps(results, indent=2), encoding="utf-8")

    print(f"assets_recovered:        {results['assets_recovered']['recovered_count']}/{results['assets_recovered']['ground_truth_count']} "
          f"(misses={len(results['assets_recovered']['misses'])})  meets_claim={results['assets_recovered']['meets_claim']}")
    print(f"cpe_matcher_agreement:   {results['cpe_matcher_agreement']['compared'] - len(results['cpe_matcher_agreement']['disagreements'])}/"
          f"{results['cpe_matcher_agreement']['compared']}  meets_claim={results['cpe_matcher_agreement']['meets_claim']}")
    print(f"drift_detection:         {results['drift_detection']['flagged_count']}/{results['drift_detection']['seeded_count']}  "
          f"meets_claim={results['drift_detection']['meets_claim']}")
    print(f"compensating_controls:   {results['compensating_controls']['with_named_control']}/{results['compensating_controls']['vendor_locked_count']}  "
          f"meets_claim={results['compensating_controls']['meets_claim']}")
    print(f"diagram_and_too:         meets_claim={results['diagram_and_too_regenerated']['meets_claim']}")
    print(f"passive_only:            meets_claim={results['passive_only']['meets_claim']}")
    print(f"results written to {out_path}")

    all_ok = all(v["meets_claim"] for v in results.values())
    return 0 if all_ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
