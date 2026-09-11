#!/usr/bin/env python3
"""Regenerate data/baseline_capture.pcap and data/drift_capture.pcap.

Both are synthetic, offline pcap fixtures built with Scapy (see
capture_gen.py); nothing here opens a socket or touches a real device.
Deterministic: re-running this script reproduces byte-identical captures
(fixed seed, fixed packet construction order).

Usage: venv/Scripts/python.exe scripts/generate_fixtures.py
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from attraction_inventory.capture_gen import generate_baseline_and_drift_captures  # noqa: E402

if __name__ == "__main__":
    data_dir = Path(__file__).resolve().parent.parent / "data"
    result = generate_baseline_and_drift_captures(data_dir)
    print(f"baseline: {result['baseline_path']} ({len(result['baseline_roster'])} assets)")
    print(f"drift:    {result['drift_path']} ({len(result['drift_roster'])} assets)")
