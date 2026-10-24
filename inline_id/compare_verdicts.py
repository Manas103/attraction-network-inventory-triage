#!/usr/bin/env python3
"""Diffs inline_id's verdicts.csv (the C++ engine) against
reference_decoder.py's output (the independent Python oracle), key for
key, for the "matched an independent Python reference decoder on every
verdict" claim. Prints and returns the mismatch count."""
import csv
import sys


def load(path):
    """Keys by an order-independent pair of (ip, port) endpoints: the C++
    and Python implementations each pick their own, differently-ordered
    canonical src/dst assignment for a bidirectional flow (one sorts raw
    network-byte-order integers, the other sorts Python byte strings), so
    comparing on the literal src/dst-labeled columns would flag every
    flow where the two orderings disagree as a false mismatch."""
    rows = {}
    with open(path, newline="") as f:
        for row in csv.DictReader(f):
            a = (row["src_ip"], row["src_port"])
            b = (row["dst_ip"], row["dst_port"])
            key = frozenset([a, b])
            rows[key] = row
    return rows


def main():
    cpp_path, ref_path = sys.argv[1], sys.argv[2]
    cpp = load(cpp_path)
    ref = load(ref_path)

    only_cpp = set(cpp) - set(ref)
    only_ref = set(ref) - set(cpp)
    common = set(cpp) & set(ref)

    mismatches = []
    for key in common:
        a, b = cpp[key], ref[key]
        if (a["identified_protocol"], a["our_decision"]) != (b["identified_protocol"], b["our_decision"]):
            mismatches.append((key, a["identified_protocol"], a["our_decision"],
                                b["identified_protocol"], b["our_decision"]))

    print(f"C++ flows: {len(cpp)}")
    print(f"Python reference flows: {len(ref)}")
    print(f"flows only in C++ output: {len(only_cpp)}")
    print(f"flows only in reference output: {len(only_ref)}")
    print(f"verdict mismatches on common flows: {len(mismatches)} / {len(common)}")
    for m in mismatches[:20]:
        print("  MISMATCH:", m)

    ok = not only_cpp and not only_ref and not mismatches
    print(f"EXACT AGREEMENT: {ok}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
