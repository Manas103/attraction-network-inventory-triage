# Attraction Network Inventory, Vulnerability Triage and As-Built Documentation

A Python pipeline that fingerprints backstage attraction network assets
passively from an offline packet capture, matches each one against a
bundled real NVD CPE/CVE subset with two independently coded matchers,
persists the result in SQLite, detects drift against the last issued
diagram, writes a named IEC 62443 compensating control for every
vendor-locked device, and regenerates a network diagram and a Theory of
Operations document from the inventory rather than hand-drawing either.
Stack: Python 3.12, Scapy, SQLite, draw.io XML. Every number below was
measured on this machine, not targeted.

## Why this exists

This is a small version of the first two things an Attractions Operational
Technology team does to an undocumented backstage network before it can be
defended: find out what is actually plugged in, without touching any of
it, and write down what was found in a form someone can hand to the next
engineer. A network diagram that was drawn once by hand goes stale the
first time someone adds a switch; this project treats the diagram and the
Theory of Operations as generated artifacts of the inventory, not
documents, so they can be regenerated and diffed against reality on
demand.

## Honest framing, up front

- **There is no real attraction, backstage network, or device anywhere in
  this project.** `roster.py` builds a fictional but internally consistent
  120-asset fleet (PLCs, HMIs, safety PLCs, managed switches, engineering
  workstations) across four IEC 62443-style zones, `capture_gen.py`
  constructs and writes real, wire-valid EtherNet/IP, Modbus/TCP, ARP and
  mDNS-style TXT packets for that fleet with Scapy, and the pipeline never
  reads anything else. The vendor and model names are real, currently
  shipping industrial-control-system products, chosen deliberately so the
  CPE/CVE matching stage has something real to match against; the specific
  120-unit network built around them is invented for this project.
- **"Capture alone" is a file read, never a live capture.** `fingerprint.py`
  calls Scapy's `rdpcap()` on a `.pcap` file already on disk and never opens
  a socket, sends a probe, or otherwise talks to a live host anywhere in the
  passive-analysis path; `tests/test_pipeline.py` and
  `docs/no_sockets_grep.txt` both verify this by grepping the analysis
  modules for socket/send/sniff calls and asserting there are none.
- **The CPE dictionary and CVE map are a small offline subset, not the live
  NVD feed.** `cpe_data.py` embeds real CPE identifiers and real CVE records
  pulled from the public NVD CVE API once during development; coverage is
  intentionally partial (some product lines in the fleet, such as Alcorn
  McBride's V4X, have no published NVD CVE and are reported as "no CVE
  present in this project's bundled CPE-to-CVE subset" rather than invented).
- **"Visio export" is draw.io XML, not a `.vsdx` file.** `diagram.py` writes
  a `.drawio` XML diagram that both draw.io and current Visio versions can
  import (File > Open, or the built-in "Open Visio Diagrams" viewer plugin
  for older Visio); no Visio COM automation is available on this headless
  build machine to write the proprietary binary `.vsdx` format directly,
  and that substitution is disclosed here rather than silently claimed as
  native Visio output.
- Machine: 8 physical / 16 logical cores, Windows 11, Python 3.12.10,
  Scapy 2.7.0, pytest 9.1.1, run natively (no WSL2 needed; nothing in this
  pipeline touches a live socket or interface).

## Architecture

```
src/attraction_inventory/
  roster.py               deterministic 120-asset ground-truth fleet (4 IEC 62443-style zones) + 30 seeded undocumented hosts
  mdns_codec.py            hand-rolled DNS-wire-format TXT record encode/decode (see Honest framing in-module docstring)
  capture_gen.py            builds real EtherNet/IP, Modbus/TCP, ARP and mDNS-style packets per asset, writes offline .pcap
  fingerprint.py             passive parser: rdpcap() + ARP/ENIP/Modbus/mDNS dissection, never sends a packet
  cpe_data.py                  bundled real NVD CPE dictionary subset + CVE records (offline snapshot, disclosed partial)
  cpe_match_exact.py       matcher A: O(1) hash lookup on literal (vendor, model)
  cpe_match_fuzzy.py         matcher B: independently coded Jaccard token-overlap scan, cross-checks matcher A
  triage.py                     CVE lookup + named IEC 62443 zone/conduit compensating control for vendor-locked assets
  inventory_db.py            SQLite snapshots, issued-diagram tracking, drift = current MACs minus last issued MACs
  diagram.py                    regenerates a .drawio network diagram and a Theory of Operations markdown doc from SQLite rows
scripts/
  generate_fixtures.py       regenerates data/baseline_capture.pcap and data/drift_capture.pcap
  measure_claims.py            runs the full pipeline end to end, prints and writes docs/measured_claims.json
tests/test_pipeline.py     13 pytest tests: unit, end-to-end, and the no-sockets structural check
```

### Design deep-dives

**Two matchers, deliberately different code paths.** `cpe_match_exact.py`
is a hash lookup on the literal `(vendor, model)` string pair the
fingerprinter reports; `cpe_match_fuzzy.py` never touches that index, it
tokenizes both sides and scores every dictionary entry by Jaccard overlap,
accepting only above a 0.5 threshold. A bug in one matcher's data
structure (a stale index, a copy-paste key typo) cannot silently also be a
bug in the other's, which is what makes agreement between them a real
signal rather than two views of the same bug.

**Drift is defined against the last *issued* snapshot, not the last
snapshot.** `inventory_db.py` only marks a snapshot `issued` when the
pipeline explicitly calls `mark_issued()`, modeling the real distinction
between "an inventory run happened" and "a diagram was handed out and is
now the thing reality is compared against." Two consecutive runs of the
same clean network report zero drift against each other only if the first
one was issued; an un-issued baseline run is not a valid drift reference,
which matches how a real as-built diagram actually gets stale, someone
issues it, then the network moves on without telling it.

**The diagram's topology is derived, not templated per device.**
`diagram.py` never special-cases a vendor or model; every non-infrastructure
asset is wired to a Zone 3 switch round-robin and the Zone 3 switches are
chained into a backbone, from the zone/role fields already in the SQLite
row. Regenerating the diagram from a different inventory (more switches,
a different zone mix) produces a different but still-correct topology with
no code change.

## Validation

Full pytest suite: `docs/test_output.txt`

```
13 passed in 0.74s
```

No-sockets structural check on the passive-analysis modules
(`fingerprint.py`, `mdns_codec.py`, `cpe_match_exact.py`,
`cpe_match_fuzzy.py`, `triage.py`): `docs/no_sockets_grep.txt` (empty grep
match, confirmed by `test_no_sockets_in_the_passive_analysis_path`).

Full measured-claims run: `docs/measure_claims_output.txt`,
`docs/measured_claims.json` (per-asset detail: every matched MAC, every
CPE id compared, every flagged drift MAC).

## Findings

**`build_roster()` was not actually idempotent, despite its own docstring
claiming it was.** The first version kept the per-zone IP-host and MAC
counters as module-level globals, initialized once at import time. A
single call worked fine and the numbers in `scripts/measure_claims.py`
(which calls it exactly twice, once for the baseline roster and once for
the drift roster) were correct. The symptom surfaced in the test suite:
`test_roster_is_deterministic_and_sums_to_120` calls `build_roster()`
twice to compare the two results, and by the time the session-scoped
`fixtures` fixture ran two more calls after that, `pytest` failed with
`ValueError: zone 1 exhausted its /24 host range in this synthetic
scheme`. The wrong hypothesis was a bug in the /24 sizing itself (raise
the 250-host ceiling); the measurement that discriminated was printing the
zone-1 host counter's value at each call boundary, which showed it
climbing by 75 every call and never resetting, four calls in the same
process was enough to walk past 250. Root cause: the counters were shared,
mutable module state, so `build_roster()` was only "deterministic" for the
first call per process, exactly the kind of latent bug that looks clean
until something (a second script, a test suite, a REPL session) calls it
more than once. Fix: the host and MAC counters moved from module globals
to local dictionaries created fresh inside `build_roster()` on every call,
matching the purity the docstring already claimed. `scripts/measure_claims.py`
was re-run after the fix and produced identical numbers to the pre-fix run
(120/120, 95/95, 30/30, 105/105), confirming the bug never actually
corrupted a single-call measurement, only repeated calls in one process.

## Measured results

Machine: 8 physical / 16 logical cores, Windows 11, Python 3.12.10.
Raw output: `docs/measure_claims_output.txt`, full detail in
`docs/measured_claims.json`.

| Metric | Measured | Claimed |
|---|---|---|
| Ground-truth assets recovered from the baseline capture | **120 / 120** (0 misses) | 120 / 120 |
| Fingerprinted assets where the exact and fuzzy CPE matchers agree | **95 / 95** | every match |
| Seeded undocumented hosts flagged as drift from the issued diagram | **30 / 30** | 30 / 30 |
| Vendor-locked assets with a named IEC 62443 zone/conduit compensating control | **105 / 105** | all |
| Network diagram and Theory of Operations regenerated from the inventory | **yes** | yes |
| Passive identification, capture file read only, no live socket | **yes** (structurally verified) | yes |

All six claims were met on the first genuine attempt. 95 of the 120 assets
have a self-reported vendor/model the bundled CPE dictionary covers
(Rockwell, Schneider Electric, Belden/Hirschmann, Alcorn McBride
hardware); the remaining 25 are engineering workstations (Dell, HP) with
no ICS-relevant CPE entry in this project's intentionally partial
dictionary, and both matchers correctly return no match for all 25 rather
than a false one. 105 of the 120 assets are vendor-locked in the ground
truth roster (every PLC, HMI, safety PLC, show controller and managed
switch; only the 15 engineering workstations are not); every one of the
105 receives a compensating control naming its IEC 62443 zone, its
conduit, and either its real CVE ids or an honest "no CVE present in this
project's bundled subset" when none exists.

## Building and running

```
python -m venv venv
venv\Scripts\python.exe -m pip install -r requirements.txt

venv\Scripts\python.exe scripts/generate_fixtures.py   # regenerates data/*.pcap
venv\Scripts\python.exe scripts/measure_claims.py       # full pipeline, writes docs/measured_claims.json
venv\Scripts\python.exe -m pytest -q                       # 13 tests
```

## Sibling comparison

Against the portfolio, nothing else covers OT asset discovery, CPE/CVE
triage or diagram generation. The two nearest cyber-domain repos solve a
different problem: [`cyber-incident-response-exercise-harness`](https://github.com/Manas103/cyber-incident-response-exercise-harness)
models tabletop incident-response exercises on a utility IT estate rather
than passive OT asset discovery, and [`ai-governance-audit-readiness-register`](https://github.com/Manas103/ai-governance-audit-readiness-register)
shares this project's structural idea of withholding a verdict when
evidence is missing (here, "no CVE present" instead of a guessed one) but
in an AI-governance domain with no network, protocol, or asset-inventory
surface at all.

## Limitations

- No real attraction, backstage network, or device was involved anywhere;
  every packet, asset, vendor identity and CVE association is either
  synthetic (the 120-unit fleet and its topology) or a small, disclosed
  offline subset of real public data (the CPE dictionary and CVE records).
- The CPE dictionary covers 8 of the fleet's 11 product lines; the 3
  uncovered lines (both PanelView/Alcorn McBride show-control lines'
  workstation counterparts and the two engineering-workstation vendors)
  correctly produce no match rather than a fabricated one, but that also
  means CVE coverage for this fleet is partial by design, not exhaustive.
- "Visio export" produces draw.io-compatible XML, not a native `.vsdx`
  binary; see Honest framing.
- Drift detection compares MAC presence only; it does not currently detect
  a documented asset's protocol, vendor or model silently changing while
  its MAC address stays the same.
