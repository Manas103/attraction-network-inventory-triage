# Inline Application Identification and Policy Enforcement Path (extension)

A C++17 inline identifier that reassembles each TCP/UDP flow from an
offline capture and names the real application from payload bytes alone,
never the port, then enforces a policy on the result; a port-only ACL is
measured side by side as the naive baseline it replaces. Stack: C++17,
libpcap, Python 3.12 (capture generator + independent reference decoder).
Every number below was measured on this machine, not targeted.

## Why this exists

This is the PANW-relevant half of `attraction-network-inventory-triage`
the base repo's passive OT fingerprinting never needed: port-independent
identification of enterprise protocols (not industrial ones), an inline
decision path, and a policy that a port-based firewall rule cannot
express. The base repo's Python fingerprinter and capture-generation
machinery are the precedent this extension follows, not a dependency of
it: this extension's capture, decoders and policy are new and separate
from the industrial OT path, sharing only this repo and its conventions.

## Honest framing, up front

- **The 1.2M-packet capture is synthetic and disclosed as such.**
  `capture_gen.py` struct-packs real, checksum-correct Ethernet/IPv4/
  TCP/UDP frames directly (not via Scapy, which measured too slow for
  1.2M packets on this machine; see `pcap_writer.py`) carrying real
  HTTP/1.1, TLS 1.2, DNS, SSH and SMB2 protocol bytes (`protocol_bytes.py`).
  No real network, host or traffic was observed.
- **"Per-flow reassembly" tracks every packet of a flow and treats each
  TCP segment as a candidate protocol-data-unit boundary**, which is true
  for every flow this capture builds (each protocol unit the generator
  writes is its own segment); it is not a generic byte-stream reframer
  (no HTTP Content-Length-based body skipping across segments). See
  Limitations.
- **TLS client fingerprinting is JA3-inspired, not JA3.** `ja3_lite` is
  an FNV-1a 64-bit hash of the ClientHello version, cipher suite list and
  extension types, the same fields JA3 hashes with MD5; it is comparable
  only within this project, not against public JA3 databases.
- Machine: 8 physical / 16 logical cores, WSL2 Ubuntu 22.04.5 (g++ 11.4,
  `-O2 -std=c++17`), libpcap 1.10.1, Python 3.12.10. The benchmark ran
  against a copy of the capture on native WSL2 ext4, not `/mnt/c`
  (`/mnt/c` measured 20-40x slower for this file size).

## Architecture

```
inline_id/
  pcap_writer.py          fast struct-based pcap writer (real checksums, no Scapy)
  protocol_bytes.py        HTTP/TLS/DNS/SSH/SMB2 wire-byte builders
  capture_gen.py            builds the 1.2M-packet capture + 40 seeded evasion flows
  reference_decoder.py     independent Python oracle: its own pcap parser + decoders
  compare_verdicts.py       diffs the C++ engine's verdicts against the oracle's
  src/
    flow_key.hpp             bidirectional flow key + hash
    decoders.hpp/.cpp        HTTP/TLS/DNS/SSH/SMB2 content-based identifiers, JA3-lite
    policy.hpp/.cpp          management-subnet policy + the port-only ACL baseline
    flow_table.hpp/.cpp      per-flow state: SYN-based origin, bounded-budget inspection
    main.cpp                  pcap read loop, throughput + latency instrumentation, reporting
  tests/test_decoders.cpp  hand-rolled main() check suite (26 checks)
  fixtures/scenarios.json  ground truth for the 40 seeded evasion flows (tracked; the
                             1.2M-packet .pcap itself is regenerable and gitignored)
  docs/                     raw benchmark, test and reference-diff output
```

### Design deep-dives

- **Policy, not a signature list.** SMB and SSH are blocked unless the
  flow's real originator (the TCP SYN sender) is in the management
  subnet; HTTP/TLS/DNS are always allowed. A port-only ACL baseline
  (`port_based_acl_decision`) blocks exactly destination ports 445 and 22
  and nothing else, which is what every seeded evasion flow defeats.
- **A bounded per-flow inspection budget** (24 payload segments) keeps
  per-flow cost constant regardless of flow length: the bulk HTTP/TLS
  flows in this capture carry 1,500+ data segments each, and inspecting
  all of them would dominate the throughput measurement for no
  classification benefit once a flow's protocol is settled.
- **Re-checking after an initial match, not trusting it once,** is what
  catches the HTTP-tunneled evasion cases: the flow's `current_protocol`
  updates whenever a later segment decodes to something different than
  what came before, and that change is flagged as `tunneling_detected`.

## Validation

Hand-rolled `main()` check suite (`docs/test_output.txt`):

```
./build/test_decoders
26 passed, 0 failed
```

Independent Python reference decoder, diffed against the C++ engine's
verdicts over all 221,055 flows (`docs/reference_diff_output.txt`):

```
C++ flows: 221055
Python reference flows: 221055
flows only in C++ output: 0
flows only in reference output: 0
verdict mismatches on common flows: 0 / 221055
EXACT AGREEMENT: True
```

## Findings

Three real bugs were found and fixed while building this, each one
changing the measured evasion-catch count:

1. **SMB2 header fields are little-endian on the wire (MS-SMB2 2.2.1);
   the first version of `protocol_bytes.py`'s `smb2_header` packed them
   big-endian** (`struct.pack("!H", ...)`), matching every other protocol
   this project builds but not SMB2's own spec. `src/decoders.cpp`'s
   `try_smb2` (correctly little-endian) could never parse the result,
   so all 10 seeded SMB port-evasion flows silently failed to classify
   (`UNKNOWN`, not `SMB`) until the generator was fixed to pack `<H`/`<I`/`<Q`.
2. **A bare TLS ApplicationData record (type `0x17`) is opaque ciphertext
   by design**, so a record header alone (5 bytes: type, version, length)
   cannot be distinguished from unrelated binary data that happens to
   start with the same byte pattern. The first version of
   `try_tls_server_hello` accepted any type-`0x17` record as TLS
   unconditionally; measured against this capture's uniformly random DNS
   query IDs alone, that produced roughly 1 false TLS classification per
   13,000 non-TLS packets. Fix: TLS is only ever established from a real
   ClientHello/ServerHello handshake message now; ApplicationData is
   never used to (re-)classify a flow.
3. **Flow origin was first inferred from whichever side sent the first
   payload byte, not the real TCP SYN sender.** SSH's own banner exchange
   has the server speak first, so every management-subnet SSH flow was
   silently attributed to the server's IP instead of the client's,
   flipping the policy decision (`BLOCK` instead of `ALLOW`) for 50
   otherwise-legitimate flows. Fix: `FlowTable::on_syn` records the real
   initiator from the bare-SYN packet; `on_payload` only falls back to
   "first payload sender" when no SYN was observed (true for UDP).

A fourth, lower-stakes bug in the capture generator itself (not the
identification engine): the two HTTP-tunneled evasion categories
(SSH-inside-HTTP and SMB-inside-HTTP) originally reused the same `idx`
range, so their 5-tuples collided and one category silently overwrote
the other's flow-table entry. Fixed by giving each its own range.

## Measured results

Machine spec repeated: 8 physical / 16 logical cores, WSL2 Ubuntu
22.04.5, g++ 11.4 `-O2`, libpcap 1.10.1, native ext4 (not `/mnt/c`).
Raw output: `docs/benchmark_output.txt`, `docs/test_output.txt`,
`docs/reference_diff_output.txt`.

| Claim | Measured |
|---|---|
| 1.2M-packet simulated capture | **1,200,000** packets, 221,055 flows |
| **40 of 40 seeded port-evasion and HTTP-tunneled cases caught** | **40 / 40**, each via content identification where the port-only ACL baseline allowed it |
| **1.1 Gbps on one core** | **4.65 Gbps** (157.2 MB processed in 0.27s, single-threaded) |
| **p99 per-flow decision latency under 25 microseconds** | **p99 = 1.93 us** (p50 = 0.03 us, p95 = 0.21 us, max = 7.93 us, over every payload-triggered decision) |
| Matched an independent Python reference decoder on every verdict | **221,055 / 221,055 exact agreement** |

The latency figure measures the `FlowTable::on_payload` call itself
(reassembly bookkeeping plus the decode attempt) in-process; it does not
include pcap I/O, which is read once per packet outside the timed region.

## Building and running

```bash
# 1. Generate the capture (regenerates fixtures/enterprise_capture.pcap
#    and the tracked fixtures/scenarios.json ground truth)
python3 capture_gen.py

# 2. Build and run the hand-rolled test suite
make test

# 3. Build and run the engine (copy the capture to a native filesystem
#    first if running under WSL2; /mnt/c measured far slower for this
#    file size)
make all
./build/inline_id fixtures/enterprise_capture.pcap fixtures/verdicts.csv docs/benchmark_output.txt

# 4. Independent oracle + diff
python3 reference_decoder.py fixtures/enterprise_capture.pcap fixtures/reference_verdicts.csv
python3 compare_verdicts.py fixtures/verdicts.csv fixtures/reference_verdicts.csv
```

## Limitations

- The capture is entirely synthetic; no real network traffic was
  observed. See Honest framing above.
- Reassembly treats each TCP segment as one protocol-data-unit boundary
  rather than reframing a generic byte stream (no HTTP Content-Length
  body skipping across segments); every flow this capture builds
  satisfies that assumption by construction, but a capture where a
  single protocol message spans multiple segments would not be decoded
  correctly by this extension.
- The per-flow inspection budget (24 payload segments) means a flow that
  changes protocol after its first 24 inspected segments would not be
  flagged as tunneling; none of the seeded evasion flows need more than
  about 8.
- TLS identification relies on the ClientHello/ServerHello handshake
  only, never ApplicationData (see Findings #2); a flow whose capture
  starts mid-session, after the handshake, is not identified as TLS by
  this extension.
- `ja3_lite` is this project's own fingerprint, not real JA3; see Honest
  framing.
