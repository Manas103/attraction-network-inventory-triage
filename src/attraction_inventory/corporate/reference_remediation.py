"""An independently coded oracle for build_fix_now_queue's membership
decision, the same two-implementation discipline cpe_match_exact.py and
cpe_match_fuzzy.py already use for CPE matching. remediation.py selects
the top non-KEV findings by sorting; this version never calls sort() or
sorted(): for every non-KEV critical finding it counts how many other
non-KEV critical findings strictly outrank it on the identical written
tie-break (priority score, then CVSS, then asset id, then CVE id) and
includes it only if fewer than the remaining capacity outrank it, a
comparative-rank selection rather than a sort-then-slice one. Both
approaches must select the identical set when ties are broken the same
way; tests/test_corporate_remediation.py diffs the two sets exactly,
not just their sizes.
"""
from __future__ import annotations

from .findings import Finding
from .remediation import KEV_DUE_IN_DAYS, NON_KEV_DUE_IN_DAYS, OWNER_BY_BUSINESS_UNIT, QUEUE_CAPACITY, QueueItem


def _priority_tuple(f: Finding) -> tuple[float, float, str, str]:
    score = f.epss_score * (f.exposure_score / 100)
    return (-score, -f.cvss, f.asset_id, f.cve_id)


def _outranks(a: Finding, b: Finding) -> bool:
    """True if a strictly outranks b on the written tie-break order."""
    return _priority_tuple(a) < _priority_tuple(b)


def build_fix_now_queue_reference(critical: list[Finding]) -> list[QueueItem]:
    kev_items = [f for f in critical if f.kev_listed]
    non_kev_items = [f for f in critical if not f.kev_listed]
    remaining_capacity = max(0, QUEUE_CAPACITY - len(kev_items))

    selected_non_kev = []
    for candidate in non_kev_items:
        outrank_count = 0
        for other in non_kev_items:
            if other is candidate:
                continue
            if _outranks(other, candidate):
                outrank_count += 1
        if outrank_count < remaining_capacity:
            selected_non_kev.append(candidate)

    queue = []
    for finding in kev_items:
        score = finding.epss_score * (finding.exposure_score / 100)
        queue.append(QueueItem(finding=finding, priority_score=score, owner=OWNER_BY_BUSINESS_UNIT[finding.business_unit], due_in_days=KEV_DUE_IN_DAYS))
    for finding in selected_non_kev:
        score = finding.epss_score * (finding.exposure_score / 100)
        queue.append(QueueItem(finding=finding, priority_score=score, owner=OWNER_BY_BUSINESS_UNIT[finding.business_unit], due_in_days=NON_KEV_DUE_IN_DAYS))

    return queue
