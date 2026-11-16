"""Ranks CVSS-critical findings by CISA KEV membership, FIRST EPSS probability
and exposure context into a fix-now remediation queue, then assigns each
surviving item a named owner and a due date.

The policy, written down once so a reviewer could audit it by hand, the
same reason severity.py's MATRIX_RULES and triage.py's compensating-control
text are both spelled out rather than left implicit:

  1. Every CVSS-critical finding that is CISA-KEV-listed enters the queue
     unconditionally. KEV membership means CISA has evidence of active,
     real-world exploitation; that is not a risk score to be outranked by
     anything else, it is a fix-now fact on its own.
  2. The queue has a fixed capacity (QUEUE_CAPACITY), modeling a real SOC's
     actual weekly fix-now throughput rather than an algorithmically
     derived cutoff. Remaining capacity after step 1 is filled from the
     non-KEV critical findings, ranked by priority_score (FIRST EPSS
     probability weighted by the asset's exposure context), highest first.
  3. A finding that clears neither rule is deprioritized, not discarded; it
     remains in the full critical-findings list, just outside the fix-now
     queue for this cycle.

Owners are assigned by business unit (a fixed, named mapping, not a
model), and due dates are relative-day SLAs: KEV-listed items get the
tightest SLA (CISA's own catalog carries a remediation-due-date
convention for federal agencies; this project borrows the spirit of a
short, non-negotiable window), non-KEV queue items get a longer one.
"""
from __future__ import annotations

from dataclasses import dataclass

from .findings import Finding

QUEUE_CAPACITY = 47
KEV_DUE_IN_DAYS = 7
NON_KEV_DUE_IN_DAYS = 21

OWNER_BY_BUSINESS_UNIT = {
    "Finance": "R. Okonkwo (Finance IT Lead)",
    "Engineering": "S. Patel (Engineering Platform Lead)",
    "Sales": "D. Marchetti (Sales Systems Lead)",
    "HR": "L. Whitfield (HR Systems Lead)",
    "Support": "T. Nakamura (Support Tooling Lead)",
    "Operations": "M. Odom (Operations IT Lead)",
}


def priority_score(finding: Finding) -> float:
    """FIRST EPSS probability weighted by exposure context (0-100 scaled
    to 0-1); never consulted for a KEV-listed finding, which is included
    by rule 1 regardless of this score."""
    return finding.epss_score * (finding.exposure_score / 100)


@dataclass(frozen=True)
class QueueItem:
    finding: Finding
    priority_score: float
    owner: str
    due_in_days: int


def _owner_for(finding: Finding) -> str:
    return OWNER_BY_BUSINESS_UNIT[finding.business_unit]


def build_fix_now_queue(critical: list[Finding]) -> list[QueueItem]:
    kev_items = [f for f in critical if f.kev_listed]
    non_kev_items = [f for f in critical if not f.kev_listed]
    non_kev_ranked = sorted(non_kev_items, key=lambda f: (-priority_score(f), -f.cvss, f.asset_id, f.cve_id))

    queue: list[QueueItem] = []
    for finding in kev_items:
        queue.append(QueueItem(finding=finding, priority_score=priority_score(finding), owner=_owner_for(finding), due_in_days=KEV_DUE_IN_DAYS))

    remaining_capacity = max(0, QUEUE_CAPACITY - len(queue))
    for finding in non_kev_ranked[:remaining_capacity]:
        queue.append(QueueItem(finding=finding, priority_score=priority_score(finding), owner=_owner_for(finding), due_in_days=NON_KEV_DUE_IN_DAYS))

    return queue
