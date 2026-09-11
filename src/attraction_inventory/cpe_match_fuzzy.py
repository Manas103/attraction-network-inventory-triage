"""Matcher B: normalized token-overlap lookup.

A deliberately different code path from cpe_match_exact.py: no hash lookup
on the literal string pair. Instead every candidate CPE entry is scored by
Jaccard token overlap between the asset's normalized (vendor + model) tokens
and the entry's normalized (vendor + product) tokens, and the best-scoring
entry above ACCEPT_THRESHOLD wins. This is intentionally a linear scan, not
an index, so a bug in one matcher's data structure cannot also be a bug in
the other's.
"""
from __future__ import annotations

import re

from .cpe_data import CPE_DICTIONARY, CpeEntry
from .fingerprint import FingerprintedAsset

ACCEPT_THRESHOLD = 0.5

_TOKEN_RE = re.compile(r"[a-z0-9]+")


def _tokenize(*parts: str) -> set[str]:
    text = " ".join(p for p in parts if p)
    return set(_TOKEN_RE.findall(text.lower()))


def _entry_tokens(entry: CpeEntry) -> set[str]:
    return _tokenize(entry.display_vendor, entry.display_product, entry.vendor, entry.product)


_ENTRY_TOKENS = [(entry, _entry_tokens(entry)) for entry in CPE_DICTIONARY]


def _jaccard(a: set[str], b: set[str]) -> float:
    if not a or not b:
        return 0.0
    inter = len(a & b)
    union = len(a | b)
    return inter / union if union else 0.0


def match_fuzzy(asset: FingerprintedAsset) -> CpeEntry | None:
    if not asset.vendor or not asset.model:
        return None
    asset_tokens = _tokenize(asset.vendor, asset.model)
    best_entry: CpeEntry | None = None
    best_score = 0.0
    for entry, entry_tokens in _ENTRY_TOKENS:
        score = _jaccard(asset_tokens, entry_tokens)
        if score > best_score:
            best_score = score
            best_entry = entry
    if best_score >= ACCEPT_THRESHOLD:
        return best_entry
    return None


def match_all_fuzzy(assets: list[FingerprintedAsset]) -> dict[str, CpeEntry | None]:
    return {a.mac: match_fuzzy(a) for a in assets}
