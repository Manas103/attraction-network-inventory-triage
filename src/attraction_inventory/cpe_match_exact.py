"""Matcher A: exact field lookup.

Builds a hash table keyed on the literal (vendor, model) strings as the
fingerprinter reports them, and looks each fingerprinted asset up directly.
O(1) per asset. This is the "fast path" matcher; cpe_match_fuzzy.py is the
independently coded second matcher used to cross-check it (see
scripts/measure_claims.py for the diff).
"""
from __future__ import annotations

from .cpe_data import CPE_DICTIONARY, CpeEntry
from .fingerprint import FingerprintedAsset


def _build_index() -> dict[tuple[str, str], CpeEntry]:
    return {(e.display_vendor, e.display_product): e for e in CPE_DICTIONARY}


_INDEX = _build_index()


def match_exact(asset: FingerprintedAsset) -> CpeEntry | None:
    if not asset.vendor or not asset.model:
        return None
    return _INDEX.get((asset.vendor, asset.model))


def match_all_exact(assets: list[FingerprintedAsset]) -> dict[str, CpeEntry | None]:
    return {a.mac: match_exact(a) for a in assets}
