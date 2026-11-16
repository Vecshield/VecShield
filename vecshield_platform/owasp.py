"""OWASP Top 10 for LLM Applications IDs, per check.

The mapping is data (``compliance/data/owasp_llm_references.json``), verified
against the published editions and carrying its own ``verified_on`` date and a
``source_url`` per entry, so a reviewer can check an ID without reading Python.

Both editions are carried, and both are written with their year, because the
2026 edition renumbered eight of the ten entries. The two VecShield leans on
hardest moved: data and model poisoning from LLM04 to LLM05, and vector and
embedding weaknesses -- the entry this product exists for -- from LLM08 to
LLM09. A bare ``LLM08`` is ambiguous between editions and ``LLM08:2026`` names
a different risk (hidden context exposure) than ``LLM08:2025`` did.

A mapping says a check reports evidence toward an entry. It does not say the
check discharges it, and a check with no entry here is unmapped on purpose:
retention, residency, inventory and erasure answer obligations the Top 10 does
not frame. :func:`for_check` returns None for those, and callers omit the field
rather than emitting an empty one -- an approximate mapping in a report a
customer cites is worse than no mapping.

This module is deliberately a leaf: it reads the JSON by path rather than
through ``compliance.data.load_references`` so that importing it cannot pull in
the compliance package, which imports :mod:`vecshield_platform.coverage` in
turn. Callers that want the file through the usual door can still use
``load_references("owasp_llm")``.
"""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Any, Optional

_DATA = (Path(__file__).resolve().parent / "compliance" / "data"
         / "owasp_llm_references.json")

#: The editions carried, newest last.
EDITIONS = ("2025", "2026")


@lru_cache(maxsize=1)
def _data() -> dict[str, Any]:
    with _DATA.open(encoding="utf-8") as handle:
        return json.load(handle)


@lru_cache(maxsize=1)
def _checks() -> dict[str, dict[str, tuple[str, ...]]]:
    return {check: {edition: tuple(ids) for edition, ids in by_edition.items()}
            for check, by_edition in _data()["checks"].items()}


def for_check(check: str) -> Optional[dict[str, list[str]]]:
    """The OWASP LLM IDs a check reports evidence toward, or None if unmapped.

    ``{"2025": ["LLM08:2025"], "2026": ["LLM09:2026"]}``. A fresh dict each
    call, so a caller may put it straight into a payload it then mutates.
    """
    entry = _checks().get(check)
    if entry is None:
        return None
    return {edition: list(ids) for edition, ids in entry.items()}


def mapped_checks() -> frozenset[str]:
    """Every check name the mapping covers."""
    return frozenset(_checks())


def reference(ref_id: str) -> Optional[dict[str, Any]]:
    """The published entry an ID names (title, edition, source url), or None."""
    for ref in _data()["references"]:
        if ref["id"] == ref_id:
            return dict(ref)
    return None


def verified_on() -> str:
    """The date the mapping's references were last checked against the source."""
    return str(_data()["verified_on"])
