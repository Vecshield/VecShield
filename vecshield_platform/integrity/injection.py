"""Prompt-injection scanner for ingested chunks.

The scanner lives in the detection library (:mod:`vecshield.injection`) so the
ingest gate can use it before anything is embedded. This module keeps the
platform's import path working.
"""

from __future__ import annotations

from vecshield.injection import (  # noqa: F401
    PACK_VERSION,
    SUPPORTING,
    InjectionResult,
    scan_text,
)

__all__ = ["scan_text", "InjectionResult", "SUPPORTING", "PACK_VERSION"]
