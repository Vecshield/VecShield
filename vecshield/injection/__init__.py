"""Detection of instructions planted in text a model will later read.

    from vecshield.injection import scan_text

    result = scan_text(chunk_text)
    result.verdict        # "injection" | "suspicious" | "clean"
    result.rules          # ids of the rules that fired
    result.layers         # which detection layers ran

See :mod:`vecshield.injection.scanner` for what the scanner does and does not
establish.
"""

from __future__ import annotations

from vecshield.injection.rules import (
    LANGUAGES,
    PACK_VERSION,
    REVIEWED_LANGUAGES,
    RULES,
    SUPPORTING,
    UNREVIEWED_LANGUAGES,
    Rule,
)
from vecshield.injection.classifier import (
    CATALOG as CLASSIFIER_CATALOG,
    ClassifierUnavailable,
    OnnxClassifier,
    default_classifier,
)
from vecshield.injection.scanner import (
    LAYERS,
    MAX_SCAN_CHARS,
    THRESHOLD,
    InjectionResult,
    defang,
    scan_surfaces,
    scan_text,
)

__all__ = ["scan_text", "scan_surfaces", "InjectionResult", "Rule", "RULES", "PACK_VERSION", "SUPPORTING",
           "LANGUAGES", "REVIEWED_LANGUAGES", "UNREVIEWED_LANGUAGES", "LAYERS",
           "MAX_SCAN_CHARS", "THRESHOLD", "defang", "OnnxClassifier",
           "ClassifierUnavailable", "CLASSIFIER_CATALOG", "default_classifier"]
