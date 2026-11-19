"""Canonical views of a text: what it says once its disguises are undone.

An injected instruction is often written so that a person or a pattern does not
see it: split by invisible characters, spelled with look-alike letters, encoded,
or placed in markup a reader never sees. Each view here undoes one of those and
is scanned like the original. A view records how it was derived, whether it
reveals something a reader would not have seen, and, where it can, how its
characters map back to the original text.

Every decoding step is bounded: by depth, by how many payloads are followed, by
how much a decoded payload may expand, and by a deadline the caller passes in.
The helpers avoid patterns that can backtrack across the input.
"""

from __future__ import annotations

import base64
import binascii
import codecs
import html
import json
import re
import time
import unicodedata
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import unquote

#: Decoded payloads followed per text, and how deep an encoding may be nested.
MAX_DECODED = 12
MAX_DECODE_DEPTH = 3
#: A decoded payload longer than this multiple of its source is not followed.
MAX_EXPANSION = 4


@dataclass
class View:
    label: str
    text: str
    #: Category credited when this view shows a signal the earlier views did not.
    evasion: str | None = None
    #: The view undoes a disguise, so a directive found only here was hidden.
    reveals: bool = False
    #: ``offsets[i]`` is the index in the original text of character ``i``;
    #: None when positions cannot be mapped (``label == "raw"`` maps to itself).
    offsets: list[int] | None = None
    #: For a decoded payload, where the encoded form sits in the original.
    source_span: tuple[int, int] | None = None
    chain: tuple[str, ...] = field(default_factory=tuple)


class Budget:
    """A deadline shared by one scan."""

    def __init__(self, seconds: float | None):
        self._deadline = None if seconds is None else time.perf_counter() + seconds
        self.exhausted = False

    def spent(self) -> bool:
        if self._deadline is not None and time.perf_counter() > self._deadline:
            self.exhausted = True
        return self.exhausted


# --------------------------------------------------------------------------- #
# invisible characters                                                        #
# --------------------------------------------------------------------------- #

# Zero-width / invisible characters used to smuggle instructions past humans.
INVISIBLE = re.compile("[​-‏‪-‮⁠-⁤﻿\U000e0000-\U000e007f]")
BIDI_CONTROL = re.compile("[‪-‮⁦-⁩]")
# Invisible in rendering but never meaningful on their own: stripped before
# matching so "ig­nore" or "ign️ore" reads as the word it hides.
FORMAT_NOISE = re.compile("[­︀-️\U000e0100-\U000e01ef]")
_STRIP = re.compile("[​-‏‪-‮⁠-⁤⁦-⁩﻿"
                    "\U000e0000-\U000e007f­︀-️\U000e0100-\U000e01ef]")

_TAG_CHARS = re.compile("[\U000e0020-\U000e007e]")
_VARIATION_RUN = re.compile("[︀-️\U000e0100-\U000e01ef]{8,}")


def decode_tag_characters(text: str) -> str:
    """Map Unicode tag characters (U+E0020..E007E) back to the ASCII they mirror.

    Tag-character "ASCII smuggling" hides a full instruction in characters no
    renderer displays; stripping them (as normalisation does) would hide the
    payload from the pattern scan too.
    """
    return _TAG_CHARS.sub(lambda m: chr(ord(m.group(0)) - 0xE0000), text)


def decode_variation_selectors(text: str) -> list[tuple[str, tuple[int, int]]]:
    """Bytes carried one per variation selector, decoded where they are text.

    The 256 variation selectors can each stand for one byte, so a run of them
    after any visible character carries an arbitrary hidden string. A run that
    decodes to readable UTF-8 is returned with its position.
    """
    out = []
    for match in _VARIATION_RUN.finditer(text):
        data = bytearray()
        for ch in match.group(0):
            cp = ord(ch)
            data.append(cp - 0xFE00 if cp <= 0xFE0F else cp - 0xE0100 + 16)
        try:
            decoded = bytes(data).decode("utf-8")
        except UnicodeDecodeError:
            continue
        if looks_like_text(decoded):
            out.append((decoded, match.span()))
    return out


def normalize(text: str) -> tuple[str, list[int] | None]:
    """NFKC with invisible, bidi and format characters removed.

    Returns the offset map when one exists. It is built character by character,
    which matches whole-string NFKC except where characters compose across
    positions; there the whole-string form is returned without a map.
    """
    if text.isascii():
        return text, None
    stripped = _STRIP.sub("", text)
    whole = unicodedata.normalize("NFKC", stripped)
    if whole == text:
        return text, None
    pieces: list[str] = []
    offsets: list[int] = []
    for index, ch in enumerate(text):
        if _STRIP.match(ch):
            continue
        folded = unicodedata.normalize("NFKC", ch)
        pieces.append(folded)
        offsets.extend([index] * len(folded))
    built = "".join(pieces)
    return (built, offsets) if built == whole else (whole, None)


# --- invisible characters with an ordinary job ------------------------------ #

# Emoji subdivision flags (England, Scotland, Wales, US states) are a black
# flag followed by a short run of tag letters and a cancel tag.
_SUBDIVISION_FLAG = re.compile(
    "\U0001f3f4[\U000e0061-\U000e007a\U000e0030-\U000e0039]{2,7}\U000e007f")
_RTL_LETTER = re.compile("[֐-ࣿיִ-﷿ﹰ-ﻼ]")


def _joins_script(ch: str) -> bool:
    """Scripts where ZWJ/ZWNJ shape words: Arabic, Persian, Syriac, Indic."""
    cp = ord(ch)
    return 0x0600 <= cp <= 0x08FF or 0x0900 <= cp <= 0x0DFF or 0xFB50 <= cp <= 0xFEFC


def _pictographic(ch: str) -> bool:
    cp = ord(ch)
    return (cp >= 0x1F000 or 0x2600 <= cp <= 0x27BF or 0x2190 <= cp <= 0x21FF
            or 0x2B00 <= cp <= 0x2BFF or 0xFE00 <= cp <= 0xFE0F
            or unicodedata.category(ch) == "So")


def without_benign_invisibles(text: str) -> str:
    """Drop invisible characters that are doing their ordinary job.

    A zero-width joiner inside an emoji sequence, a ZWNJ inside a Persian word,
    a byte-order mark at the start of a file, a left-to-right mark in Hebrew or
    Arabic text, and the tag letters of a subdivision flag are how real text is
    written. Only what is left can be hiding something.
    """
    text = _SUBDIVISION_FLAG.sub("", text)
    if text.startswith("﻿"):
        text = text[1:]
    has_rtl = bool(_RTL_LETTER.search(text))
    out: list[str] = []
    for i, ch in enumerate(text):
        if ch in "‌‍" and 0 < i < len(text) - 1:
            before, after = text[i - 1], text[i + 1]
            if ch == "‍" and _pictographic(before) and _pictographic(after):
                continue
            if _joins_script(before) and _joins_script(after):
                continue
        if ch in "‎‏" and has_rtl:
            continue
        out.append(ch)
    return "".join(out)


# --------------------------------------------------------------------------- #
# look-alike letters                                                          #
# --------------------------------------------------------------------------- #

def _load_confusables() -> tuple[dict[str, str], str]:
    path = Path(__file__).resolve().parent / "data" / "confusables_latin.json"
    with path.open(encoding="utf-8") as handle:
        data = json.load(handle)
    return data["map"], data["unicode_version"]


#: Letters of other scripts that render as one Latin letter, derived from the
#: Unicode Security Mechanisms (UTS #39) confusables data; see the data file
#: for its version, source hash and licence (Unicode License v3).
CONFUSABLES, CONFUSABLES_VERSION = _load_confusables()
_WORD = re.compile(r"[^\W\d_]+")
_LATIN_LETTER = re.compile(r"[A-Za-zÀ-ɏ]")


def _is_mixed(word: str) -> bool:
    return (any(ch in CONFUSABLES for ch in word)
            and bool(_LATIN_LETTER.search(word)))


def mixed_script_tokens(text: str) -> list[str]:
    if text.isascii():
        return []
    return [m.group(0) for m in _WORD.finditer(text) if _is_mixed(m.group(0))]


def fold_confusables(text: str) -> str:
    """Fold look-alike letters to Latin, inside mixed-script words only.

    "ignоre" with a Cyrillic o is folded; a sentence of real Russian or
    Greek is left alone, because a word written wholly in one script is not a
    disguise. One character maps to one character, so positions are unchanged.
    """
    if text.isascii():
        return text

    def fold(m: re.Match) -> str:
        word = m.group(0)
        if not _is_mixed(word):
            return word
        return "".join(CONFUSABLES.get(ch, ch) for ch in word)

    return _WORD.sub(fold, text)


# --------------------------------------------------------------------------- #
# spelling disguises                                                          #
# --------------------------------------------------------------------------- #

#: Words an injected instruction is built from. Disguised spellings are undone
#: only when the result is one of these, so ordinary text is left as written.
DIRECTIVE_WORDS = (
    "ignore", "disregard", "forget", "override", "bypass", "instructions",
    "instruction", "previous", "prior", "above", "system", "prompt", "password",
    "secret", "reveal", "developer", "restrictions", "guidelines", "exfiltrate",
    "token", "rules", "pretend", "jailbreak", "unrestricted", "credentials",
    "assistant", "directions", "commands", "obey", "confidential", "print",
    "repeat", "output", "everything",
)
_DIRECTIVE_SET = frozenset(DIRECTIVE_WORDS)
_SPACED_WORDS = tuple(w for w in DIRECTIVE_WORDS if len(w) >= 5)
_SEPARATORS = r"[\s._\-`'*]{0,3}"
#: One pass for every word: at a word start only the alternatives beginning
#: with that letter are tried.
_SPACED = re.compile(
    r"\b(?:" + "|".join(_SEPARATORS.join(map(re.escape, word)) for word in _SPACED_WORDS)
    + r")\b", re.I)
_SEPARATOR_CHARS = re.compile(r"[\s._\-`'*]")

#: Words used to put spaces back into a run of single letters.
_GLUE = ("all", "the", "your", "you", "and", "me", "to", "of", "tell", "show", "now",
         "other", "original", "hidden", "word", "first", "letter", "share", "code", "act",
         "as", "no", "under", "answer", "start", "response", "refuse", "when", "here",
         "are", "new", "my", "any", "that", "this", "say", "give", "what", "is", "in",
         "do", "not", "follow", "only", "instead", "text", "before", "said", "told",
         "been", "have", "were", "was", "reply", "with", "write", "these", "those",
         "them", "it", "on", "for", "from", "must", "will", "should", "please", "then")
_SEGMENT_WORDS = sorted(_DIRECTIVE_SET | set(_GLUE), key=len, reverse=True)
_LETTER_RUN = re.compile(r"(?<![^\W\d_])(?:[^\W\d_][ \t]){3,}[^\W\d_](?![^\W\d_])")
_LINE_RUN = re.compile(r"(?:(?<=\n)|^)(?:[^\n]?\n){6,}[^\n]?(?=\n|$)")

_LEET = {"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s"}
_LEET_TOKEN = re.compile(r"(?<![A-Za-z0-9@$])[A-Za-z0-9@$]{3,}(?![A-Za-z0-9@$])")
_LEET_WORDS = _DIRECTIVE_SET | frozenset(w for w in _GLUE if len(w) >= 3)


def collapse_spaced_directives(text: str) -> str:
    """Rejoin directive words split by spaces or punctuation ("i.g.n.o.r.e")."""
    def join(m: re.Match) -> str:
        found = m.group(0)
        return _SEPARATOR_CHARS.sub("", found).lower() if _SEPARATOR_CHARS.search(found) else found

    return _SPACED.sub(join, text)


def _segment(run: str) -> str:
    """Put spaces back into letters run together, using the directive words.

    Letters that belong to no known word stay together as one word, so a
    single spaced word ("s h a r e") comes back whole.
    """
    lowered = run.lower()
    out: list[str] = []
    unknown: list[str] = []
    i = 0
    while i < len(lowered):
        for word in _SEGMENT_WORDS:
            if len(word) >= 3 and lowered.startswith(word, i):
                if unknown:
                    out.append("".join(unknown))
                    unknown = []
                out.append(word)
                i += len(word)
                break
        else:
            unknown.append(lowered[i])
            i += 1
    if unknown:
        out.append("".join(unknown))
    return " ".join(out)


def rejoin_letter_runs(text: str) -> str:
    """Undo letter-spacing and one-character-per-line layouts."""
    def lines(m: re.Match) -> str:
        return "".join(part if part else " " for part in m.group(0).split("\n"))

    out = _LINE_RUN.sub(lines, text) if text.count("\n") >= 6 else text

    def letters(m: re.Match) -> str:
        return _segment(re.sub(r"[ \t]", "", m.group(0)))

    return _LETTER_RUN.sub(letters, out)


def fold_leetspeak(text: str) -> str:
    """Read digit-for-letter spellings, where the result is a directive word."""
    def fold(m: re.Match) -> str:
        token = m.group(0)
        if token.isalpha() or token.isdigit():
            return token
        plain = "".join(_LEET.get(ch, ch) for ch in token).lower()
        if plain in _LEET_WORDS:
            return plain
        alternate = "".join("l" if ch == "1" else _LEET.get(ch, ch) for ch in token).lower()
        return alternate if alternate in _LEET_WORDS else token

    return _LEET_TOKEN.sub(fold, text) if any(ch in text for ch in "013457@$") else text


def _deletes(word: str) -> set[str]:
    return {word[:i] + word[i + 1:] for i in range(len(word))}


_TYPO_WORDS = tuple(w for w in DIRECTIVE_WORDS if len(w) >= 6) + ("above",)
_TYPO_INDEX: dict[str, str] = {}
for _word in _TYPO_WORDS:
    for _variant in _deletes(_word) | {_word}:
        _TYPO_INDEX.setdefault(_variant, _word)
_ALPHA_TOKEN = re.compile(r"[A-Za-z]{5,14}")
#: First two letters a slipped spelling can start with, when the slip is not a
#: substitution or insertion in those two positions. A cheap screen: most
#: words of a document are dismissed on it.
_TYPO_STARTS = frozenset(start for w in _TYPO_WORDS
                         for start in (w[:2], w[1] + w[0], w[1:3], w[0] + w[2]))
#: The same screen for a letter added or changed at the very start
#: ("xignore", "ugnore") and in second place ("iunstructions", "ixstructions").
_TYPO_SECOND = frozenset(start for w in _TYPO_WORDS for start in (w[:2], w[1:3]))
_TYPO_SKIP = frozenset(pair for w in _TYPO_WORDS
                       for pair in ((w[0], w[1:3]), (w[0], w[2:4])))
#: Real words one edit from a directive word.
_NOT_TYPOS = frozenset({"forgot", "systems", "prompts", "secrets", "reveals", "tokens",
                        "outputs", "repeats", "prints", "bypassed", "override", "overrode",
                        "printed", "prompted", "secrete", "systemd", "revealed", "outputs",
                        "priory", "abode", "adobe", "printer", "sprint", "repeal", "repent",
                        "output", "outpost", "prompter", "promptly"})


def correct_directive_typos(text: str) -> str:
    """Read a directive word with one slipped letter as the word it is.

    One insertion, deletion, substitution or transposition, on words of six or
    more letters, and never an inflection of the word ("ignored" stays).
    """
    def fix(m: re.Match) -> str:
        token = m.group(0)
        lowered = token.lower()
        if (lowered[:2] not in _TYPO_STARTS and lowered[1:3] not in _TYPO_SECOND
                and (lowered[0], lowered[2:4]) not in _TYPO_SKIP):
            return token
        if lowered in _DIRECTIVE_SET or lowered in _NOT_TYPOS:
            return token
        for variant in _deletes(lowered) | {lowered}:
            word = _TYPO_INDEX.get(variant)
            if word is None or abs(len(word) - len(lowered)) > 1:
                continue
            if lowered.startswith(word) or word.startswith(lowered):
                continue                                   # an inflection, not a slip
            if lowered.startswith(word[:-1]):
                continue                                   # "ignoring", "prompted"
            return word
        return token

    return _ALPHA_TOKEN.sub(fix, text)


# --------------------------------------------------------------------------- #
# encodings                                                                   #
# --------------------------------------------------------------------------- #

_BASE64ISH = re.compile(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{24,}={0,2}(?![A-Za-z0-9+/=])")
_HEXISH = re.compile(r"\b(?:[0-9a-fA-F]{2}){12,}\b")
_URL_ENCODED = re.compile(r"(?:%[0-9a-fA-F]{2}){4,}")
_BACKSLASH = re.compile(r"(?:\\u[0-9a-fA-F]{4}|\\x[0-9a-fA-F]{2}){4,}")
_BACKSLASH_ONE = re.compile(r"\\u([0-9a-fA-F]{4})|\\x([0-9a-fA-F]{2})")
_QUOTED_PRINTABLE = re.compile(r"=([0-9A-F]{2})")

_MARK_WORDS = ("ignore", "instruction", "previous", "prompt", "password", "disregard",
               "reveal", "forget", "directive", "system")
_ROT13_MARKS = tuple(codecs.encode(w, "rot13") for w in _MARK_WORDS)
_REVERSED_MARKS = tuple(w[::-1] for w in _MARK_WORDS)


def looks_like_text(s: str) -> bool:
    if len(s) < 8:
        return False
    printable = sum(ch.isprintable() or ch.isspace() for ch in s)
    return printable / max(len(s), 1) > 0.85


def _payloads(text: str) -> list[tuple[str, str, tuple[int, int]]]:
    """``(encoding, decoded text, span)`` for each encoded run that is text."""
    found: list[tuple[str, str, tuple[int, int]]] = []
    for m in _BASE64ISH.finditer(text):
        try:
            decoded = base64.b64decode(m.group(0), validate=True).decode("utf-8")
        except (binascii.Error, UnicodeDecodeError, ValueError):
            continue
        if looks_like_text(decoded):
            found.append(("base64", decoded, m.span()))
    for m in _HEXISH.finditer(text):
        try:
            decoded = bytes.fromhex(m.group(0)).decode("utf-8")
        except (ValueError, UnicodeDecodeError):
            continue
        if looks_like_text(decoded):
            found.append(("hex", decoded, m.span()))
    for m in _URL_ENCODED.finditer(text):
        decoded = unquote(m.group(0))
        if decoded != m.group(0) and looks_like_text(decoded):
            found.append(("url_fragment", decoded, m.span()))
    return found


def decoded_payloads(text: str, budget: Budget) -> list[tuple[tuple[str, ...], str, tuple[int, int]]]:
    """Encoded payloads, followed through nested encodings.

    Returns ``(chain, decoded text, span in text)``; the span is that of the
    outermost encoded run. Bounded by :data:`MAX_DECODED`,
    :data:`MAX_DECODE_DEPTH` and :data:`MAX_EXPANSION`.
    """
    out: list[tuple[tuple[str, ...], str, tuple[int, int]]] = []
    frontier: list[tuple[tuple[str, ...], str, tuple[int, int] | None]] = [((), text, None)]
    for _depth in range(MAX_DECODE_DEPTH):
        following: list[tuple[tuple[str, ...], str, tuple[int, int] | None]] = []
        for chain, current, span in frontier:
            for encoding, decoded, inner in _payloads(current):
                if len(out) >= MAX_DECODED or budget.spent():
                    return out
                if len(decoded) > MAX_EXPANSION * max(inner[1] - inner[0], 1):
                    continue
                item = (chain + (encoding,), decoded, span or inner)
                out.append(item)
                following.append(item)
        frontier = following
        if not frontier:
            break
    return out


def decode_backslash_escapes(text: str) -> str:
    if "\\u" not in text and "\\x" not in text:
        return text

    def run(m: re.Match) -> str:
        return _BACKSLASH_ONE.sub(lambda c: chr(int(c.group(1) or c.group(2), 16)), m.group(0))

    return _BACKSLASH.sub(run, text)


def decode_quoted_printable(text: str) -> str:
    if text.count("=") < 3:
        return text
    hits = _QUOTED_PRINTABLE.findall(text)
    if len(hits) < 3:
        return text
    decoded = _QUOTED_PRINTABLE.sub(
        lambda m: chr(int(m.group(1), 16)) if 0x20 <= int(m.group(1), 16) < 0x7F else m.group(0),
        text.replace("=\r\n", "").replace("=\n", ""))
    return decoded


def rot13_if_marked(text: str) -> str | None:
    lowered = text.lower()
    if any(mark in lowered for mark in _ROT13_MARKS):
        return codecs.encode(text, "rot13")
    return None


def reversed_if_marked(text: str) -> str | None:
    lowered = text.lower()
    if any(mark in lowered for mark in _REVERSED_MARKS):
        return text[::-1]
    return None


# --------------------------------------------------------------------------- #
# markup a reader does not see                                                #
# --------------------------------------------------------------------------- #

_TAG = re.compile(r"<([A-Za-z][A-Za-z0-9]{0,15})\b([^<>]{0,2000})>")
_STYLE_ATTR = re.compile(r"""\bstyle\s*=\s*(?:"([^"]{0,1000})"|'([^']{0,1000})')""", re.I)
_HIDDEN_STYLE = re.compile(
    r"display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0(?![.\d])|"
    r"opacity\s*:\s*0(?![.\d])|"
    r"(?<![-\w])color\s*:\s*(?:white\b|#fff(?:fff)?\b|rgba?\(\s*255\s*,\s*255\s*,\s*255\b)",
    re.I)
_HIDDEN_ATTR = re.compile(r"(?:^|\s)(?:hidden|aria-hidden\s*=\s*['\"]?true)(?=[\s'\"/]|$)", re.I)
_TEXT_ATTR = re.compile(r"""\b(?:alt|title|aria-label)\s*=\s*(?:"([^"]{12,1000})"|'([^']{12,1000})')""",
                        re.I)
_MAX_HIDDEN_SEGMENTS = 40
_HIDDEN_SCAN = 4000


@dataclass
class HiddenSegment:
    kind: str          # "comment" | "hidden_element" | "attribute"
    text: str
    start: int
    end: int


def hidden_segments(text: str) -> list[HiddenSegment]:
    """Text carried in markup that a reader of the rendered page does not see.

    HTML comments, the content of elements hidden by style or attribute, and
    long ``alt``/``title`` values. Found with ``str.find`` and bounded matches,
    so a hostile page costs time in proportion to its length.
    """
    if "<" not in text:
        return []
    out: list[HiddenSegment] = []
    position = 0
    while len(out) < _MAX_HIDDEN_SEGMENTS:
        start = text.find("<!--", position)
        if start < 0:
            break
        end = text.find("-->", start + 4)
        stop = end if end >= 0 else min(len(text), start + 4 + _HIDDEN_SCAN)
        body = text[start + 4:stop]
        if body.strip():
            out.append(HiddenSegment("comment", body, start, stop + (3 if end >= 0 else 0)))
        position = stop + 3
    for m in _TAG.finditer(text):
        if len(out) >= _MAX_HIDDEN_SEGMENTS:
            break
        attrs = m.group(2)
        style = _STYLE_ATTR.search(attrs)
        hidden = bool(style and _HIDDEN_STYLE.search(style.group(1) or style.group(2) or ""))
        hidden = hidden or bool(_HIDDEN_ATTR.search(attrs))
        if hidden:
            close = text.find(f"</{m.group(1)}", m.end(), m.end() + _HIDDEN_SCAN)
            stop = close if close >= 0 else min(len(text), m.end() + _HIDDEN_SCAN)
            body = text[m.end():stop]
            out.append(HiddenSegment("hidden_element", body, m.start(), stop))
        for attr in _TEXT_ATTR.finditer(attrs):
            value = attr.group(1) or attr.group(2)
            out.append(HiddenSegment("attribute", value, m.start(), m.end()))
    return out


# --------------------------------------------------------------------------- #
# assembling the views                                                        #
# --------------------------------------------------------------------------- #

def reading(text: str) -> tuple[str, list[int] | None]:
    """The one reading a classifier is given: what the text says once invisible
    characters, compatibility forms, tag characters and look-alike letters are
    undone. Returns it with the map back to the original, where one exists."""
    tagged = decode_tag_characters(text)
    normalized, offsets = normalize(tagged)
    if tagged != text:
        offsets = None                 # tag decoding keeps length, but be exact or silent
    return fold_confusables(normalized), offsets


#: Readings kept for one text, across every level of decoding.
MAX_VIEWS = 48


def _readings(text: str, *, chain: tuple[str, ...] = (), encoded: bool = False,
              source_span: tuple[int, int] | None = None) -> list[View]:
    """The single-step readings of ``text``: everything except payload decoding.

    ``encoded`` marks text that was itself decoded out of a payload: every
    reading of it is credited to the encoding and counts as revealed.
    """
    prefix = ">".join(f"{c}_decoded" for c in chain)
    evasion = "encoded_payload" if encoded else "encoding_evasion"

    def name(label: str) -> str:
        return f"{prefix}>{label}" if prefix else label

    out: list[View] = []
    if encoded:
        out.append(View(prefix, text, "encoded_payload", True, source_span=source_span,
                        chain=chain))
    else:
        tag_decoded = decode_tag_characters(text)
        if tag_decoded != text:
            out.append(View("tag_decoded", tag_decoded, "encoding_evasion", True))
        for decoded, span in decode_variation_selectors(text):
            out.append(View("variation_selector_decoded", decoded, "encoding_evasion", True,
                            source_span=span, chain=("variation_selectors",)))

    normalized, offsets = normalize(text)
    if encoded:
        offsets = None
    if normalized != text:
        out.append(View(name("normalized"), normalized, evasion, True, offsets,
                        source_span=source_span, chain=chain))

    folded = fold_confusables(normalized)
    if folded != normalized:
        out.append(View(name("confusable_folded"), folded, evasion, True, offsets,
                        source_span=source_span, chain=chain))

    deobfuscated = fold_leetspeak(collapse_spaced_directives(rejoin_letter_runs(folded)))
    if deobfuscated != folded:
        out.append(View(name("deobfuscated"), deobfuscated, evasion, True,
                        source_span=source_span, chain=chain))

    spelled = correct_directive_typos(deobfuscated)
    if spelled != deobfuscated:
        # A slipped letter is a typo, not a disguise: nothing is "revealed"
        # unless the text had to be decoded to get here.
        out.append(View(name("spelling_corrected"), spelled,
                        evasion if encoded else None, encoded,
                        source_span=source_span, chain=chain))

    decoded_html = html.unescape(normalized) if "&" in normalized else normalized
    if decoded_html != normalized:
        out.append(View(name("html_unescaped"), decoded_html, evasion, True,
                        source_span=source_span, chain=chain))

    decoded_url = unquote(normalized) if "%" in normalized else normalized
    if decoded_url != normalized:
        out.append(View(name("url_decoded"), decoded_url, evasion, True,
                        source_span=source_span, chain=chain))

    escaped = decode_backslash_escapes(normalized)
    if escaped != normalized:
        out.append(View(name("escapes_decoded"), escaped, evasion, True,
                        source_span=source_span, chain=chain))

    printable = decode_quoted_printable(normalized)
    if printable != normalized:
        out.append(View(name("quoted_printable_decoded"), printable, evasion, True,
                        source_span=source_span, chain=chain))

    rotated = rot13_if_marked(normalized)
    if rotated is not None:
        out.append(View(name("rot13_decoded"), rotated, "encoded_payload", True,
                        source_span=source_span, chain=chain + ("rot13",)))
    backwards = reversed_if_marked(normalized)
    if backwards is not None:
        out.append(View(name("reversed"), backwards, "encoded_payload", True,
                        source_span=source_span, chain=chain + ("reversed",)))
    return out


def views(text: str, budget: Budget) -> list[View]:
    """Every distinct reading of ``text``, the original first.

    Disguises are stacked in practice (a leetspeak payload inside base64, a
    base64 payload inside a URL-encoded query string), so each decoded payload
    is given the same readings as the text itself, and payloads are looked for
    in each reading of the text, not only in the text as written.
    """
    out = [View("raw", text)]
    level = _readings(text)
    out.extend(level)

    normalized, offsets = normalize(text)
    seen_payloads: set[str] = set()
    # Where an encoded run sits is known only for runs found in the text as
    # written (or its normalised form, through the offset map).
    for host in [View("normalized", normalized, offsets=offsets)] + [
            v for v in level if v.label in ("url_decoded", "html_unescaped",
                                            "escapes_decoded", "quoted_printable_decoded",
                                            "deobfuscated")]:
        if len(out) >= MAX_VIEWS or budget.spent():
            break
        for chain, decoded, span in decoded_payloads(host.text, budget):
            if decoded in seen_payloads:
                continue
            seen_payloads.add(decoded)
            source = None
            if host.label == "normalized":
                if offsets is None and normalized == text:
                    source = span
                elif offsets is not None and span[1] - 1 < len(offsets):
                    source = (offsets[span[0]], offsets[span[1] - 1] + 1)
            out.extend(_readings(decoded, chain=chain, encoded=True, source_span=source))
            if len(out) >= MAX_VIEWS or len(seen_payloads) >= MAX_DECODED:
                break

    # Preserve order while dropping readings that came out identical.
    seen: set[str] = set()
    unique: list[View] = []
    for view in out[:MAX_VIEWS]:
        if view.text and view.text not in seen:
            seen.add(view.text)
            unique.append(view)
    return unique
