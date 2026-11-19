"""Build the benchmark dataset from the fetched sources.

    python benchmarks/injection/build.py

Writes ``.cache/_built/dataset.jsonl`` and ``.cache/_built/manifest.json``.
Everything is deterministic: selection and splitting use SHA-256 of stable
keys, never a random generator, so two builds from the same sources are
byte-identical and the manifest's dataset hash identifies what was scored.

Row: ``{id, split, label, family, source, form, text, meta}``

``split``   ``dev`` (rules may be developed against it), ``test`` (reported),
            ``heldout`` (a whole source never read during development)

Second round (2026-11-18): InjecAgent and LLMail-Inject, held out in the first
round, are now split dev/test, and fresh sources take their place as held-out.
Harder constructed families were added: payloads inside structured containers,
stacked obfuscations, a payload split across paragraphs, a payload in a very
long document, and an English payload in a non-English document.
``label``   1 an instruction placed for the model that reads the text, 0 not
``form``    ``prompt`` (a bare short string) or ``document`` (a chunk-shaped text)
"""

from __future__ import annotations

import csv
import hashlib
import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Iterable, Iterator

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[1]))

from benchmarks.injection import agentdojo  # noqa: E402
from benchmarks.injection.mutate import OBFUSCATIONS  # noqa: E402

CACHE = HERE / ".cache"
OUT = CACHE / "_built"

LENGTHS = (500, 2000, 8000)
POSITIONS = ("start", "middle", "end")
NEGATIVE_CHUNK = 2000
#: Share of long-document sources set aside as carriers for embedded payloads.
CARRIER_PERCENT = 25
EMBEDDED_PER_SPLIT = 900
MUTATION_PAYLOADS_PER_SPLIT = 60
PER_SOURCE_NEGATIVE_CAP = 1500
HARD_PAYLOADS_PER_SPLIT = 240
HELDOUT_SAMPLE = 2000
DILUTED_LENGTH = 30_000

#: Two obfuscations applied one after the other (inner first).
STACKS = (("rot13", "base64"), ("reversed", "base64"), ("leetspeak", "html_comment"),
          ("homoglyph_cyrillic", "zero_width_split"), ("base64", "css_hidden"),
          ("unicode_escapes", "html_comment"), ("typos", "letter_spaced"),
          ("fullwidth", "one_char_per_line"), ("leetspeak", "base64"),
          ("base64", "url_query"))
FOREIGN_CARRIERS = ("wikipedia_de", "wikipedia_ru", "wikipedia_zh", "wikipedia_ar")

#: Most BIPIA attack strings are an ordinary request ("What is the capital of
#: Brazil?") with nothing in them that says they are addressed to the model.
#: Some name the answer they want changed ("...in your response"). The two are
#: reported apart, because only the second carries a marker a content scanner
#: could read; the split is made by this pattern, applied to every string.
_NAMES_ANSWER = re.compile(r"\byour\s+(answer|response|reply|output)\b", re.I)


def _h(*parts: object) -> int:
    return int.from_bytes(hashlib.sha256("\x1f".join(map(str, parts)).encode()).digest()[:8], "big")


def _half(*key: object) -> str:
    return "dev" if _h("split", *key) % 2 == 0 else "test"


def _row(split: str, label: int, family: str, source: str, form: str, text: str,
         **meta) -> dict:
    rid = hashlib.sha256(f"{family}\x1f{source}\x1f{text}".encode()).hexdigest()[:16]
    return {"id": rid, "split": split, "label": label, "family": family,
            "source": source, "form": form, "text": text, "meta": meta}


def _parquet(path: Path) -> list[dict]:
    import pyarrow.parquet as pq

    return pq.read_table(path).to_pylist()


_FUNCTION_WORDS = {
    "en": "the and you your to of is that this what with for are not all me my",
    "de": "der die das und ich du sie nicht ist ein eine mit auf deine dein meine den dem zu",
    "fr": "le la les des et tu vous est une un pas tes ton mes dans pour que sur",
    "es": "el la los las y tu tus es una un no mis que para con por del",
    "it": "il la le gli e tu tue tuoi è una un non mie che per con del di",
    "pt": "o a os as e você suas seus é uma um não minhas que para com em do da",
    "ro": "și este un o nu în la cu pentru care tale mele să fără",
}
_FUNCTION_SETS = {lang: frozenset(words.split()) for lang, words in _FUNCTION_WORDS.items()}


def _language(text: str) -> str:
    """Language bucket for reporting. A heuristic, used only to group results."""
    from vecshield.classify.language import detect

    decided = detect(text)
    if decided:
        return decided
    tokens = re.findall(r"[^\W\d_]+", text.lower())
    votes = {lang: sum(t in words for t in tokens) for lang, words in _FUNCTION_SETS.items()}
    best = max(votes, key=votes.get)
    ranked = sorted(votes.values(), reverse=True)
    return best if ranked[0] >= 1 and ranked[0] > ranked[1] else "undecided"


# --------------------------------------------------------------------------- #
# benign documents                                                            #
# --------------------------------------------------------------------------- #

def _paragraphs(text: str) -> list[str]:
    return [p for p in (part.strip("\n") for part in text.split("\n\n")) if p.strip()]


def _chunks(text: str, size: int) -> list[str]:
    """Paragraph-aligned chunks of about ``size`` characters."""
    out, current, length = [], [], 0
    for para in _paragraphs(text):
        while len(para) > size:            # a single oversized paragraph
            if current:
                out.append("\n\n".join(current))
                current, length = [], 0
            out.append(para[:size])
            para = para[size:]
        if length + len(para) > size and current:
            out.append("\n\n".join(current))
            current, length = [], 0
        current.append(para)
        length += len(para) + 2
    if current:
        out.append("\n\n".join(current))
    return [c for c in out if len(c) >= 200]


def _tree_docs(source: str, patterns: tuple[str, ...]) -> Iterator[tuple[str, str]]:
    root = CACHE / source / "tree"
    for pattern in patterns:
        for path in sorted(root.glob(pattern)):
            try:
                text = path.read_text(encoding="utf-8")
            except UnicodeDecodeError:
                continue
            if len(text) >= 400:
                yield str(path.relative_to(root)), text


def _wikipedia_docs() -> Iterator[tuple[str, str, str]]:
    for path in sorted((CACHE / "wikipedia").glob("*.json")):
        lang = path.name.split("-")[0]
        for item in json.loads(path.read_text(encoding="utf-8"))["rows"]:
            row = item["row"]
            if len(row["text"]) >= 400:
                yield lang, f"{lang}:{row['id']}", row["text"]


DOC_SOURCES = {
    "tldr_pages": ("*/pages/**/*.md",),
    "runbooks_openshift": ("*/alerts/**/*.md",),
    "runbooks_prometheus": ("*/content/**/*.md",),
    "django_docs": ("*/docs/**/*.txt",),
    "owasp_cheatsheets": ("*/cheatsheets/*.md",),
    "prompt_guide": ("*/pages/**/*.en.mdx",),
}
CARRIER_SOURCES = ("wikipedia_en", "runbooks_openshift", "django_docs")


def _benign_documents() -> Iterator[tuple[str, str, str, str]]:
    """``(source, language, doc key, text)`` for every benign document."""
    for source, patterns in DOC_SOURCES.items():
        for key, text in _tree_docs(source, patterns):
            yield source, "en", key, text
    for lang, key, text in _wikipedia_docs():
        yield f"wikipedia_{lang}", lang, key, text


# --------------------------------------------------------------------------- #
# attacks                                                                     #
# --------------------------------------------------------------------------- #

def _direct_prompts() -> list[dict]:
    rows = []
    for path in sorted((CACHE / "deepset" / "data").glob("*.parquet")):
        split = "dev" if path.name.startswith("train") else "test"
        for r in _parquet(path):
            rows.append(_row(split, int(r["label"]), "direct_prompt", "deepset", "prompt",
                             r["text"], language=_language(r["text"])))
    for path in sorted((CACHE / "gandalf" / "data").glob("*.parquet")):
        split = "test" if path.name.startswith("test") else "dev"
        for r in _parquet(path):
            rows.append(_row(split, 1, "direct_prompt", "gandalf", "prompt", r["text"],
                             language="en"))
    with (CACHE / "yanismiraoui" / "prompt_injections.csv").open(encoding="utf-8") as handle:
        for r in csv.DictReader(handle):
            text = r["prompt_injections"].strip()
            if text:
                rows.append(_row(_half("yanis", text), 1, "direct_prompt", "yanismiraoui",
                                 "prompt", text, language=_language(text)))
    return rows


def _insert(carrier: str, payload: str, position: str) -> tuple[str, int, int]:
    """Place ``payload`` as its own paragraph. Returns text and payload span."""
    paras = _paragraphs(carrier)
    index = {"start": 0, "middle": len(paras) // 2, "end": len(paras)}[position]
    before = "\n\n".join(paras[:index])
    after = "\n\n".join(paras[index:])
    head = before + "\n\n" if before else ""
    tail = "\n\n" + after if after else ""
    return head + payload + tail, len(head), len(head) + len(payload)


def _carrier_of_length(text: str, size: int) -> str | None:
    """A paragraph-aligned prefix of about ``size`` characters, or None."""
    current, length = [], 0
    for para in _paragraphs(text):
        if length + len(para) > size and current:
            break
        current.append(para[:size])
        length += len(para) + 2
    out = "\n\n".join(current)
    return out if len(out) >= 0.6 * size else None


def _bipia() -> list[dict]:
    rows = []
    base = CACHE / "bipia" / "benchmark"

    def contexts(kind: str, part: str) -> list[str]:
        out = []
        for line in (base / kind / f"{part}.jsonl").read_text(encoding="utf-8").splitlines():
            ctx = json.loads(line)["context"]
            out.append("\n".join(ctx) if isinstance(ctx, list) else str(ctx))
        out.sort(key=lambda c: _h("bipia-ctx", c))
        return out[:50]

    for part, split in (("train", "dev"), ("test", "test")):
        text_ctx = contexts("email", part) + contexts("table", part)
        code_ctx = contexts("code", part)
        for kind, ctxs in (("email", contexts("email", part)), ("table", contexts("table", part)),
                           ("code", code_ctx)):
            for ctx in ctxs:
                rows.append(_row(split, 0, "bipia_clean_context", "bipia", "document", ctx,
                                 context=kind))
        for attack_file, pool, family in ((f"text_attack_{part}.json", text_ctx, "bipia_text"),
                                          (f"code_attack_{part}.json", code_ctx, "bipia_code")):
            attacks = json.loads((base / attack_file).read_text(encoding="utf-8"))
            for category, strings in attacks.items():
                for string in strings:
                    for position in POSITIONS:
                        ctx = pool[_h("bipia", string, position) % len(pool)]
                        text, start, end = _insert(ctx, string, position)
                        rows.append(_row(
                            split, 1, family, "bipia", "document", text, category=category,
                            position=position, payload_span=[start, end],
                            marker=("names_the_answer" if _NAMES_ANSWER.search(string)
                                    else "none")))
    return rows


def _injecagent() -> list[dict]:
    rows = []
    for name in ("dh_base", "ds_base", "dh_enhanced", "ds_enhanced"):
        variant = name.split("_")[1]
        for case in json.loads((CACHE / "injecagent" / "data" / f"test_cases_{name}.json")
                               .read_text(encoding="utf-8")):
            # Split on the attacker's instruction, so the base and enhanced
            # forms of one instruction land on the same side.
            split = _half("injecagent", case.get("Attacker Instruction"))
            rows.append(_row(split, 1, f"injecagent_{variant}", "injecagent", "document",
                             str(case["Tool Response"]), attack_type=case.get("Attack Type")))
    return rows


def _llmail() -> list[dict]:
    rows = []
    data = json.loads((CACHE / "llmail" / "data" / "labelled_unique_submissions_phase2.json")
                      .read_text(encoding="utf-8"))
    attempts = sorted((k for k, v in data.items()
                       if v.get("attack_attempt") == "True" and v.get("reason") == "judge"),
                      key=lambda k: _h("llmail", k))[:6000]
    succeeded = sorted((k for k, v in data.items() if v.get("reason") == "api_triggered"),
                       key=lambda k: _h("llmail", k))
    for text in attempts:
        rows.append(_row(_half("llmail", text), 1, "llmail_attempt", "llmail", "document", text,
                         judge_category=data[text].get("judge_category")))
    for text in succeeded:
        rows.append(_row(_half("llmail", text), 1, "llmail_succeeded", "llmail", "document",
                         text))
    for text in json.loads((CACHE / "llmail" / "data" / "emails_for_fp_tests.json")
                           .read_text(encoding="utf-8")):
        rows.append(_row(_half("llmail", text), 0, "llmail_benign_email", "llmail",
                         "document", text))
    return rows


def _agentdojo() -> list[dict]:
    """AgentDojo's tool-output documents with its goals placed by its templates."""
    import yaml

    root = CACHE / "agentdojo" / "src" / "agentdojo"
    templates: dict[str, str] = {}
    for name in ("baseline_attacks.py", "important_instructions_attacks.py"):
        templates.update(agentdojo.templates(root / "attacks" / name))
    rows = []
    for suite in ("banking", "slack", "travel", "workspace"):
        goals = agentdojo.goals(root / "default_suites" / "v1" / suite / "injection_tasks.py")
        vectors = yaml.safe_load(
            (root / "data" / "suites" / suite / "injection_vectors.yaml").read_text("utf-8"))
        paths = (sorted((root / "data" / "suites" / "workspace" / "include").glob("*.yaml"))
                 if suite == "workspace" else
                 [root / "data" / "suites" / suite / "environment.yaml"])
        docs = []
        for path in paths:
            docs += agentdojo.documents(yaml.safe_load(path.read_text("utf-8")), vectors)
        for doc in docs:
            clean = doc["clean"]
            if len(clean) >= 40:
                rows.append(_row(_half("agentdojo-doc", suite, doc["point"]), 0,
                                 "agentdojo_clean", "agentdojo", "document", clean,
                                 suite=suite))
            for attack, template in sorted(templates.items()):
                for goal in goals:
                    # Goals are split, so a goal seen in dev is never in test.
                    text = doc["render"](agentdojo.render_attack(template, goal))
                    rows.append(_row(_half("agentdojo-goal", goal), 1, f"agentdojo_{attack}",
                                     "agentdojo", "document", text, suite=suite,
                                     point=doc["point"]))
    return rows


def _take(rows: list[dict], n: int) -> list[dict]:
    return sorted(rows, key=lambda r: _h("take", r["id"]))[:n]


def _heldout_round_two() -> list[dict]:
    """Sources first read by this harness in the second round, all held out."""
    rows: list[dict] = []
    for path in sorted((CACHE / "gandalf_summarization" / "data").glob("*.parquet")):
        for r in _parquet(path):
            rows.append(_row("heldout", 1, "summarization_injection", "gandalf_summarization",
                             "document", r["text"]))

    def labelled(source: str, items: list[tuple[str, int, dict]],
                 positive_family: str = "labelled_prompt") -> None:
        positives = [_row("heldout", 1, positive_family, source, "prompt", text, **meta)
                     for text, label, meta in items if label == 1 and text and text.strip()]
        negatives = [_row("heldout", 0, "labelled_prompt", source, "prompt", text, **meta)
                     for text, label, meta in items if label == 0 and text and text.strip()]
        rows.extend(_take(positives, HELDOUT_SAMPLE) + _take(negatives, HELDOUT_SAMPLE))

    items = []
    for name in ("train", "validation", "test"):
        with (CACHE / "slabs" / "data" / f"{name}.csv").open(encoding="utf-8") as handle:
            items += [(r["text"], int(r["label"]), {}) for r in csv.DictReader(handle)]
    labelled("slabs", items)

    items = []
    for path in sorted((CACHE / "wambosec" / "data").glob("*.parquet")):
        items += [(r["prompt"], int(r["label"]),
                   {"goal": r.get("goal"), "length_type": r.get("length_type")})
                  for r in _parquet(path)]
    labelled("wambosec", items)

    items = []
    for name in ("train", "test"):
        for line in (CACHE / "turkish" / "data" / f"{name}.jsonl").read_text("utf-8").splitlines():
            if line.strip():
                r = json.loads(line)
                items.append((r["text"], int(r["label"]), {"language": "tr"}))
    labelled("turkish", items)

    csv.field_size_limit(10 ** 9)
    items = []
    with (CACHE / "spml" / "spml_prompt_injection.csv").open(encoding="utf-8") as handle:
        for r in csv.DictReader(handle):
            if r["Source"]:            # rows taken from Gandalf overlap a dev source
                continue
            items.append((r["User Prompt"], int(r["Prompt injection"]),
                          {"degree": r["Degree"]}))
    labelled("spml", items)

    items = []
    with (CACHE / "jailbreak" / "default" / "jailbreak_dataset_full.csv").open(
            encoding="utf-8") as handle:
        for r in csv.DictReader(handle):
            items.append((r["prompt"], int(r["type"] == "jailbreak"), {}))
    labelled("jailbreak", items, positive_family="jailbreak_prompt")

    for key, text in _tree_docs("cursor_rules", ("*/rules/**/*.mdc",)):
        for chunk in _chunks(text, NEGATIVE_CHUNK)[:6]:
            rows.append(_row("heldout", 0, "agent_rules", "cursor_rules", "document", chunk,
                             doc=key))
    return rows


# --------------------------------------------------------------------------- #
# harder constructed cases                                                    #
# --------------------------------------------------------------------------- #

def _one_line(text: str) -> str:
    return " ".join(text.split())


CONTAINERS = {
    "json_field": lambda p: json.dumps(
        {"id": 4812, "status": "open", "title": "Quarterly access review",
         "notes": p, "priority": "normal"}, ensure_ascii=False, indent=1),
    "csv_cell": lambda p: ("id,customer,comment\n1042,Acme Ltd,\""
                           + _one_line(p).replace('"', '""')
                           + "\"\n1043,Globex,\"Renewal confirmed for the third quarter\""),
    "markdown_table": lambda p: ("| Field | Value |\n|---|---|\n| Owner | Platform team |\n"
                                 "| Notes | " + _one_line(p).replace("|", "/") + " |"),
    "code_comment": lambda p: ("```python\ndef handler(event):\n    # " + _one_line(p)
                               + "\n    return process(event)\n```"),
    "yaml_front_matter": lambda p: ("---\ntitle: Release notes\ndescription: >\n  "
                                    + _one_line(p) + "\ntags: [release]\n---"),
    "email_quote": lambda p: ("On Tuesday, Maria wrote:\n"
                              + "\n".join("> " + line for line in p.splitlines() or [p])),
    "html_alt": lambda p: ('<img src="chart.png" alt="'
                           + _one_line(p).replace('"', "&quot;") + '">'),
    "footnote": lambda p: "[^1]: " + _one_line(p),
}


def _hard_cases(direct: list[dict], carriers: dict, foreign: dict) -> list[dict]:
    rows = []
    for split in ("dev", "test"):
        pool = sorted((r for r in direct if r["split"] == split and r["label"] == 1),
                      key=lambda r: _h("hard", r["id"]))[:HARD_PAYLOADS_PER_SPLIT]
        mid = carriers[(split, 2000)]
        long = carriers[(split, 8000)]
        names = sorted(CONTAINERS)
        for index, payload in enumerate(pool):
            text = payload["text"]
            source, carrier = mid[_h("hard-carrier", payload["id"]) % len(mid)]

            # 1. inside a structured container, in the middle of a document
            kind = names[index % len(names)]
            doc, start, end = _insert(carrier, CONTAINERS[kind](text), "middle")
            rows.append(_row(split, 1, "container_payload", payload["source"], "document", doc,
                             container=kind, carrier=source))

            # 2. split across two paragraphs with ordinary text between
            words = text.split()
            if len(words) >= 6:
                paras = _paragraphs(carrier)
                half = len(paras) // 2
                first, second = " ".join(words[:len(words) // 2]), " ".join(words[len(words) // 2:])
                between = paras[half] if half < len(paras) else "See the appendix for details."
                doc = "\n\n".join(paras[:half] + [first, between, second] + paras[half + 1:])
                rows.append(_row(split, 1, "split_payload", payload["source"], "document", doc,
                                 carrier=source))

            # 3. one payload in a very long document
            pieces, size, k = [], 0, 0
            while size < DILUTED_LENGTH:
                piece = long[(_h("dilute", payload["id"]) + k) % len(long)][1]
                pieces.append(piece)
                size += len(piece)
                k += 1
            position = POSITIONS[index % 3]
            doc, start, end = _insert("\n\n".join(pieces), text, position)
            rows.append(_row(split, 1, "diluted_payload", payload["source"], "document", doc,
                             position=position, payload_span=[start, end],
                             document_length=len(doc)))

            # 4. an English-or-other payload in a document in another language
            pool_foreign = foreign[split]
            source_f, carrier_f = pool_foreign[_h("foreign", payload["id"]) % len(pool_foreign)]
            doc, start, end = _insert(carrier_f, text, "middle")
            rows.append(_row(split, 1, "foreign_carrier_payload", payload["source"], "document",
                             doc, carrier=source_f))
            rows.append(_row(split, 0, "carrier_without_payload", source_f, "document",
                             carrier_f, carrier_length=len(carrier_f)))

        english = sorted((r for r in direct if r["split"] == split and r["source"] == "gandalf"),
                         key=lambda r: _h("mutate", r["id"]))[:MUTATION_PAYLOADS_PER_SPLIT]
        for payload in english:
            for inner, outer in STACKS:
                rows.append(_row(split, 1, "stacked_evasion", "gandalf", "prompt",
                                 OBFUSCATIONS[outer](OBFUSCATIONS[inner](payload["text"])),
                                 obfuscation=f"{inner}+{outer}", payload_id=payload["id"]))
    return rows


def _notinject() -> list[dict]:
    rows = []
    for path in sorted((CACHE / "notinject" / "data").glob("NotInject_*.parquet")):
        level = path.name.split("_")[1].split("-")[0]
        for r in _parquet(path):
            rows.append(_row("heldout", 0, "notinject", "notinject", "prompt", r["prompt"],
                             trigger_words=level, category=r.get("category")))
    return rows


# --------------------------------------------------------------------------- #
# assembly                                                                    #
# --------------------------------------------------------------------------- #

def build() -> list[dict]:
    rows: list[dict] = []
    direct = _direct_prompts()
    rows += direct

    carriers: dict[tuple[str, int], list[tuple[str, str]]] = defaultdict(list)
    foreign: dict[str, list[tuple[str, str]]] = defaultdict(list)
    negatives: dict[tuple[str, str], list[dict]] = defaultdict(list)
    for source, lang, key, text in _benign_documents():
        split = _half("doc", source, key)
        if source in FOREIGN_CARRIERS and _h("foreign-carrier", source, key) % 100 < 15:
            carrier = _carrier_of_length(text, 2000)
            if carrier:
                foreign[split].append((source, carrier))
            continue
        if source in CARRIER_SOURCES and _h("carrier", source, key) % 100 < CARRIER_PERCENT:
            for size in LENGTHS:
                carrier = _carrier_of_length(text, size)
                if carrier:
                    carriers[(split, size)].append((source, carrier))
            continue
        per_doc = 3 if source.startswith("wikipedia") else 12
        for chunk in _chunks(text, NEGATIVE_CHUNK)[:per_doc]:
            negatives[(split, source)].append(
                _row(split, 0, "benign_document", source, "document", chunk, language=lang))
    for (_split, _source), items in sorted(negatives.items()):
        items.sort(key=lambda r: _h("neg", r["id"]))
        rows += items[:PER_SOURCE_NEGATIVE_CAP]

    # Payloads placed in carriers, and the same carriers without them: a pair
    # differs only by the payload, so a difference in verdict is the payload's.
    used_carriers: set[tuple[str, str]] = set()
    for split in ("dev", "test"):
        payloads = sorted((r for r in direct if r["split"] == split and r["label"] == 1),
                          key=lambda r: _h("embed", r["id"]))[:EMBEDDED_PER_SPLIT]
        for index, payload in enumerate(payloads):
            size = LENGTHS[index % 3]
            position = POSITIONS[(index // 3) % 3]
            pool = carriers[(split, size)]
            source, carrier = pool[_h("carrier-pick", payload["id"]) % len(pool)]
            text, start, end = _insert(carrier, payload["text"], position)
            rows.append(_row(split, 1, "embedded_payload", payload["source"], "document", text,
                             carrier=source, carrier_length=size, position=position,
                             payload_span=[start, end],
                             language=payload["meta"].get("language")))
            if (split, carrier) not in used_carriers:
                used_carriers.add((split, carrier))
                rows.append(_row(split, 0, "carrier_without_payload", source, "document",
                                 carrier, carrier_length=size))

    for split in ("dev", "test"):
        english = sorted((r for r in direct if r["split"] == split and r["source"] == "gandalf"),
                         key=lambda r: _h("mutate", r["id"]))[:MUTATION_PAYLOADS_PER_SPLIT]
        for payload in english:
            rows.append(_row(split, 1, "evasion", "gandalf", "prompt", payload["text"],
                             obfuscation="none", payload_id=payload["id"]))
            for name, fn in OBFUSCATIONS.items():
                rows.append(_row(split, 1, "evasion", "gandalf", "prompt", fn(payload["text"]),
                                 obfuscation=name, payload_id=payload["id"]))

    rows += _hard_cases(direct, carriers, foreign)
    rows += _bipia()
    rows += _injecagent()
    rows += _llmail()
    rows += _agentdojo()
    rows += _heldout_round_two()
    rows += _notinject()

    seen: set[str] = set()
    unique = []
    for row in rows:                      # identical text in one family: keep one
        if row["id"] not in seen:
            seen.add(row["id"])
            unique.append(row)
    return unique


def write(rows: Iterable[dict]) -> dict:
    OUT.mkdir(parents=True, exist_ok=True)
    rows = list(rows)
    path = OUT / "dataset.jsonl"
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")
    counts: Counter = Counter((r["split"], r["label"], r["family"], r["source"]) for r in rows)
    manifest = {
        "rows": len(rows),
        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        "by_split_label": {f"{s}/{l}": n for (s, l), n in sorted(
            Counter((r["split"], r["label"]) for r in rows).items())},
        "by_family": [{"split": s, "label": l, "family": f, "source": src, "rows": n}
                      for (s, l, f, src), n in sorted(counts.items())],
    }
    (OUT / "manifest.json").write_text(json.dumps(manifest, indent=1) + "\n")
    return manifest


if __name__ == "__main__":
    manifest = write(build())
    print(json.dumps({k: manifest[k] for k in ("rows", "sha256", "by_split_label")}, indent=1))
