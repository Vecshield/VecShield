# Plan: a layered prompt-injection detection engine

Status: Phases 0 to 3 are implemented (2026-11-18); Phases 4 to 7 are not.
Section 13 records what was built, where it departs from the plan below, and
the decisions taken. The measured results are in
[`docs/library/benchmarks/injection.md`](../library/benchmarks/injection.md).
Sections 1 to 12 are the plan as it was written before the work, kept for the
reasoning; where they say "today" they describe the scanner before it.

This plan covers the scanner in `vecshield_platform/integrity/injection.py`:
what it does today, what current research and open-source tooling say about
detecting injected instructions in retrievable content, which of that tooling
can be used under this project's Apache-2.0 licence, and a phased design that
fits the engine's existing rules (coverage is stated, unmeasured is not a pass,
data stays in the customer's environment).

---

## 1. Summary

The scanner is a well-built signature engine: 40 weighted patterns in
nine pattern categories (plus two evasion categories), a supporting-signal rule that keeps runbooks quiet, and a
normalisation pass (NFKC, invisible and bidi characters, Unicode tag decoding,
look-alike folding, base64/hex/URL decoding). On its own corpus it scores
precision 1.00 and recall 1.00.

That score does not describe real-world recall, and the corpus manifest says so
("injection recall on this corpus is an upper bound, not an estimate"). A
29-case probe written for this plan, using attack styles the patterns were not
written for, was detected 3 times out of 29 (section 2.2). The misses are not
tuning problems. They are the limits of signatures: paraphrase, other
languages, encodings outside the three handled, and anything past character
5,000 of a surface.

The plan is to keep the signature layer as the precise, explainable base and
add what the research supports around it:

1. **Measure first**, on external data in document form, at a low false-positive
   rate (Phase 0).
2. **Close the cheap, certain gaps** in canonicalisation and coverage (Phase 1).
3. **Turn the rules into data**, with per-rule calibration, more languages and a
   use-versus-mention control (Phase 2).
4. **Move the scanner into the library** so the ingest gate can use it (Phase 3).
5. **Add a semantic-similarity layer** with no heavy runtime (Phase 4).
6. **Train and ship our own small classifier**, document-shaped and
   over-defence-aware, as a hash-pinned optional model (Phase 5).
7. **Fuse with the corpus-level integrity signals** the platform already
   computes, and report retrieval exposure (Phase 6).
8. **Optionally** add a judge on the operator's own model endpoint (Phase 7).

No existing open-source detector is recommended as a bundled dependency. The
reasons are in section 4: the best-known ones are archived, English-only,
licence-encumbered, need `trust_remote_code`, or were trained on short prompts
and transfer poorly to documents.

One limit should be stated up front and kept in the docs: published adaptive
attacks defeat every detector that has been tested against them, including
detection-style defences ([Nasr et al. 2025](https://arxiv.org/abs/2510.09023)).
This engine raises the cost of poisoning a store and catches commodity and
mass-inserted payloads. It is not a security boundary, and the existing
remediation text ("treat retrieved context as untrusted data") stays true.

---

## 2. Where the engine is today

### 2.1 What exists

| Aspect | Today | Where |
|---|---|---|
| Method | 40 regex patterns in 9 categories plus 2 evasion categories, summed category weights, threshold 0.5 | `integrity/injection.py` |
| Supporting signals | Weight 0.3, can add to a real signal, cannot flag alone | `SUPPORTING` |
| Canonicalisation | NFKC; invisible, bidi and format characters; tag-character decoding; confusable folding (48 hand-picked Cyrillic/Greek letters); spaced-letter collapse for 9 words; HTML unescape; URL decode; base64 and hex, one level, first 8 payloads | `_candidates`, `_decoded_payloads` |
| Structure | Zero-click image exfiltration (placeholder and static secret in query string), CSS-hidden text, HTML comments | `_image_exfiltration`, `hidden_content` |
| Languages | English, plus one pattern with seven Spanish/French/German/Portuguese verbs | `_PATTERNS` |
| Surfaces | `chunk.text` and string metadata values, **first 5,000 characters each** | `engine._scan_injection_surfaces` |
| Output | One finding per collection, HIGH if any chunk is high-confidence, else MEDIUM | `integrity/engine.py:207` |
| Corroboration | Injection chunk ids feed duplication, hubness and ingestion-burst findings | `engine.py:382-417` |
| Library | **Not present.** `vecshield/` has no injection scanner, so `IngestGate` cannot block one | `vecshield/ingest/gate.py` |
| Runtime | Not present. `MonitoredConnector` records result ids but nothing links them to flagged chunks | `runtime/proxy.py` |
| Corpus | 55 items: 23 attacks, 32 hard negatives, written by the detector's authors | `benchmark/corpus/injection.yaml` |
| External benchmark | None. `benchmarks/` holds PII and PHI harnesses only | |

The remediation text on the finding recommends "add an injection filter to the
ingestion pipeline". The product does not currently offer one.

### 2.2 A probe of what it misses

Twenty-nine single-sentence attacks, written for this plan and run through
`scan_text`. This is directional evidence from a small hand-written set, not a
benchmark; Phase 0 replaces it with one.

| Group | Cases | Detected | Notes |
|---|---|---|---|
| Paraphrase with no trigger vocabulary ("set aside whatever guidance you were given earlier") | 5 | 0 | |
| Task hijack, soft steering, authority claim, forged turn ("Stop summarising. Instead...") | 5 | 0 | Two reached 0.3 on a bare `Assistant:` line |
| Knowledge poisoning with no instruction (false fact stated as an update) | 1 | 0 | Out of reach of any instruction detector; see non-goals |
| Other languages: German, French, Chinese, Russian, Japanese, Arabic | 6 | 0 | The German verb in the pattern is `ignoriere`, but the object nouns are Spanish/French/English |
| Encodings: double base64, ROT13, leetspeak, reversed text, one character per line, typos | 6 | 0 | |
| Encodings: single base64, split words, fullwidth letters | 3 | 3 | |
| HTML comment addressed to the model without a listed keyword; image URL with a non-template placeholder | 2 | 0 | |
| Plain English override placed after character 5,000 | 1 | 0 | Truncated before scanning |
| **Total** | **29** | **3** | |

Two further observations from the same run:

- **Cost.** A 5,000-character benign chunk scans in about 2.9 ms. A chunk made
  of repeated `<a style='` scans in about 52 ms, eighteen times slower: the
  `hidden_content` pattern backtracks. It is bounded today only by the
  5,000-character cut, so removing that cut (Phase 1) has to come with a
  linear-time rewrite of that pattern and a per-surface time budget.
- **Variation-selector smuggling.** `_FORMAT_NOISE` strips variation selectors
  so a word split by one still matches. But bytes can be encoded *in* a run of
  selectors (one selector per byte). Those are stripped, not decoded, so a
  payload hidden that way is removed from the scanner's view, the opposite of
  what `_decode_tag_characters` does for tag characters.

---

## 3. What research and tooling say

Sources are listed in section 12. Items marked † were read in this session;
the rest are from the published literature as I know it and should be
re-checked before being cited in user-facing docs.

| # | Finding | Source | What it means here |
|---|---|---|---|
| 1 | Detector rankings on public benchmarks do not transfer. The top detector on BIPIA caught 2% of AgentDojo injections at 1% FPR. Input *form* explains much of it: models trained on short prompts miss the same strings inside tool outputs. False-positive rates ranged from 0 to over 90%. | † Liu 2026, "Passing the Test You Trained On" | Evaluate on document chunks with payloads embedded, never on bare prompts. Report recall at a fixed low FPR. Never train on a set we report on. |
| 2 | Guard models lean on trigger words. On 339 benign sentences containing words like "ignore", existing guards including ProtectAI v2 scored under 60%. | † InjecGuard / PIGuard, ACL 2025 | A regex engine has the same bias by construction. NotInject becomes a standing false-positive gate. Over-defence mitigation goes into training. |
| 3 | Character injection (emoji and tag smuggling, homoglyphs, digit substitution) bypassed six production detectors, up to 100% in some settings, because the classifier's tokenizer never sees the hidden text. | † Hackett et al. 2025 | Our canonicaliser already undoes most of these. Running it *before* any model is a real advantage and must stay the first stage. |
| 4 | Adaptive attackers (gradient, RL, search, humans) pushed attack success above 90% against 12 published defences that had reported near zero. | † Nasr, Carlini, Tramèr et al. 2025 | Do not claim robustness. Keep a frozen adaptive red-team set, and describe the engine as cost-raising. |
| 5 | Poisoned passages built to be retrieved show measurable artefacts: unusually high query similarity, low masked-token probability on key tokens, dense clusters, linguistic irregularity. Reported filters remove about 90% of poisoned text while keeping about 95% of benign. | † GMTP (ACL Findings 2025); † RAGuard 2025; TrustRAG | The platform already computes hubness, duplication and embedding anomaly. Corpus-level signals are a second, independent line of evidence that content-only tools lack. |
| 6 | Five crafted passages per target question in a corpus of millions are enough to steer answers. Those passages need not contain any instruction. | PoisonedRAG (USENIX Security 2025) | Misinformation without an instruction is not detectable as injection. It is handled by provenance, supersession and hubness, and stated as a non-goal of this scanner. |
| 7 | Multi-scanner designs (signatures + vector similarity to known attacks + a transformer + canaries) are the common open-source architecture. | † Vigil; Rebuff; LLM Guard | The layering is sound. The implementations are unmaintained (section 4), so we take the design and not the code. |
| 8 | "Known-answer" detection: ask a model to repeat a secret while reading the suspect text, and flag when the secret is missing. | DataSentinel (IEEE S&P 2025) | A cheap, structured judge for the ambiguous band. It appears among the defences bypassed in (4), so it is optional and never the only layer. |
| 9 | Marking retrieved text as data (delimiting, datamarking, encoding) reduces attack success at the application. | Spotlighting (Microsoft 2024) | Outside the scanner, but it belongs in the remediation guidance. |

---

## 4. Licence and safety review

Checked on 2026-11-18 against the GitHub and Hugging Face APIs, PyPI metadata
and the licence files themselves. "Reference" means read it for ideas, do not
depend on it.

### 4.1 Detection tools

| Project | Licence | State | Decision | Why |
|---|---|---|---|---|
| LLM Guard (Protect AI) | MIT | **Archived** 2026-07 | Reference | Unmaintained. Its prompt-injection scanner is a wrapper over the model below. |
| Rebuff | Apache-2.0 | **Archived** 2024-08 | Reference | Design source for the similarity layer and canaries. |
| Vigil | Apache-2.0 | Last push 2024-01, alpha | Reference | Design source for layering. Its bundled embeddings were built with a proprietary embedding API. |
| NeMo Guardrails | Apache-2.0 | Active | Reference | A rails framework for applications; `injection_detection` and `jailbreak_detection` modules are worth reading for heuristics. Wrong shape for a corpus scanner. |
| LlamaFirewall | MIT (code) | Active | Reference | Code is MIT; the model it runs is not (below). |
| garak | Apache-2.0 | Active | **Use, dev-only** | Probe modules (`latentinjection`, `encoding`, `smuggling`, `badchars`, `web_injection`, `promptinject`) are generators for the obfuscation and embedded-payload test sets. Never a runtime dependency. |

### 4.2 Detector models

| Model | Licence | Gated | Loads without custom code | Decision | Why |
|---|---|---|---|---|---|
| `protectai/deberta-v3-base-prompt-injection-v2` | Apache-2.0 | No | Yes (safetensors, ONNX) | Baseline in the bake-off; not a default | Archived. English only. Model card says it does not detect jailbreaks. Under 60% on NotInject. Trained on prompts, not documents. |
| `meta-llama/Llama-Prompt-Guard-2-86M` / `-22M` | Llama 4 Community License | Manual (name, DOB, organisation) | Yes | **Do not bundle or default.** Bring-your-own only | Requires passing on the agreement, "Built with Llama" attribution, an acceptable-use policy, and a naming rule for derived models. Not compatible with shipping inside an Apache-2.0 distribution without changing what users agree to. 512-token window. |
| `leolee99/PIGuard` | MIT | No | **No** (`trust_remote_code=True`) | **Reject as a dependency**; use its method and NotInject | Loading executes repository code. English only. |
| `deepset/deberta-v3-base-injection` | MIT | No | Yes | Baseline only | Small 2023 training set; known high false-positive rate. |
| `qualifire/prompt-injection-sentinel` | "other" | Auto | Yes | Reject | Non-standard licence. |
| `testsavantai/prompt-injection-defender-*` | none declared | No | Yes | Reject | No licence is no permission. |

### 4.3 Base models and runtime, for our own classifier

| Component | Licence | Notes |
|---|---|---|
| `jhu-clsp/mmBERT-small` / `-base` | MIT | Multilingual ModernBERT. Preferred candidate. Repository ships `.bin` weights: load only in the training environment with `weights_only=True`. |
| `microsoft/mdeberta-v3-base` | MIT | Multilingual fallback candidate. Same `.bin` caveat. |
| `answerdotai/ModernBERT-base` | Apache-2.0 | English candidate; safetensors available. |
| `minishlab/potion-base-8M`, `potion-multilingual-128M` (model2vec) | MIT | Static embeddings, numpy only, no torch. Candidate for the similarity layer. |
| `intfloat/multilingual-e5-small` | MIT | ONNX available. Heavier candidate for the similarity layer. |
| `google/embeddinggemma-300m` | Gemma | Reject: use-restricted licence, manual gate. |
| onnxruntime | MIT | Inference without PyTorch. |
| tokenizers | Apache-2.0 | |
| google-re2 (optional) | BSD-3-Clause | Linear-time regex, if the stdlib patterns cannot be made safe. |

### 4.4 Datasets

| Dataset | Licence | Use | Notes |
|---|---|---|---|
| BIPIA (Microsoft) | MIT (LICENSE file; repo archived) | Eval | Indirect attacks in email, table, code, web and summarisation contexts. Web QA and summarisation contexts must be fetched from their sources under their own terms; skip those two or fetch at run time. |
| LLMail-Inject (Microsoft) | MIT | Eval, and a held-out slice for the adaptive set | Real submissions from a public challenge against an email assistant with defences in place. |
| InjecAgent | MIT | Eval | Tool-output injections. |
| AgentDojo | MIT | Eval | Injection payloads and task suite. |
| Open-Prompt-Injection | MIT | Eval and training | Attack strategies (naive, escape, context-ignoring, fake completion, combined). |
| `leolee99/NotInject` | MIT | **False-positive gate** | 339 benign sentences with trigger words. Never trained on. |
| `deepset/prompt-injections` | Apache-2.0 | Training | Includes German. |
| HackAPrompt | MIT (auto-gated) | Training | Human competition data. |
| Lakera `gandalf_ignore_instructions`, `mosscap_prompt_injection` | MIT | Training | Direct, short-prompt form; needs embedding into documents. |
| SPML | MIT | Training | |
| PoisonedRAG | MIT | Eval, non-goal measurement | Confirms and quantifies what the scanner should *not* be expected to catch. |
| PINT (Lakera) | MIT repo, **archived 2026-04**; dataset private | Not usable | Cannot be run without Lakera. |
| `xTRam1/safe-guard-prompt-injection`, `JasperLS/prompt-injections` | none declared | **Do not use** | |
| `allenai/wildjailbreak` | ODC-BY, gated | Do not use | Jailbreaks, not injection; attribution and gate overhead for little gain. |
| MS MARCO | Non-commercial terms | **Do not use** for benign chunks | |

Benign document chunks for negatives come from sources fetched at benchmark
time and not redistributed: Wikipedia and Stack Exchange dumps (CC BY-SA),
documentation sets under CC BY, Apache-2.0 or MIT, and READMEs from permissively
licensed repositories. The manifest records source, licence and hash for each.

**Rules that follow from this table**

- Nothing gated, unlicensed or licence-"other" enters training data or the
  repository.
- Third-party datasets are downloaded by pinned revision and hash when the
  benchmark runs. Only small MIT or Apache-2.0 sets may be vendored, each with a
  NOTICE entry.
- A released model's card lists every training source and its licence. Share-
  alike text (CC BY-SA) is used for evaluation negatives only, never for
  training, so no share-alike question attaches to the weights.
- CI checks the licence of every new runtime dependency against an allow-list
  (Apache-2.0, MIT, BSD, PSF, Unicode).

---

## 5. Design principles and non-goals

**Principles**

1. **Canonicalise once, then every layer reads the same views.** Signatures,
   similarity and the classifier all run on the output of the canonicaliser.
2. **Each layer is optional except the first, and coverage says which ran.** A
   clean result from the signature layer alone reads as "signature layer only;
   paraphrased and non-English instructions are not detected", in the same way
   NER absence is reported today.
3. **Low false-positive rate is the operating constraint.** A store of one
   million chunks at 1% FPR produces 10,000 false flags. Gates are set on recall
   at FPR ≤ 0.1% on document-shaped negatives.
4. **Evidence stays explainable.** Every flag names a rule id, an exemplar id or
   a model version and score, and a character span where one exists.
5. **Nothing leaves the host.** All default layers run locally with no network
   access at scan time.
6. **The library never imports the platform.** Content-only layers live in
   `vecshield/`; corpus-level fusion lives in `vecshield_platform/`.
7. **Irreversible actions wait for calibration.** Quarantine proposals keep
   requiring a `likely` class, earned per rule or per model threshold.

**Non-goals**

- *Deciding whether a passage is true.* Knowledge poisoning without an
  instruction is reported through provenance, supersession, duplication and
  hubness, not by this scanner. The docs will say so.
- *Jailbreak detection for user prompts.* The subject is stored, retrievable
  content. Direct user-prompt screening is an application guardrail.
- *Robustness to an attacker who optimises against this exact engine.*
- *Images, audio and PDFs' hidden layers.* The scanner sees the text and
  metadata the connector returns.

---

## 6. Target architecture

```
chunk.text, metadata values
        │
        ▼
┌─────────────────────────────────────────────────────────────────┐
│ L0  Canonicaliser            vecshield/injection/canonical.py   │
│     views: raw · normalised · folded · decoded(n) · visible ·   │
│            hidden · per-window                                  │
│     budget: time, depth, expansion ratio                        │
└─────────────────────────────────────────────────────────────────┘
        │ views + offset maps
        ├──────────────► L1  Signature rules (data, per-rule class)     always
        ├──────────────► L2  Semantic similarity to attack exemplars    extra: injection-sim
        └──────────────► L3  Classifier (ONNX, hash-pinned)             extra: injection-ml
                                   │
                                   ▼
                    Fusion: calibrated score, verdict, spans,
                    layers_run, counter-signals (use vs mention)
                                   │
        library boundary ──────────┼──────────────────────────────────
                                   ▼
        L4  Corpus-level evidence (platform): hubness, duplication,
            ingestion burst, embedding anomaly, provenance,
            retrieval exposure from the runtime monitor
                                   │
                                   ▼
        L5  Optional judge on the operator's own endpoint (ambiguous band)
```

Output contract, replacing `InjectionResult` compatibly (`score`, `categories`,
`spans`, `is_injection`, `high_confidence` keep their meaning):

```
verdict:      injection | suspicious | clean
score:        calibrated probability-like value in [0, 1]
layers_run:   {"signatures": "ran", "similarity": "absent", "classifier": "absent"}
signals:      [{layer, id, category, weight|score, span, view, transform_chain}]
counter:      [{id, reason}]            # e.g. quoted example in a security article
truncated:    false | {scanned_chars, total_chars}
budget:       {exhausted: false, ...}
```

---

## 7. Phases

Sizes are relative: S is days, M is one to two weeks, L is several weeks.
Each phase ends in something measurable and can ship on its own.

### Phase 0. Measurement (M) — prerequisite for everything after

Build `benchmarks/injection/`, following the layout of `benchmarks/ai4privacy/`.

1. **Loaders** for BIPIA (email, table, code), LLMail-Inject, InjecAgent,
   AgentDojo payloads, Open-Prompt-Injection and NotInject, each pinned to a
   revision and a hash, each normalised to one schema: `text`, `label`,
   `payload_span`, `attack_family`, `language`, `obfuscation`, `source`,
   `licence`.
2. **Embedding generator.** Places each payload into benign chunks at the start,
   middle and end, at three chunk lengths (about 500, 2,000 and 8,000
   characters). This is the document-shaped form that finding 1 requires, and
   it measures position and dilution directly.
3. **Mutation generator.** Applies obfuscations to a payload sample: the
   encodings in section 2.2, plus the twelve character-injection techniques
   from finding 3, using garak's encoders where they exist.
4. **Translation set.** A fixed sample of payloads in the nine languages the
   NER layer already routes (de, fr, es, it, nl, pt, pl, sv) plus zh, ja, ru,
   ar, hi. Machine translated, then checked by a fluent reader for a subset;
   the unchecked remainder is labelled as such.
5. **Benign set.** At least 20,000 document chunks from the sources in 4.4,
   weighted towards the kinds this scanner has flagged before: runbooks, API
   documentation, security articles that quote attacks, prompt-engineering
   guides, chat transcripts, HTML with ordinary CSS, text in right-to-left and
   joining scripts. Plus all of NotInject.
6. **Metrics.** Recall at FPR 0.1% and 1%; precision; per attack family, per
   language, per obfuscation, per position and per length; span overlap where
   a payload span is known; milliseconds per 1,000 characters per layer; the
   worst-case time on an adversarial timing set.
7. **Splits.** Sources are split, not rows. A source used for training in
   Phase 5 is never reported as a test score. A frozen adaptive set (a held-out
   LLMail-Inject slice plus in-house red-team cases) is touched only for
   release decisions.
8. **Baselines.** Run the current scanner, and `protectai/...-v2` through an
   adapter, and record both. The bake-off numbers are what later phases must
   beat.
9. **CI.** A deterministic sample of a few thousand rows runs on every change
   through the regression logic in `vecshield_platform/benchmark.py`. The full
   run is scheduled.

*Exit:* a committed baseline file with intervals; the published docs replace
"injection 1.00 / 1.00" with the external figures beside the in-house ones.

### Phase 1. Canonicalisation and coverage hardening (M)

Certain, cheap, independent of any model.

1. **Scan the whole surface.** Replace `value[:5000]` with overlapping windows
   (for example 4,000 characters with 400 overlap) up to
   `IntegrityLimits.max_text_chars`, and record truncation in the outcome when
   that limit is hit. A payload at character 5,001 is found.
2. **Linear-time patterns and budgets.** Rewrite `hidden_content` so it cannot
   backtrack across the surface; add a per-surface time budget and a decode
   budget (depth, payload count, expansion ratio). An exhausted budget is
   recorded and makes the outcome partial. Add the adversarial timing set to
   the tests.
3. **Recursive, bounded decoding.** Depth 3; chains recorded
   (`base64 → url → text`). Add ROT13 and reversed text (accepted only when the
   decoded view scores and the raw view does not), quoted-printable,
   `\uXXXX`/`\xNN`/`&#NN;` escapes, and a conservative digit-for-letter fold
   applied only inside words that become dictionary directive words.
4. **Variation-selector payloads.** Decode byte runs carried in variation
   selectors before stripping them, as tag characters are decoded today.
5. **Full confusables table.** Replace the 48-letter subset with a generated
   table from Unicode `confusables.txt` (Unicode Licence v3, already cited in
   the source), restricted to single-code-point Latin prototypes, kept as data
   with its version.
6. **Visible and hidden views.** A small tolerant HTML/Markdown pass that
   separates what a reader sees from what they do not: comments, `alt`/`title`
   attributes, zero-size or same-colour text, `hidden` attributes,
   `<details>`, link targets. Directive content in the hidden view gets the
   `hidden_directive` treatment it gets today for decoded text. No new
   dependency: `html.parser` from the standard library.
7. **Whitespace-layout attacks.** A view with newlines and repeated separators
   collapsed, so one-character-per-line and wide letter-spacing read as words.
8. **Offset maps.** Every view keeps a map back to raw offsets, so spans from
   decoded views can be located and redacted. Today transformed hits carry no
   position.

*Exit:* obfuscation-family recall on the Phase 0 mutation set is reported
before and after; the timing set stays under budget; no regression on NotInject
or the in-house hard negatives.

### Phase 2. Rules as data, more languages, use versus mention (M)

1. **Rule pack.** Move `_PATTERNS` into `vecshield/injection/rules/*.yaml`:
   `id`, `category`, `weight`, `pattern`, `languages`, `references`
   (OWASP and ATLAS ids), `positives`, `negatives`. Each rule's own examples
   run as tests. The pack has a version that appears in evidence, which also
   makes findings reproducible across releases.
2. **Per-rule calibration.** Extend `benchmark.py` so each rule earns
   `likely / possible / uncertain` from its precision lower bound on the
   Phase 0 benign set, as content detectors do. Fusion uses the class, and the
   Actions page already knows what to do with it.
3. **New rule families** suggested by the probe and the datasets: text addressed
   to the reader-model ("note to the AI", "assistant, before you answer"),
   task hijack ("stop X; instead Y"), forged completion (answer followed by a
   fabricated user turn), authority claims, conditional triggers ("when asked
   about X, always say Y"), and tool-call syntax for current agent formats.
4. **Languages.** Core override, exfiltration and role rules for the thirteen
   languages in the translation set, written from the translated attack sample
   and reviewed by a fluent reader. Languages without review ship as
   `uncertain`. Coverage states which languages have rules.
5. **Use versus mention.** A security article quoting "ignore all previous
   instructions" is the most predictable false positive. Add counter-signals:
   the match sits inside a code block or quotation and the surrounding text is
   about attacks (lexicon), or the document is an instruction-tuning dataset
   row. A counter-signal lowers the verdict to `suspicious`, is recorded, and
   never hides a match in the hidden view or a decoded view. This reuses the
   counter-signal idea already in `explain.py`.
6. **Scoring.** Replace "sum of category maxima" with a small logistic model
   over rule classes, category co-occurrence, hidden/decoded flags and
   counter-signals, fitted on Phase 0 training sources. Rules stay readable;
   only their combination is learned.

*Exit:* every rule has a measured class or is marked `uncertain`; recall at
0.1% FPR by language is published.

### Phase 3. Into the library and the ingest gate (S–M)

1. **Move** canonicaliser, rules and fusion to `vecshield/injection/`.
   `vecshield_platform.integrity.scan_text` re-exports, so nothing downstream
   changes. The import direction rule holds.
2. **SDK and CLI.** `check_injection(text)`, `vecshield injection-check
   chunks.jsonl`, and JSON output with the contract in section 6.
3. **Ingest gate.** `IngestGate(injection="flag" | "block" | "off")`. Default
   `flag`: recorded, not blocked. `block` applies to `injection` verdicts whose
   deciding signal is `likely`. The LangChain, LlamaIndex, Airflow, Dagster and
   Prefect examples gain one line each.
4. **Engine.** Per-layer coverage in the `prompt_injection` check outcome;
   rule ids and pack version in evidence; finding title unchanged so
   fingerprints and suppressions survive.
5. **Remediation text** gains the application-side controls from finding 9.

*Exit:* the product offers the ingestion filter its own finding recommends.

### Phase 4. Semantic similarity layer (M)

Catches paraphrase near known attacks without a transformer at run time.

1. **Exemplar index.** A few thousand canonicalised attack sentences from the
   training-eligible sources in 4.4, deduplicated and clustered, stored as
   vectors with ids and source attribution. Shipped as a hash-pinned data file.
2. **Embedder.** Bake-off between a static model2vec model (numpy only) and
   `multilingual-e5-small` on onnxruntime, on Phase 0 data. Choose on recall at
   0.1% FPR per megabyte and per millisecond. The exemplar vectors are built
   with the chosen embedder, so there is no dependence on a proprietary API as
   in Vigil.
3. **Scoring.** Sentence windows from the visible and hidden views; maximum
   similarity to an exemplar; a threshold calibrated on the benign set;
   evidence names the exemplar cluster, never reproduces third-party text
   beyond a short clip.
4. **Benign anchors.** A second small index of hard-negative sentences
   (NotInject-like, written in-house); a window closer to a benign anchor than
   to any attack exemplar is not flagged. This is the similarity-layer version
   of over-defence mitigation.
5. **Packaging.** Extra `vecshield[injection-sim]`. Absent, the layer reports
   `absent` and nothing else changes.

*Exit:* paraphrase-family recall at 0.1% FPR improves by a margin agreed after
Phase 0; added cost per chunk is published.

### Phase 5. Our own classifier (L)

1. **Why our own.** Section 4.2: no existing model is at once maintained,
   multilingual, cleanly licensed, loadable without custom code, and trained on
   documents.
2. **Data.** Built by the Phase 0 generators from training-eligible sources:
   payloads embedded in benign chunks at varied positions and lengths, with
   obfuscations applied *after* canonicalisation is simulated (the model is
   trained on canonicalised text, since that is what it will see). Benign
   chunks with trigger words, quoted attacks and imperative documentation are
   over-sampled, following the InjecGuard training idea. NotInject stays
   held out.
3. **Model.** Fine-tune `mmBERT-small` and `mdeberta-v3-base`; compare with
   the ProtectAI baseline and with layers 1–2. Two heads: chunk-level
   injection probability and token-level payload tagging, so the model
   localises the span instead of only flagging the chunk.
4. **Operating point.** Threshold chosen for FPR ≤ 0.1% on the benign set;
   temperature-scaled scores; a `likely` band and a `possible` band.
5. **Export.** ONNX, int8-quantised, single file with no external data, plus
   the tokenizer file. Inference through onnxruntime on CPU. No PyTorch, no
   `transformers`, no pickle at run time.
6. **Distribution.** Through the existing catalogue in `nlp_models.py`:
   hash-pinned, installable from a wheelhouse or private index, never fetched
   in response to a web request. `vecshield-platform nlp install
   --injection`. Extra `vecshield[injection-ml]`.
7. **Cascade.** The classifier runs on chunks where layers 1–2 are not already
   decisive, and on a random sample of the rest so the cascade's blind spot is
   measured, which is the lesson of the PHI cascade result in
   `asq_phi_ablation.md`. A `full` mode runs it on everything.
8. **Model card.** Training sources and licences, evaluation by family,
   language, position and length, known failures, and the adaptive-set result.
9. **Bring-your-own adapter.** A small interface so an operator can point the
   layer at another local ONNX model they are licensed to use (Prompt Guard 2,
   for instance). VecShield neither ships nor downloads it.

*Exit:* on held-out sources, recall at 0.1% FPR beats layers 1–2 and the
ProtectAI baseline by a margin set after Phase 0; NotInject accuracy is
reported; throughput is published for CPU.

### Phase 6. Corpus-level fusion and exposure (M)

Platform only. This is where VecShield can do what content-only tools cannot.

1. **Chunk-level fusion.** A chunk's injection verdict is combined with the
   signals already computed for it: is it a hub, is it in a near-duplicate
   cluster across sources, did it arrive in an ingestion burst, is its
   embedding an outlier, does it lack provenance. Two independent weak signals
   raise a `suspicious` chunk; none lowers an `injection` one.
2. **Retrieval-optimised text.** Features from finding 5 that need no model:
   a chunk whose leading span restates a question and whose remainder is a
   directive; repeated near-identical chunks differing only in the leading
   span. A masked-token probability check, as in GMTP, is evaluated once the
   Phase 5 encoder exists and adopted only if it adds recall at fixed FPR.
3. **Exposure.** `MonitoredConnector` already records `result_ids`. Join them
   with flagged chunk ids: "this chunk was returned by 37 queries from 4
   principals since it was written". That turns a content finding into an
   incident timeline and gives triage an ordering.
4. **Per-chunk findings in the console.** Triage, suppress (with expiry, as
   suppressions work today) and quarantine at chunk level.
5. **Demo estate.** Seed scenarios for each new family and check the seeded
   counts, as `demo/seed.py` does for isolation.

*Exit:* fused precision at fixed recall beats content-only on the Phase 0
poisoning scenarios; exposure appears on the finding.

### Phase 7. Optional judge (S, after the rest)

For `suspicious` chunks only, off by default.

- Runs against an endpoint the operator configures; the docs recommend a local
  model. It is listed in `model_egress` like any other configured egress.
- Known-answer form (finding 8): the model is asked to return a random token
  while reading the chunk as quoted data. No tools, a bounded structured
  reply, a fixed token limit.
- The judge's answer can raise a chunk to `injection`. It cannot clear one,
  because the chunk can address the judge.
- Rate and cost limits per audit; each call recorded in the audit log.

---

## 8. Threats the detector itself could introduce

| Threat | Control |
|---|---|
| Malicious or tampered model file | Hash-pinned catalogue; ONNX and tokenizer JSON only; hash verified before the file is opened; single file, no external-data references; no `trust_remote_code`; no pickle; onnxruntime pinned and tracked by the existing CVE check. |
| Dependency compromise | Extras only; versions pinned with hashes in the wheelhouse path; licence allow-list in CI; no new base dependency (the signature layer stays standard-library). |
| Training-data poisoning or licence taint | Sources pinned by revision and hash; licence recorded per source; no gated or unlicensed data; training base weights loaded with `weights_only=True` in an isolated environment. |
| Denial of service by a hostile chunk | Linear-time patterns; per-surface time budget; decode depth, count and expansion limits; window cap; an adversarial timing set in CI. An exhausted budget is reported, never silent. |
| Second-order injection through evidence | Finding previews carry live payloads into the console, JSON, HTML reports, alert sinks and anything that reads them, including LLM-based triage tools. Previews are defanged: invisible characters removed, markdown images and links neutralised, angle brackets escaped, length capped, and a `defanged` flag set. Audit the alert sinks and report templates for raw previews as part of Phase 3. |
| Attack corpora in the repository | Third-party attack data is downloaded at benchmark time, not vendored. In-house cases stay in `benchmark/corpus/` as today. No workflow feeds corpus files to an LLM with tools. |
| Customer data leaving the host | Layers 0–4 make no network calls. The judge is opt-in, operator-configured and reported as egress. |
| False positives causing data loss | Quarantine and deletion proposals require a `likely` signal; `block` at ingest is opt-in; suppressions expire. |
| A clean result read as assurance | Coverage names the layers that ran and the languages with rules; the docs carry the adaptive-attack limit; the finding text keeps "treat retrieved context as untrusted". |
| The engine used as an oracle | Unavoidable for open source. The mitigation is layers that do not share a failure mode, corpus-level evidence an attacker does not control, and operator-private exemplars and rules (below). |

Operator-private additions: a deployment can add its own rule file and its own
exemplars (for example, payloads found in its own incidents). They are loaded
from the state directory and are not part of the public pack.

---

## 9. Evaluation gates

Thresholds are set from the Phase 0 baseline, not guessed here. The gates
themselves:

| Gate | Blocks a merge when |
|---|---|
| Benign FPR | FPR on the sampled benign set rises above the recorded value plus tolerance |
| NotInject | Accuracy falls |
| Family recall at 0.1% FPR | Any attack family, language or obfuscation family that was measured falls, or loses its measurement |
| Position and length | Recall at any position or length bucket falls |
| Timing | Any item in the adversarial timing set exceeds the budget |
| Rule examples | A rule's own positive or negative example fails |
| In-house corpus | The existing `benchmark/corpus/injection.yaml` regression (unchanged) |

Release-only: the frozen adaptive set, reported in the changelog whatever the
result.

---

## 10. Sequencing and dependencies

```
Phase 0 ──┬─► Phase 1 ──► Phase 2 ──► Phase 3 ──┬─► Phase 4 ──► Phase 5 ──► Phase 7
          │                                     └─► Phase 6 (needs 3; gains from 5)
          └─► (baselines inform every exit criterion)
```

- Phases 0–3 need no model and no new dependency. They fix the truncation,
  the timing exposure, the missing ingest filter and the measurement gap, and
  are worth doing even if the rest is deferred.
- Phase 4 is the cheapest paraphrase coverage. Phase 5 is the largest piece of
  work and the largest expected gain on paraphrase and languages.
- Phase 6 can start after Phase 3 in parallel with 4 and 5.

## 11. Decisions needed

1. **Scope of the first tranche.** Recommendation: Phases 0–3 as one tranche.
2. **Is a trained model in scope for this project?** Phase 5 means owning a
   training pipeline, a model card and a release process. The alternative is
   stopping at Phase 4 plus the bring-your-own adapter.
3. **Default for the ingest gate.** Recommendation: `flag`, with `block`
   opt-in.
4. **Languages for the first rule pack**, and who reviews them.
5. **Where benchmark downloads are allowed to run** (CI egress policy), since
   third-party data is fetched, not vendored.

---

## 12. Sources

Read in this session:

- Liu, "Passing the Test You Trained On: Re-evaluating Prompt-Injection
  Detectors for LLM Agents", 2026. https://arxiv.org/abs/2610.03448
- Li et al., "InjecGuard: Benchmarking and Mitigating Over-defense in Prompt
  Injection Guardrail Models" (PIGuard), ACL 2025.
  https://arxiv.org/abs/2410.22770 · https://huggingface.co/leolee99/PIGuard
- Hackett et al., "Bypassing LLM Guardrails: An Empirical Analysis of Evasion
  Attacks against Prompt Injection and Jailbreak Detection Systems", 2025.
  https://arxiv.org/abs/2504.11168
- Nasr, Carlini, Tramèr et al., "The Attacker Moves Second", 2025.
  https://arxiv.org/abs/2510.09023
- Kim et al., "Safeguarding RAG Pipelines with GMTP", Findings of ACL 2025.
  https://arxiv.org/abs/2507.18202
- "Secure Retrieval-Augmented Generation against Poisoning Attacks" (RAGuard),
  2025. https://arxiv.org/abs/2510.25025
- Yi et al., "Benchmarking and Defending Against Indirect Prompt Injection
  Attacks on Large Language Models" (BIPIA), KDD 2025.
  https://arxiv.org/abs/2312.14197 · https://github.com/microsoft/BIPIA
- Model cards: https://huggingface.co/protectai/deberta-v3-base-prompt-injection-v2 ·
  https://huggingface.co/meta-llama/Llama-Prompt-Guard-2-86M
- Vigil. https://github.com/deadbits/vigil-llm
- Licence and status data: GitHub and Hugging Face APIs, PyPI metadata,
  2026-11-18.

From the literature, not re-read in this session; verify before citing:

- Zou et al., "PoisonedRAG", USENIX Security 2025.
- Liu et al., "DataSentinel", IEEE S&P 2025.
- Hines et al., "Defending Against Indirect Prompt Injection Attacks With
  Spotlighting", 2024.
- Zhan et al., "InjecAgent", 2024; Debenedetti et al., "AgentDojo", 2024.
- Zhou et al., "TrustRAG", 2025.

---

## 13. What was built (Phases 0 to 3), and decisions

### Decisions

| Question | Decision |
|---|---|
| First tranche | Phases 0 to 3 together. Done. |
| Phase 5, a model of our own | **Adopt an already-trained model; do not train one from scratch.** Phase 5 becomes: pick a pre-trained classifier on the benchmark, wrap it behind the layer interface, ship it hash-pinned and optional. The first candidate, ProtectAI DeBERTa v2, was scored in this tranche; its result and what it means for the choice are in the benchmark write-up. Fine-tuning a pre-trained model on document-shaped data stays open as a later step if no off-the-shelf model clears the false-positive bar. |
| Ingest gate default | `flag`. `block` is opt-in. Done. |
| CI gate for the benchmark | Not wired for now. The benchmark was run by hand and its results recorded in the repository. |

### Built

| Phase | Built | Where |
|---|---|---|
| 0 | Fetcher with pinned revisions and a hash lock; deterministic dataset builder; 22 obfuscations; embedded-payload sets by position and length; dev, test and held-out splits; legacy, current and classifier detectors; Wilson intervals and recall at a fixed false-positive rate; recorded summaries | `benchmarks/injection/` |
| 1 | Whole-surface scanning with a character limit and a time budget, both reported; bounded nested decoding; ROT13, reversed text, leetspeak, letter-spaced and one-per-line layouts, variation-selector payloads, backslash and quoted-printable escapes, a typo-tolerant reading; a look-alike table derived from Unicode data; a hidden-markup view; linear-time patterns; offset maps for normalised and decoded views | `vecshield/injection/canonical.py` |
| 2 | Rules as data with ids, references, examples and a pack version; 37 new rules; nine more languages, marked unreviewed; a use-versus-mention signal; per-rule behaviour measured | `vecshield/injection/rules.py`, `scanner.py` |
| 3 | Scanner in the library; `check_injection()`; `vecshield injection-check`; gate, SDK and CLI `injection` setting; integrity engine coverage details, rule ids and pack version in evidence; defanged previews; remediation text | `vecshield/`, `vecshield_platform/integrity/` |

### Where it departs from the plan

- **Rules are a Python data module, not YAML.** The library has no YAML
  dependency, and regular expressions are easier to read as raw strings than
  inside JSON. Each rule still has an id, references, examples that run as
  tests, and a pack version.
- **Scoring is unchanged.** The plan proposed a fitted combination of rule
  classes. The additive score was kept so that existing thresholds, tests and
  severities mean what they did. A learned combination belongs with the layers
  that produce real-valued scores (Phases 4 and 5).
- **Per-rule calibration is measured and recorded, not yet used.** `block`
  acts on high-confidence verdicts. Tying it to a per-rule `likely` class
  needs more benign data per rule than this benchmark has; most rules fire on
  too few benign rows to bound.
- **No translated attack set.** Other languages are measured on the two public
  sources that contain them (European languages only). Rules for Russian,
  Chinese, Japanese and Arabic are covered by their own examples and nothing
  else; that is stated wherever they are listed.
- **About 13,400 benign documents, not 20,000**, and no chat transcripts.
- **Sources not included:** AgentDojo and Open-Prompt-Injection (their attacks
  are generated by code that needs the agent harness), HackAPrompt (gated),
  and the BIPIA web and summarisation contexts (not redistributable).
- **garak was not used.** The obfuscations are written in the harness, which
  keeps an attack toolkit out of the dependency set.
- **Whole-text scanning, not windows.** With every pattern bounded, scan time
  grows in proportion to length, so windows bought nothing.
- **The check's outcome keeps its meaning.** A clean, fully read collection
  still reads `passed`. The outcome's coverage now says the method was
  signatures and which layers are absent. Making an absent layer `inconclusive`
  would turn every audit partial for a layer nobody can install yet; that
  changes when Phase 4 or 5 ships an optional layer.
- **Use versus mention marks, it does not excuse.** Text about injection that
  quotes a payload is flagged as `suspicious` and is never blocked or rated
  high. It is still flagged: an attacker can write the preamble too.
- **Operator-private rules and exemplars** are not built.
- **Previews are defanged at the source**, in the scanner, so every consumer
  of evidence gets the inert form. The alert sinks and report templates were
  not separately audited for other raw text.

### Second round (2026-11-18): more data, harder cases, F1 and AUC

- **Benchmark doubled** to 54,192 rows: six more public sources, AgentDojo
  rebuilt from its data files, and constructed hard cases. F1, ROC-AUC and
  PR-AUC added, with thresholds chosen on dev and applied elsewhere unchanged.
- **Rule packs 2026.11.2 and 2026.11.3.** Test-split F1 0.44 to 0.58 and
  ROC-AUC 0.66 to 0.80. Held-out F1 and ROC-AUC unchanged, for the second
  round running. The conclusion for this plan: further rule work buys little
  outside the data it is written against.
- **Phase 5 is built in its decided form**: an optional, hash-pinned,
  already-trained classifier beside the rules (`vecshield.injection.classifier`),
  with two catalogued models. It is where F1 and AUC improved on held-out data
  (F1 0.21 to 0.66–0.73, ROC-AUC 0.56 to 0.95), with the caveat that both models
  were trained on several of the benchmark's sources.
- **Phase 4 (similarity to known attacks) was skipped.** The classifier covers
  the paraphrase gap it was meant for, and a similarity index built from the
  same public payloads would share the classifier's training-overlap problem.
- **Still open:** Phase 6 (fusion with corpus-level signals, retrieval
  exposure), Phase 7 (optional judge), per-language review of the unreviewed
  rules, a translated attack set for non-European languages, and an
  evaluation set that is known to be outside every candidate model's training
  data. The last is the most useful next step: without it no classifier figure
  here is out of sample.

