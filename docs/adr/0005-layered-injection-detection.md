# ADR 0005: Layered injection detection, with an optional pinned classifier

Status: proposed (2026-11-18)

## Context

Prompt-injection detection was a set of 40 regular expressions inside the
platform's integrity engine. Three things were wrong with where and how it ran:

- It lived in `vecshield_platform`, so the library's ingest gate could not use
  it. The integrity finding told users to "add an injection filter to the
  ingestion pipeline", and the product did not offer one.
- It read the first 5,000 characters of a text surface and nothing after.
- Its only measurement was a 55-item corpus written alongside the rules, on
  which it scored 1.00 and 1.00.

Measured on public data (`docs/library/benchmarks/injection.md`), the rules
find a minority of planted instructions, and work on them improves results on
the sources they are developed against and nowhere else. A pre-trained
classifier finds far more. It is also a file of weights from a third party
that is wrong more often on ordinary text.

## Decision

1. **The scanner moves to the library** (`vecshield.injection`). The platform
   imports it; the import direction rule is unchanged.
2. **Rules are data**: each has a stable id, examples that run as tests, and
   the pack has a version that appears in evidence.
3. **The ingest gate checks for injected instructions by default, and stops
   nothing by default.** `IngestGate(injection="flag")` lists flagged chunks in
   `report.injection_flags` and allows them. `"block"` is opt-in and blocks
   only high-confidence flags. `"off"` skips the check. This is a new default
   behaviour of an existing interface: reports gain an `injection` section and
   nothing that was allowed before is blocked.
4. **A pre-trained classifier is an optional second opinion**, behind these
   rules:
   - Off unless `VECSHIELD_INJECTION_MODEL_DIR` is set or a classifier object
     is passed. VecShield downloads nothing.
   - A model file is loaded only if the SHA-256 of the ONNX file and of the
     tokenizer match a catalogue in the source
     (`vecshield.injection.CLASSIFIER_CATALOG`). A mismatch is refused.
   - Only data is loaded: one ONNX graph and one tokenizer JSON, on CPU,
     through `onnxruntime` and `tokenizers`. No pickle, no repository code, no
     `trust_remote_code`, no PyTorch.
   - Catalogued models must be under a licence compatible with redistribution
     alongside Apache-2.0 code, must not be gated, and must have been scored
     on the project's benchmark.
   - A flag that rests on the classifier alone is never high confidence. The
     gate does not block on it and nothing proposes an irreversible action
     from it. Only a rule, which a reviewer can read, can do that.
   - A classifier that is configured and cannot be loaded makes the check
     partial. It is never treated as if no classifier had been asked for.
5. **The check says how it read the text.** The `prompt_injection` outcome
   records the method, which layers ran, the rule pack, and the languages that
   have rules. A surface longer than the scan limit, or a scan that ran out of
   its time budget, makes the outcome partial.
6. **Evidence previews are made inert** before they are stored, because an
   excerpt of an injection is an injection to whatever reads the report.

## What this does not establish

- That a chunk with no flag is safe. The rules read signatures; the classifier
  reads phrasing. Neither reads intent, and published adaptive attacks defeat
  both kinds of detector.
- That a statement is true. Text that misleads without instructing is not
  looked for.
- That the classifier's benchmark figures hold on other data. Both catalogued
  models were trained on several of the benchmark's sources.

## Alternatives considered

- **Bundle an existing detector.** The maintained, permissively licensed ones
  were English-only or trained on short prompts; Meta's Prompt Guard 2 is under
  a licence that does not fit this distribution; PIGuard needs
  `trust_remote_code`.
- **Train a model in this project.** Rejected for now in favour of an
  already-trained model: it would mean owning a training pipeline and its data
  licensing.
- **Let the classifier block.** Rejected: its false positives on ordinary text
  are several times the rules', and its opinion cannot be checked by reading it.
- **Make the gate block by default.** Rejected: a signature match is not enough
  to stop an ingestion pipeline that worked yesterday.
- **Download the model on first use.** Rejected: the server does not fetch
  code or weights in response to configuration, as with the NER models.

## Consequences

- Ingest reports and integrity findings carry rule ids, a pack version and the
  layers that ran. Consumers that read `IngestGateReport.to_dict()` see a new
  `injection` key.
- A text that only supporting rules fire on now scores between 0.30 and 0.45,
  by how many fired, instead of at most 0.30. It is still never flagged.
- Scanning is slower than before per character (about 1.6 ms per 1,000
  characters), and now covers the whole text.
- With the classifier on, scanning costs about 55 ms per 1,000 characters on a
  CPU.
- The benchmark is run by hand and is not a CI gate yet.

## Migration

No configuration change is needed. To keep the gate exactly as it was, pass
`injection="off"`. Stored audits keep the outcomes they recorded.
