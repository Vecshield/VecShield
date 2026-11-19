# Changelog

All notable changes to this project will be documented in this file.

The format is based on Keep a Changelog, and this project follows Semantic
Versioning before and after the `1.0.0` release.

## [Unreleased]

### Added

- `vecshield.injection`: the prompt-injection scanner, moved from the platform.
  Rule pack `2026.11.1`, 76 rules: 39 of the 40 earlier patterns kept and
  given ids (three gained bounds on their gaps; the markup pattern, which
  could backtrack, became a linear-time scan), and 37 added (overrides without
  "previous", prompt-leak questions, text
  addressed to the model, task hijack, instructions about the answer,
  authority claims, and core override and prompt-leak rules in German, French,
  Spanish, Italian, Portuguese, Russian, Chinese, Japanese and Arabic, all
  marked unreviewed).
- Canonical views: nested base64/hex/URL decoding to depth 3, ROT13, reversed
  text, leetspeak, letter-spaced and one-character-per-line layouts, variation
  selector payloads, backslash and quoted-printable escapes, a typo-tolerant
  reading, and HTML comments, hidden elements and `alt`/`title` text read as a
  hidden view. Look-alike folding uses a table derived from Unicode
  `confusables.txt` 18.0.0 (356 letters; it was 48).
- `check_injection()`, `vecshield injection-check`, and the ingest gate's
  `injection` setting (`flag` default, `block`, `off`).
- Whole-text scanning with a character limit and a time budget; both are
  reported when hit.

- Rule pack `2026.11.3`, 86 rules: `role.pretend` removed as a rule that
  flags on its own. In the second benchmark round's held-out data it fired on
  149 of 158 false positives, nearly all benign role-play prompts. Plain
  "pretend to be" stays as the supporting `role.pretend.weak`;
  `role.pretend_unrestricted` still flags. The change was made after seeing
  held-out results and the benchmark reports both packs.
- Rule pack `2026.11.2`, 87 rules. Decoded payloads are given every reading
  the text itself gets, so a disguise inside a disguise is read (leetspeak in
  base64, base64 in a URL-encoded query, ROT13 in base64). New rules: turn
  markers of other chat templates, the "(system_message)" marker, "important
  message from me to you", "before you can solve the task … do the following",
  a tool call written as JSON keys, and supporting signals for a first-person
  request inside a record's field and for an instruction to send mail to a
  named address. `role.pretend` flags only in the imperative position and the
  bare word "uncensored" became supporting: both had fired mostly on benign
  rows in the first benchmark round.
- Text the rules do not flag now carries a graded score (0.30 to 0.45 by how
  many supporting signals fired), still under the threshold. It changes
  ranking, not verdicts.
- `vecshield.injection.classifier`: an optional, hash-pinned pre-trained
  classifier as a second opinion. Its flags are never high confidence.

### Measured

- F1, ROC-AUC, recall and false-positive rate, for the rules alone and
  with each catalogued classifier, on developed-against and held-out public
  data, are in [benchmarks/injection.md](benchmarks/injection.md), with the
  cases nothing finds. The first round is in
  [benchmarks/injection_round1.md](benchmarks/injection_round1.md).

- Professional FOSS repository structure, contributor documentation, examples,
  and quality tooling.

## [0.0.1] - 2026-07-06

### Added

- Local PII/PHI/PCI/secret detection with a dependency-light regex classifier.
- Optional NLP detection through Presidio and spaCy.
- CLI commands for `detect`, `ingest-check`, `training-check`, and
  `redact-preview`.
- Python SDK helpers for text checks, chunk gates, dataset scans, and redaction.
- Local datasource readers for common training-data formats.

[Unreleased]: https://github.com/vecshield/vecshield/compare/v0.0.1...HEAD
[0.0.1]: https://github.com/vecshield/vecshield/releases/tag/v0.0.1
