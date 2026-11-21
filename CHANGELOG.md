# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Changes to the detection engine specifically are also tracked in
[`docs/library/detection-changelog.md`](docs/library/detection-changelog.md).

## [Unreleased]

### Added

- Prompt-injection detection moved into the detection library
  (`vecshield.injection`) and rebuilt as a rule pack run over canonical views
  of the text. New: `vecshield.check_injection()`, `vecshield injection-check`,
  and an `injection` setting on `IngestGate`, `check_chunks()` and
  `vecshield ingest-check` (`flag` by default: flagged chunks are listed and
  allowed; `block` is opt-in). The integrity engine uses the same scanner.
- The scanner now reads the whole of a text surface (it read the first 5,000
  characters), undoes more disguises (nested encodings, ROT13, reversed text,
  digit-for-letter spellings, letter spacing, bytes hidden in variation
  selectors, backslash and quoted-printable escapes, typos), reads markup a
  reader does not see as a view of its own, and has rules for nine more
  languages, each marked unreviewed. Findings name the rule ids and the
  rule-pack version.
- A benchmark for it on public data, with pinned sources and a held-out split:
  `benchmarks/injection/`, written up in
  [`docs/library/benchmarks/injection.md`](docs/library/benchmarks/injection.md).
  It is not yet a CI gate.
- `VECSHIELD_INTEGRITY_INJECTION_MAX_CHARS` and
  `VECSHIELD_INTEGRITY_INJECTION_TIME_BUDGET` bound one surface's scan.
- An optional pre-trained classifier beside the injection rules
  (`pip install "vecshield[injection-ml]"`, then point
  `VECSHIELD_INJECTION_MODEL_DIR` at the model files). It is off by default,
  loads only files whose SHA-256 matches a pinned catalogue, downloads
  nothing, and can flag a chunk for review but never make a flag high
  confidence or block one. See
  [`docs/library/injection_classifier.md`](docs/library/injection_classifier.md).
- Rule pack `2026.11.3`: plain "pretend to be" no longer flags on its own
  (on public data it was almost always benign role-play); it is a supporting
  signal, and flags when what is pretended is an unrestricted model.
- Rule pack `2026.11.2`: stacked disguises are decoded through each other,
  rules for forged turn markers of more chat templates, planted "message from
  me to you" blocks and task hijacks, and supporting signals for a request
  sitting in a data field. Unflagged text now carries a graded score.
- The injection benchmark now reports F1, ROC-AUC and PR-AUC, and covers
  twice the data: 54,192 rows, six more public sources, and constructed hard
  cases (payloads in structured containers, split across paragraphs, in very
  long documents, in documents in another language, under two disguises).

- Two-step sign-in for local accounts ([ADR 0004](docs/adr/0004-totp-mfa.md)).
  Anyone can add an authenticator app (TOTP) under Settings → Security and
  receives ten single-use recovery codes. Sign-in then asks for a code after
  the password. A wrong code counts toward the lockout, and a code works only
  once. Admins can reset a lost authenticator from Users. Every change is
  audited.
- `--mfa-required` / `VECSHIELD_MFA_REQUIRED` (`off`, `admin`, `all`)
  requires two-step sign-in. Accounts without it are taken to set-up before
  anything else. The Helm chart defaults to `admin`.
- `VECSHIELD_JWT_REQUIRE_MFA=1` accepts a JWT only when its `amr` claim shows
  the identity provider did MFA.
- `GET /auth/users` reports `mfa_enabled` for each account.
- New dependencies: `pyotp` (codes) and `segno` (enrollment QR code). Both are
  pure Python with no dependencies of their own.

### Changed

- The `prompt_injection` check outcome records how the text was read
  (`method`, `detection_layers`, `rule_pack`, the languages with rules) and is
  partial when a surface was longer than the scan limit or ran out of scan
  time. Injection evidence previews are defanged before they are stored.
- Demo scenario S12: the instruction in `curated_corpus` was a documented miss
  and is now caught; the walkthrough says which words the rule reads and what
  is still missed.

- `GET /admin/jobs` returns each job's `result` summarized to `{"id": ...}`,
  the record the run saved. A full result can be a whole audit, and the Runs
  list only links to it. `GET /admin/jobs/{id}` still returns the full result.
- `GET /admin/jobs` accepts `limit` from 1 to 500 and `GET /runtime/alerts`
  from 1 to 1000; `offset` must not be negative. Out-of-range values are a
  `422` instead of an unbounded read.

### Fixed

- Finished background jobs no longer stay in server memory for the life of the
  process. A job leaves memory once its final state is saved to history, and
  is read from there. Without history, only the newest 200 finished jobs are
  kept.
- The console's static assets are served gzip-compressed to clients that
  accept it. `dashboard.js` and `dashboard.css` drop from about 1.07 MB to
  about 290 KB on a first load. Only the `/static` mount is compressed: API
  responses, Range requests, fonts and images are served as before.
- pgvector: a table without a primary key is no longer identified by its
  first column, which need not be unique. Erasing one chunk could delete every
  row sharing that value. Such a table is now keyed by a NOT NULL unique index
  when it has one. Otherwise it is keyed by row position (`ctid`), and erasure
  refuses to delete from it. When no column has a conventional name, the chunk
  text is the column with the longest values, not an arbitrary one, so a
  `tenant` column is no longer read as text and hidden from the isolation
  check.

## [0.1.0]

First open-source release, under Apache-2.0.

### Added

- `vecshield` — the detection library: regex and checksum classifiers with an
  optional Presidio/spaCy NER layer, an ingest gate, chunk-boundary analysis,
  dataset scanning, and framework adapters for LangChain, LlamaIndex, Airflow,
  Dagster and Prefect.
- `vecshield_platform` — the server: a FastAPI API and web console, thirteen
  vector-store connectors, and five assessment engines (scan, posture,
  integrity, access, compliance).
- Role-based access control (`viewer`, `operator`, `compliance`, `admin`) with
  static tokens, JWT, or local accounts; separation of duties on approvals; a
  hash-chained audit log; and an audited reveal path for masked values.
- Coverage states throughout: a check that could not observe something reports
  *unsupported* or *inconclusive* rather than passing, and a partial read exits
  `3` rather than `0`.
- A labelled benchmark corpus with precision and recall reported as Wilson
  intervals, plus confidence calibration derived from measurement. CI fails on
  a regression.
- A seeded demo estate — six stores, fourteen collections, fifteen scenarios
  across six regulatory frameworks — that verifies its own scenarios still
  fire, with a one-command Docker Compose stack.

[Unreleased]: https://github.com/vecshield/vecshield/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/vecshield/vecshield/releases/tag/v0.1.0
