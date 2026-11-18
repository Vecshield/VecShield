# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Changes to the detection engine specifically are also tracked in
[`docs/library/detection-changelog.md`](docs/library/detection-changelog.md).

## [Unreleased]

### Added

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

- `GET /admin/jobs` returns each job's `result` summarized to `{"id": ...}`,
  the record the run saved. A full result can be a whole audit, and the Runs
  list only links to it. `GET /admin/jobs/{id}` still returns the full result.
- `GET /admin/jobs` accepts `limit` from 1 to 500 and `GET /runtime/alerts`
  from 1 to 1000; `offset` must not be negative. Out-of-range values are a
  `422` instead of an unbounded read.

### Fixed

- pgvector: a tenant kept in a json/jsonb metadata column (LangChain's
  `cmetadata`, LlamaIndex's `metadata_`) is now found and probed. Before, such
  a table was reported as single-tenant ("isolation is not applicable") while
  several tenants shared it. The column's top-level keys become chunk metadata,
  and `query(where=)` filters inside it. A filter key the table has neither as
  a column nor as a json key now raises instead of being dropped, which ran
  the query unfiltered. This also applies to filters passed through the
  runtime proxy.
- Finished background jobs no longer stay in server memory for the life of the
  process. A job leaves memory once its final state is saved to history, and
  is read from there. Without history, only the newest 200 finished jobs are
  kept.
- The console's static assets are served gzip-compressed to clients that
  accept it. `dashboard.js` and `dashboard.css` drop from about 1.07 MB to
  about 290 KB on a first load. Only the `/static` mount is compressed: API
  responses, Range requests, fonts and images are served as before.

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
