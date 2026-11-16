# Changelog

All notable changes to Inspectra are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions
follow [Semantic Versioning](https://semver.org/).

## [2.1.1] - 2026-11-16

### Fixed

- README now embeds logo-mark, wordmark, and banner-light assets (absolute URLs render on PyPI).
- "How it works" section with the architecture diagram.
- CI badge is live (GitHub Actions workflow badge); coverage badge states the measured 89%.
- Python version truth: requires-python `>=3.10`, CI matrix `3.10/3.11/3.12`, badge `3.10+`.
- Project URLs: Documentation points at the docs tree; "Live sample report" points at GitHub Pages.
- Deleted EcoMind-contaminated dead assets from docs/assets/.

## [2.1.0] - 2026-11-16

### Added

- **Bounded concurrency:** `--concurrency` (default 4) runs checks
  concurrently with a bounded thread pool; `--delay` (default 0.2s)
  applies per-host spacing between requests so sleeping never holds
  another host's slot.
- **Per-host politeness:** max 2 in-flight requests per host regardless
  of global concurrency, enforced with a per-host semaphore keyed by
  hostname.
- **Per-run DNS/TLS caches:** DNS resolution and TLS handshake results
  are cached per run keyed by host (and host+port), so each host is
  resolved/hand-shaken at most once per scan.
- **Replay `skipped` reporting:** replayed scans now emit a `skipped`
  array (`dns`, `ports`, `tls` with reason "requires live network; not
  available in replay") and the CLI prints one line listing them,
  instead of silently omitting raw-socket checks.

## [2.0.0] - 2026-11-14

### Added

- **Deterministic replay (M4):** `--save-fixtures DIR` records every HTTP
  request/response to disk; `--replay DIR` replays scans entirely from
  disk with zero network I/O. Two runs against the same fixtures produce
  byte-identical JSON reports (modulo timestamps).
- **`evidence_hash` on findings:** `sha256` of canonical JSON evidence
  (truncated to 16 chars), stored on every `Finding` and emitted in JSON
  reports and SARIF `properties.evidenceHash`.
- **SARIF output:** `--format sarif` produces SARIF 2.1.0 compatible
  output consumable by GitHub Code Scanning.
- **Baseline diff:** `--save-baseline` / `--baseline` compare scans
  against a previous run; `--fail-on` applies only to new findings.
- **SSRF hardening:** validated IP pinning (DNS rebinding protection),
  explicit blocked-network list including CGNAT (100.64/10), HTTPS→HTTP
  downgrade rejection, per-redirect-hop re-validation.
- **Evidence redaction:** header lines, URL userinfo/query tokens, and
  JWTs are redacted before any reporter serializes them.
  `--no-redact` disables with a stderr warning.
- **Hosted sample report:** a static report and supporting files are
  hosted on GitHub Pages at
  https://shashu123456.github.io/Inspectra/ for recruiter review without
  installing anything.

### Changed

- **CLI:** `--format` now accepts `sarif` and comma-separated lists
  (`sarif,json,markdown`); `-o/--output` writes a single-format report
  to an exact path; `--fail-on` accepts `none|low|medium|high` and
  works without a baseline.
- **Reports:** JSON includes `evidence_hash` per finding plus `scope`
  and `redaction` metadata; SARIF includes `evidenceHash` in result
  properties and scope/redaction in run properties.

## [1.0.0] — 2026-09-08

Initial public release.

### Added

- **Assessment checks (8):** DNS record analysis, Nmap port discovery
  (top-1000 default, explicit lists, skip), HTTP analysis (redirects,
  error states, server disclosure), TLS certificate inspection (expiry,
  self-signed, hostname mismatch, protocol versions), security header
  assessment (9 rules), technology fingerprinting (24 signatures),
  robots.txt inspection, and opt-in rate-limited directory observation.
- **Explainable findings:** every finding carries observation, impact
  reasoning, evidence, confidence, severity and a concrete
  recommendation.
- **Risk engine:** severity × confidence rubric producing a 0–100
  posture score with letter grade (A+ … F).
- **Reports:** JSON (always), Markdown (default), and a polished,
  self-contained HTML report. All human-facing timestamps are displayed
  in Indian Standard Time (IST, UTC+05:30).
- **CLI:** single `inspectra scan` command with Rich console output,
  first-run authorization consent gate, and CI-friendly exit codes
  (0 clean · 1 findings · 2 error).
- **Safety model:** passive GET-only assessment, timeouts on every
  network operation, safe-by-default wordlists, authorization banner.
- **Live demo:** `demo/server.py` hosts a harmless misconfigured fixture
  site plus a UI that runs real scans in the browser.
- **Project infrastructure:** test suite (89 tests, ~90% coverage) with
  a local fixture server, strict mypy on `src/`, ruff lint + format,
  GitHub Actions CI on Python 3.11/3.12, issue templates, and sample
  reports under `examples/`.

### Security

- Safe-by-design: no exploitation, brute-forcing, or payload delivery;
  the check registry and contribution policy enforce it.
