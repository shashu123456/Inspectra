# Changelog

All notable changes to Inspectra are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions
follow [Semantic Versioning](https://semver.org/).

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
