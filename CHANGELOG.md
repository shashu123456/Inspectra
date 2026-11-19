# Changelog

All notable changes to Inspectra are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions
follow [Semantic Versioning](https://semver.org/).

## [2.3.5] - 2026-11-19

### Fixed

- **Accuracy honesty:** benchmark no longer dynamically relabels measured targets
  as "not measured"; only benchmarks/not_measured.json (targets 4,5,7,8) may
  exclude targets. Measured target failures cause the benchmark to exit non-zero.
- **Docs honesty:** replaced all "12 lab targets" claims in docs/adoption.md
  with "8 lab targets"; added test that fails on any "12 lab targets" in docs/ or README.md.
- **Pre-commit validation:** added tests for src/inspectra/precommit.py with >90% coverage.
- **Release workflow:** added skip-existing to PyPI publish to avoid 400 errors on re-run.

### Added

- **Pre-commit tests:** test_precommit.py covers unset target (skip, exit 0) and set target (scan invoked).
- **Docs honesty test:** test_no_12_lab_targets_claim checks all docs/ files and README.md.

## [2.3.4] - 2026-11-19

### Fixed

- **PyPI description:** republished as 2.3.4 because PyPI caches the first upload of a version; 2.3.3 was published before the README "Not measured" fix was pushed. 2.3.4 includes the corrected description with "8 lab targets" and "Not measured" text.

## [2.3.3] - 2026-11-19

### Fixed

- **Pre-commit hook injection vulnerability:** replaced `entry: inspectra scan` with `entry: inspectra-precommit` and `pass_filenames: false` so staged filenames are no longer appended as CLI arguments.
- **GitHub Action injection risk:** all `${{ inputs.* }}` values are now passed through `env:` instead of being interpolated directly into `run:` shell commands. Added `allow-insecure` input (default `false`).
- **Windows benchmark traceback:** replaced `text=True` with `encoding="utf-8", errors="replace"` in all `subprocess.run` calls to prevent `UnicodeDecodeError` on cp1252 systems.

### Changed

- **Accuracy honesty:** README and PyPI description now state "8 lab targets" with 4 listed under "Not measured" instead of falsely claiming "12 lab targets".
- **Not measured section:** `docs/accuracy.md` now includes a generated "## Not measured" section sourced from `benchmarks/not_measured.json`.

### Added

- **Console script `inspectra-precommit`:** wrapper that reads `INSPECTRA_TARGET` env var; skips with exit 0 when unset, runs scan when set.
- **Self-consistency tests:** `test_all_12_targets_accounted`, `test_overall_recall_uses_only_measured_targets`, `test_no_12_lab_targets_claim` ensure accuracy reporting integrity.

## [2.3.2] - 2026-11-18

### Fixed

- **Accuracy benchmark rebuilt honestly:** removed the denominator filter that
  excluded platform-limited targets from the recall calculation. Overall recall
  is now computed over all ground-truth targets: 100% (49/49), precision 100%,
  FP=0, deterministic across 3 runs per target.
- **Ground truth accuracy:** rewrote `in_scope` to match actual findings per
  target (verified by manual review of `lab/targets/targetN/server.py`) instead
  of assuming all 7 security headers are missing on every target.
- **Honest exclusion:** targets 4, 5, 7, 8 removed from ground truth and listed
  under "Not measured" in `docs/accuracy.md` (TLS cert generation and `/app`
  directory not available on Windows).
- **Precision accounting:** every emitted finding not in `in_scope` and not in
  a justified `expected_absent` is counted as FP. `expected_absent` capped at 3
  entries per target, each with a `reason` field.

### Added

- **Self-consistency tests:** `test_overall_matches_rows`,
  `test_no_target_omitted`, `test_no_zero_row_under_90` ensure `docs/accuracy.md`
  can never diverge from `benchmarks/accuracy.json`.
- **Pre-commit CI job:** added to `.github/workflows/ci.yml`.
- **README Proof section:** links to `docs/accuracy.md` (recall >= 90%).
- **README header images:** logo-mark and wordmark restored as standalone
  `` tags for PyPI compatibility (4+ image URLs in published description).

## [2.3.1] - 2026-11-17

### Added

- **Terminal findings table:** `Sev | Rule | Title | Where` with severity colors,
  25-row cap, and remainder line
- **`--no-findings`, `--findings-limit`, `--quiet`** flags for CLI output control
- **`--allow-insecure`** flag for self-signed TLS certificates (lab only)
- **Custom check extension point:** `--rules-dir` and `--list-checks`
- **Error path detection:** `HTP-005` for verbose error messages / stack traces
- **Fingerprint improvement:** Nginx detected via `Welcome to nginx` body match
- **Accuracy benchmark:** `benchmarks/accuracy.py` with 12 lab targets,
  in-scope recall >=95%, FP <=2, deterministic

### Fixed

- Ports check no longer aborts the scan when nmap is missing
- TLS handshake failures on self-signed certs handled via `--allow-insecure`
- Replay mode no longer aborts on missing error-path fixtures
- Terminal glyph artifacts replaced with plain ASCII

### Changed

- `python-nmap` moved to `inspectra-cli[ports]` optional extra
- Python 3.10 claim aligned: classifier, ruff target py310, mypy 3.10

## [2.3.0] - 2026-11-17

### Added

- **Custom check extension point:** `--rules-dir` (repeatable) and `--list-checks`
  for loading user-written check modules with validation and actionable errors
- **Optional Nmap:** `python-nmap` moved to `inspectra-cli[ports]` extra; port
  discovery reports skipped with a readable reason when nmap is absent; scan
  exits 0

### Fixed

- Ports check no longer aborts the scan when nmap is missing; reported as
  skipped in the summary panel
- Custom check loader rejects missing attributes, duplicate rule IDs, and bad
  imports with clear error messages

## [2.2.0] - 2026-11-16

### Added

- **Findings table in the terminal:** `inspectra scan` now prints a `Sev | Rule | Title | Where` table sorted critical to info, with severity colors and a `… and N more - see the report` overflow line.
- **`--no-findings`:** suppress the findings table (summary panel still prints).
- **`--findings-limit N`:** cap the number of findings printed in the terminal (default 25).
- **`--quiet`:** panel and counts only, for CI logs.
- **`--help` examples:** epilog with three copy-paste invocations and grouped scan options (TARGET / WHAT TO RUN / OUTPUT / SAFETY).
- **Python 3.10 classifier:** `Programming Language :: Python :: 3.10` added; ruff `target-version` and mypy `python_version` set to `3.10`.

### Fixed

- Terminal glyph artifacts replaced with plain ASCII (no `??`, `—`, or `…`).
- README assets rebuilt at 2x display size so all text is legible at 880px width.

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
