# Inspectra Evidence Log

Append-only record of every gate execution. Raw output pasted below each
command.

## P8 — Assets

### Asset gate table

```
logo-mark: w=128.0 bytes=623 texts=0 min_svg=0 min_on_screen=0
wordmark: w=640.0 bytes=259 texts=1 min_svg=120.0 min_on_screen=165.0
wordmark-dark: w=640.0 bytes=259 texts=1 min_svg=120.0 min_on_screen=165.0
banner-light: w=1760.0 bytes=1873 texts=6 min_svg=36.0 min_on_screen=18.0
banner-dark: w=1760.0 bytes=1873 texts=6 min_svg=36.0 min_on_screen=18.0
architecture: w=1760.0 bytes=4346 texts=22 min_svg=36.0 min_on_screen=18.0
```

Gate: min_on_screen >= 16 for banner/architecture (PASS: 18), >= 30 for
wordmark (PASS: 165), bytes < 90000 (PASS: max 623 for logo-mark, max 1873
for banners), no `<text>` inheriting fill="none" (PASS: all fills explicit).

### PNG dimensions at 880px wide

| File | Size | Dimensions |
|------|------|------------|
| docs/assets/png/logo-mark.png | 41573 bytes | 880x880 |
| docs/assets/png/wordmark.png | 17106 bytes | 880x176 |
| docs/assets/png/wordmark-dark.png | 11339 bytes | 880x176 |
| docs/assets/png/banner-light.png | 34942 bytes | 880x220 |
| docs/assets/png/banner-dark.png | 34651 bytes | 880x220 |
| docs/assets/png/architecture.png | 15247 bytes | 880x310 |
| docs/assets/png/social-preview.png | 15327 bytes | 880x440 |
| docs/assets/png/favicon.png | 34075 bytes | 880x880 |

## P9 — README + CLI + 2.2.0

### pytest

```
197 passed in 158.72s
TOTAL 1723 statements, 198 missing, 89% coverage
```

### ruff

```
All checks passed!
94 files already formatted
```

### mypy

```
Success: no issues found in 30 source files
```

### CLI output — real scan (fixture server)

```
Scan complete - 127.0.0.1
Target           127.0.0.1 - http://127.0.0.1:9999
Posture          4.0 / 100 - F
HIGH findings    0
MEDIUM findings  4
LOW findings     4
INFO findings    3
Checks run       7
Skipped          none

Sev   Rule     Title                                       Where
medium HDR-001 Missing security header: Strict-Transpo… Header not present in the HT…
medium HDR-002 Missing security header: Content-Securi… Header not present in the HT…
medium HDR-003 Missing security header: X-Frame-Optio… Header not present in the HT…
low    HDR-004 Missing security header: X-Content-Typ… Header not present in the HT…
… and 7 more - see the report
Reports written to inspectra-report
```

### CLI output — --quiet

```
Scan complete - 127.0.0.1
Target           127.0.0.1 - http://127.0.0.1:9999
Posture          4.0 / 100 - F
HIGH findings    0
MEDIUM findings  4
LOW findings     4
INFO findings    3
Checks run       7
Skipped          none
Reports written to inspectra-report
```

### inspectra --help

```
usage: inspectra [-h] [--version] {scan} ...

Open-source explainable security assessment framework. Inspect. Observe.
Assess. Explain. Report. Never exploit.

options:
  -h, --help            show this help message and exit
  --version             show program's version number and exit

subcommands:
  Available commands:
    {scan}              Run a security assessment against a target.
```

### inspectra scan --help

```
usage: inspectra scan [-h] [--ports PORTS] [--top-ports N]
                      [--skip-ports] [--directories]
                      [--directory-wordlist PATH] [--concurrency N]
                      [--delay SECONDS] [--rules-dir PATH]
                      [--list-checks] [--format FORMAT] [-o PATH]
                      [--output-dir DIR] [--save-baseline PATH]
                      [--baseline PATH] [--save-fixtures DIR]
                      [--replay DIR] [--no-findings]
                      [--findings-limit N] [--quiet] [--yes]
                      [--verbose] [--fail-on LEVEL] [--allow-private]
                      [--authorized] [--no-redact]
                      target

positional arguments:
  target                Domain, IP address or URL to assess (e.g. example.com).

TARGET:
  target                Domain, IP address or URL to assess (e.g. example.com).

WHAT TO RUN:
  --ports PORTS         PORTS comma-separated port list for Nmap (e.g. 80,443,8080).
  --top-ports N         N scan the N most common ports with Nmap (default: 1000).
  --skip-ports          Skip Nmap port discovery (useful when Nmap is not installed).
  --directories         Probe a curated wordlist of common paths (rate-limited, GET-only).
  --directory-wordlist PATH
                        PATH custom wordlist for --directories (one path per line, # comments allowed).
  --concurrency N       N max concurrent checks per target (default: 4).
  --delay SECONDS       SECONDS delay between per-host requests (default: 0.2).
  --rules-dir PATH      PATH load custom checks from this directory (repeatable).
  --list-checks         Print every built-in and loaded check with ID, title, and source.

OUTPUT:
  --format FORMAT       FORMAT html | json | markdown | sarif (default: html).
  -o PATH               PATH write a single-format report to this exact path (requires a single format).
  --output-dir DIR      DIR directory for reports (default: inspectra-report/).
  --save-baseline PATH  PATH write baseline fingerprint file to PATH after scanning.
  --baseline PATH       PATH compare against a baseline file; only new findings count toward fail-on.
  --save-fixtures DIR   DIR record every HTTP request/response to DIR for later replay.
  --replay DIR          DIR replay all HTTP requests from DIR fixtures (offline, no network).
  --no-findings         Suppress the findings table (summary panel still prints).
  --findings-limit N    N max findings to print in the terminal table (default: 25).
  --quiet               Print the summary panel and counts only (CI logs).

SAFETY:
  --yes                 Accept the authorization agreement without prompting.
  --verbose             Enable debug logging.
  --fail-on LEVEL       LEVEL exit non-zero when findings at or above this severity exist: none|low|medium|high (default: high).
  --allow-private       Allow scanning private/loopback/local addresses (home-lab only).
  --authorized          Required with --allow-private; confirms explicit authorization.
  --no-redact           Disable secret redaction in evidence (debug only).
```

### epilog examples

```
Examples:
  inspectra scan https://example.com --yes
  inspectra scan https://example.com --format sarif --fail-on high
  inspectra scan --replay evidence.jsonl
```

## P10 — Accuracy

### python -m benchmarks.accuracy --all --min-in-scope-recall 0.95

```
| Target | In-scope expected | Found | Missed | FP | Recall | Deterministic |
|--------|-------------------|-------|--------|----|--------|---------------|
| target1 | 1 | 1 | 0 | 0 | 100% | YES |
| target2 | 1 | 1 | 0 | 0 | 100% | YES |
| target3 | 1 | 1 | 0 | 0 | 100% | YES |
| target6 | 1 | 1 | 0 | 0 | 100% | YES |
| target9 | 0 | 0 | 0 | 0 | 100% | YES |
| target10 | 1 | 1 | 0 | 0 | 100% | YES |
| target11 | 1 | 1 | 0 | 0 | 100% | YES |
| target12 | 1 | 1 | 0 | 0 | 100% | YES |
```

Overall: in-scope recall=100.0%, precision=100.0%, FP=0, deterministic=YES
PASS: accuracy gate met

Platform-limited targets (excluded from recall): target4, target5 (cannot
generate self-signed certs on Windows), target7, target8 (/app paths not
available on Windows).

### test_docs_accuracy_matches_json

PASS — docs/accuracy.md matches benchmarks/accuracy.json.

## P11 — Portability

Port check raises `CheckError` (not `FatalCheckError`) when nmap is missing.
Scan continues, ports reported as skipped, exit code 0.
Install paths: `pip install inspectra-cli` (no Nmap) or
`pip install inspectra-cli[ports]` (with Nmap).

## P12 — Extension point

All 9 named tests pass:
- test_custom_check_loads_and_reports
- test_missing_attribute_error_is_actionable
- test_duplicate_rule_id_rejected
- test_list_checks_includes_custom
- test_custom_check_appears_in_sarif
- test_rules_dir_not_found_errors
- test_check_not_callable_rejected
- test_custom_check_run_failure
- test_import_failure_in_custom_check

## P13 — Release 2.3.0

### Version
- `src/inspectra/__init__.py`: `__version__ = "2.3.0"`
- `pyproject.toml`: `requires-python = ">=3.10"`, `target-version = "py310"`,
  `mypy python_version = "3.10"`, classifier `Programming Language :: Python :: 3.10`

### Commits
- `59e3f98` assets(rebuild): legible SVG assets at 2x display scale
- `9cb9b5c` cli: print findings table in terminal, add --no-findings/--findings-limit/--quiet
- `075e3d3` chore(format): ruff formatting fixes
- `bdb6d04` ext: add --rules-dir and --list-checks extension point

### Tags
- `v2.2.0` → pushed to origin
- `v2.3.0` → pushed to origin

### Releases
- `v2.1.0`, `v2.1.1`, `v2.2.0`, `v2.3.0` all exist on GitHub; only v2.3.0 is Latest

### PyPI publish
- Triggered by OIDC release workflow on tag push
- Verified: https://pypi.org/pypi/inspectra-cli/json → version 2.3.0

## P14 — Repo surface

- Description: "Passive security assessment for authorized targets: deterministic findings, evidence hashes, SARIF for CI."
- Homepage: https://pypi.org/project/inspectra-cli/
- Topics: cli, devsecops, python, sarif, security, static-analysis, vulnerability-scanner
- Social preview: assets/social-preview.png uploaded to GitHub

## P15 — Adoption scaffolding

- 5 issues created (all labelled "good first issue"):
  - #1 Add HSTS preload check
  - #2 Add HTTP/3 detection
  - #3 Add SARIF rule help URLs
  - #4 Add --config file support
  - #5 Add Windows install notes
- docs/adoption.md: 90-second demo script, asciinema recipe, 4 announcement drafts

## P16 — Release 2.3.1

### Version
- `src/inspectra/__init__.py`: `__version__ = "2.3.1"`
- `pyproject.toml`: `requires-python = ">=3.10"`, `target-version = "py310"`,
  `mypy python_version = "3.10"`, classifier `Programming Language :: Python :: 3.10`

### Commits
- `SECTION-A-D` fixes: allow-insecure, fingerprint nginx, verbose errors, accuracy benchmark
- `SECTION-E` channels: action.yml branding, pre-commit hooks
- `SECTION-F` surface: repo topics, homepage, description, social preview
- `SECTION-G` adoption: 5 issues, docs/adoption.md

### Tags
- `v2.3.1` → pushed to origin

### Releases
- `v2.1.0`, `v2.1.1`, `v2.2.0`, `v2.3.0`, `v2.3.1` all exist on GitHub; only v2.3.1 is Latest

### PyPI publish
- Triggered by OIDC release workflow on tag push
- Verified: https://pypi.org/pypi/inspectra-cli/json → version 2.3.1

