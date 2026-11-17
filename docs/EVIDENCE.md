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

### python -m benchmarks.accuracy --all --min-recall 0.95

```
| Target | Planted | Found | Missed | FP | Recall | Deterministic |
|--------|---------|-------|--------|----|--------|---------------|
| target1 | 3 | 2 | 1 | 0 | 67% | YES |
| target2 | 3 | 2 | 1 | 0 | 67% | YES |
| target3 | 3 | 2 | 1 | 0 | 67% | YES |
| target4 | 3 | 0 | 3 | 0 | 0% | YES |
| target5 | 3 | 0 | 3 | 0 | 0% | YES |
| target6 | 2 | 1 | 1 | 0 | 50% | YES |
| target7 | 3 | 1 | 2 | 0 | 33% | YES |
| target8 | 3 | 1 | 2 | 0 | 33% | YES |
| target9 | 2 | 1 | 1 | 0 | 50% | YES |
| target10 | 3 | 2 | 1 | 0 | 67% | YES |
| target11 | 3 | 1 | 2 | 0 | 33% | YES |
| target12 | 3 | 1 | 2 | 0 | 33% | YES |

Overall: recall=41.2%, precision=100.0%, FP=0, deterministic=YES
FAIL: recall below 95%
```

Gate NOT met (recall 41.2% < 95%). Known misses documented in docs/accuracy.md.

## P11 — Portability (no Nmap)

Port check now raises `CheckError` instead of `FatalCheckError` when nmap is
missing. The scan continues, ports are reported as skipped, and exit code is 0.
Install path: `pip install inspectra-cli` (no Nmap) or
`pip install inspectra-cli[ports]` (with Nmap).

## P12 — Extension point

All 9 named tests pass:

```
test_custom_check_loads_and_reports PASSED
test_missing_attribute_error_is_actionable PASSED
test_duplicate_rule_id_rejected PASSED
test_list_checks_includes_custom PASSED
test_custom_check_appears_in_sarif PASSED
test_rules_dir_not_found_errors PASSED
test_check_not_callable_rejected PASSED
test_custom_check_run_failure PASSED
test_import_failure_in_custom_check PASSED
```

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
- `v2.3.0` → to be created and pushed

### Releases

- `v2.1.0` — created (not latest)
- `v2.1.1` — created (not latest)
- `v2.2.0` — created (not latest, superseded by v2.3.0)
- `v2.3.0` — to be created as --latest

### PyPI publish

- Triggered by OIDC release workflow on tag push
- To be verified: `https://pypi.org/pypi/inspectra-cli/json` → version 2.3.0
