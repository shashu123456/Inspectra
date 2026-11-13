# Inspectra — Usage Guide

## Installation

```bash
pip install inspectra
```

From source:

```bash
git clone <repository-url>
cd inspectra
pip install -e ".[dev]"
```

### Installing Nmap (recommended)

Port discovery uses [Nmap](https://nmap.org). Without it, run with
`--skip-ports`.

| OS | Command |
|----|---------|
| Debian/Ubuntu | `sudo apt install nmap` |
| Fedora | `sudo dnf install nmap` |
| macOS | `brew install nmap` |
| Windows | Download from <https://nmap.org/download.html> and enable "Add to PATH" |

## Quick Start

```bash
# First run shows the authorization agreement (accepted once, then remembered)
inspectra scan example.com
```

Output lands in `./inspectra-report/`:

| File | Purpose |
|------|---------|
| `report.md` | Human-readable Markdown report (default) |
| `report.json` | Machine-readable results for tooling |
| `inspectra.log` | Structured scan log |

Timestamps in all human-facing reports are shown in **Indian Standard Time**
(`Asia/Kolkata`, UTC+05:30, e.g. `2026-09-08 18:24:53 IST`). The JSON report
additionally stores the raw UTC ISO-8601 timestamps (`started_at`) alongside
the display value (`started_at_ist`), so tooling stays timezone-safe.

## Live demo

A self-contained demo server hosts a harmless, deliberately misconfigured
fixture site and a page that runs **real scans** against it:

```bash
.venv\Scripts\python demo\server.py
# then open http://127.0.0.1:9000/api/demo-page
```

`GET /api/scan` runs a real scan and returns the JSON report;
`/api/report/html`, `/api/report/md` and `/api/report/json` serve the last
scan's reports.

## Command Reference

```
inspectra scan TARGET [options]
```

| Option | Description |
|--------|-------------|
| `--format {markdown,html}` | Human-readable report format (default: `markdown`) |
| `--output-dir DIR` | Report directory (default: `inspectra-report/`) |
| `--ports 80,443,8080` | Explicit port list for Nmap |
| `--top-ports N` | Scan the N most common ports (default: 1000) |
| `--skip-ports` | Skip port discovery (no Nmap required) |
| `--directories` | Probe a curated wordlist of common paths (rate-limited, GET-only) |
| `--directory-wordlist FILE` | Use a custom wordlist with `--directories` |
| `--yes` | Accept the authorization agreement without prompting |
| `--verbose` | Enable debug logging |
| `inspectra --version` | Show the version |

## Examples

Assess a site and get a polished HTML report:

```bash
inspectra scan example.com --format html
```

Assess a home-lab device with an explicit port list:

```bash
inspectra scan 192.168.1.1:8443 --ports 80,443,8443
```

Skip port discovery (Nmap not installed):

```bash
inspectra scan example.com --skip-ports
```

Opt-in directory observation with a custom wordlist:

```bash
inspectra scan example.com --directories --directory-wordlist my-paths.txt
```

## Reading the Report

Every finding follows the same structure:

* **What was observed** — the raw observation.
* **Why it matters** — the security reasoning, in plain language.
* **Evidence** — the data the observation is based on.
* **Confidence** — how sure Inspectra is (low / medium / high).
* **Severity** — info, low, medium or high.
* **Recommendation** — a concrete next step.

The **posture score** (0–100 with a letter grade) weights severity by
confidence. Re-run after fixes to watch the score improve — that loop is the
point of the tool.

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | Scan completed, no actionable findings |
| `1` | Scan completed, findings present |
| `2` | Scan failed or authorization declined |

## Deterministic Replay (M4)

Record every HTTP request/response to a fixtures directory, then replay scans
entirely from disk with zero network I/O. Two runs against the same fixtures
produce byte-identical reports (modulo timestamps), so CI can diff scans and
detect regressions without touching the network.

```bash
# Record all HTTP traffic to a fixtures directory
inspectra scan example.com --save-fixtures ./my-fixtures

# Replay from recorded fixtures (offline — no network)
inspectra scan example.com --replay ./my-fixtures --format json
```

`--save-fixtures` and `--replay` are mutually exclusive. `--replay` implies
offline mode: no sockets are opened, no DNS lookups are made, and checks that
require raw sockets (DNS, port discovery, TLS) are skipped.

### Replay in CI

Commit a fixture set to your repository and replay it on every push:

```bash
# Record once (locally)
inspectra scan https://example.com --save-fixtures tests/fixtures/replay

# Replay in CI (no network)
inspectra scan https://example.com --replay tests/fixtures/replay --format json > report.json
diff report.json report.json.prev  # empty = no regression
```

## Safety Notes

Inspectra performs **passive** assessment only. It never exploits, never
brute-forces, never sends attack payloads, and rate-limits the opt-in
directory check. Only scan systems you own or are explicitly authorized to
test — see [safety.md](safety.md).
