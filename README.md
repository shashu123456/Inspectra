<div align="center">

# 🔍 Inspectra

**An Open-Source Explainable Security Assessment Framework**

*Inspect. Observe. Assess. Explain. Report. **Never exploit.***

[![CI](https://img.shields.io/badge/CI-github--actions-blue)](.github/workflows/ci.yml)
[![Python](https://img.shields.io/badge/python-3.11%2B-blue)](pyproject.toml)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Code style: ruff](https://img.shields.io/badge/code%20style-ruff-261230)](pyproject.toml)
[![Checked with mypy](https://img.shields.io/badge/types-mypy-blue)](pyproject.toml)

</div>

---

## ⚠️ Authorized Use Only

Inspectra is a **passive** assessment tool. It observes what a system
willingly reveals and explains what it means. It never exploits, never
brute-forces, and never sends attack payloads. **Scan only systems you own
or are explicitly authorized to test** — unauthorized scanning may be
illegal in your jurisdiction. See [docs/safety.md](docs/safety.md).

## Why Inspectra?

Most scanners dump raw output and leave the thinking to you. Inspectra is
built around **explainability**: every finding answers

| | |
|---|---|
| **What was observed** | the raw observation |
| **Why it matters** | the security reasoning, in plain language |
| **Evidence** | the data behind the observation |
| **Confidence** | how sure the tool is (low / medium / high) |
| **Severity** | info / low / medium / high |
| **Recommendation** | a concrete next step |

plus a **posture score** (0–100 with a letter grade) so you can measure
improvement: scan → fix → re-scan → watch the score rise.

## Features (v1.0.0)

- ✅ Target validation with normalization (domain, IP, URL)
- ✅ First-run authorization gate, persisted consent
- ✅ DNS resolution & record analysis (A/AAAA/CNAME/MX/NS/TXT)
- ✅ Port discovery via Nmap (top-1000 default, `--ports` / `--skip-ports`)
- ✅ HTTP analysis: redirects, error states, server disclosure
- ✅ TLS verification: expiry, self-signed, hostname mismatch, protocol versions
- ✅ Security header assessment (9 rules: HSTS, CSP, X-Frame-Options, …)
- ✅ Technology fingerprinting (24 curated signatures)
- ✅ robots.txt inspection (disallowed paths, sitemaps)
- ✅ Opt-in directory observation (rate-limited, GET-only, curated wordlist)
- ✅ Evidence capture on every finding
- ✅ Risk engine: severity × confidence → posture score & grade
- ✅ Reports: **Markdown** (default), **HTML** (self-contained, polished), **JSON**
- ✅ Exit codes for CI: 0 clean · 1 findings · 2 error

## Quick Start

```bash
pip install inspectra          # or: pip install -e ".[dev]" from a clone
inspectra scan example.com --format html
```

First run shows the authorization agreement (accepted once, then
remembered). Reports land in `./inspectra-report/`:

```
inspectra-report/
├── report.html   (or report.md)
├── report.json
└── inspectra.log
```

All report timestamps are displayed in **Indian Standard Time**
(`Asia/Kolkata`, UTC+05:30).

### Live demo (no install needed to look around)

```bash
python demo/server.py
# open http://127.0.0.1:9000/api/demo-page
```

The demo hosts a harmless, deliberately misconfigured fixture site and a
page that runs **real Inspectra scans** against it, rendering findings
in-browser with links to the full HTML/Markdown/JSON reports.

<details>
<summary><strong>Installing Nmap (recommended)</strong></summary>

Port discovery uses [Nmap](https://nmap.org). Without it, run with
`--skip-ports`.

| OS | Command |
|----|---------|
| Debian/Ubuntu | `sudo apt install nmap` |
| Fedora | `sudo dnf install nmap` |
| macOS | `brew install nmap` |
| Windows | [nmap.org/download.html](https://nmap.org/download.html) (enable "Add to PATH") |

</details>

## Example

```console
$ inspectra scan <fixture-target> --yes --skip-ports --format html
Scan complete — 127.0.0.1
┌───────────────┬───────┐
│ Severity      │ Count │
├───────────────┼───────┤
│ HIGH          │ 0     │
│ MEDIUM        │ 4     │
│ LOW           │ 4     │
│ INFO          │ 5     │
│ Posture score │ 4.0 / 100 (F) │
└───────────────┴───────┘
Reports written to …/inspectra-report
```

(Transcript from the committed sample: a deliberately misconfigured
fixture site — hence the F grade. See
[`examples/sample-report/`](examples/sample-report/).)

A full sample — `report.md`, `report.html` and `report.json` — is committed
under [`examples/sample-report/`](examples/sample-report/).

## Architecture in 30 Seconds

```
CLI ─▶ Orchestrator ─▶ [8 check modules] ─▶ Risk Engine ─▶ Reporters
```

Eight independent checks (dns · ports · http · tls · headers ·
fingerprint · robots · directories) share one data contract (`models.py`)
and one scan context; the risk engine scores findings by severity ×
confidence; three renderers turn the result into reports. Adding a check is
one new file plus one registry line — see
[CONTRIBUTING.md](CONTRIBUTING.md) and
[docs/architecture.md](docs/architecture.md).

## Project Layout

```
inspectra/
├── src/inspectra/          # the tool (one package, one responsibility per file)
│   ├── cli.py              # argparse, consent gate, exit codes
│   ├── orchestrator.py     # runs checks, builds ScanResult
│   ├── models.py           # Target / Finding / Severity / Confidence / ScanResult
│   ├── network.py          # httpx client + TLS inspection
│   ├── checks/             # 8 assessment modules + registry
│   ├── analysis/           # risk engine + recommendation helpers
│   ├── report/             # json / markdown / html renderers
│   └── data/               # versioned rules, fingerprints, wordlist
├── tests/                  # pytest suite (local fixture server, no internet)
├── demo/                   # live demo: fixture site + in-browser scan UI
├── docs/                   # architecture, usage, safety, roadmap
├── examples/sample-report/ # committed sample output (md + html + json)
└── scripts/                # report-regeneration helper
```

## Technologies

| | |
|---|---|
| [httpx](https://www.python-httpx.org/) | HTTP client (timeouts, redirect control) |
| [dnspython](https://www.dnspython.org/) | DNS record resolution |
| [python-nmap](https://pypi.org/project/python-nmap/) | Nmap integration for port discovery |
| [cryptography](https://cryptography.io/) | X.509 certificate parsing |
| [rich](https://rich.readthedocs.io/) | Terminal UI: progress, colours, summary tables |
| [Jinja2](https://jinja.palletsprojects.com/) | HTML report templating |
| pytest · mypy · ruff | Test suite, strict type checking, lint + format |

## Development

```bash
git clone <repository-url> && cd inspectra
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
ruff check . && ruff format --check . && mypy && pytest
```

## Documentation

| Document | Purpose |
|----------|---------|
| [docs/architecture.md](docs/architecture.md) | The single source of truth for the design |
| [docs/usage.md](docs/usage.md) | CLI reference, options, examples |
| [docs/safety.md](docs/safety.md) | Ethics, legal guidance, authorized-use checklist |
| [docs/roadmap.md](docs/roadmap.md) | Release history and future direction (planning only) |
| [CHANGELOG.md](CHANGELOG.md) | Notable changes per release |
| [CONTRIBUTING.md](CONTRIBUTING.md) | How to add a check |

## Roadmap

V1 is feature-frozen by design; every future idea lives in
[`docs/roadmap.md`](docs/roadmap.md). Highlights for v2:
async engine, plugin system, cookie/CORS checks, passive subdomain
enumeration via certificate transparency, and a read-only web dashboard.

## License

[MIT](LICENSE) — © 2026 Inspectra contributors.

## Disclaimer

Inspectra is provided "as is", without warranty of any kind. You are solely
responsible for ensuring your use of the tool is legal and authorized.
