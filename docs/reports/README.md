# Inspectra sample reports

Generated from **authorized local lab targets** (hosted under `lab/targets/*/server.py`)
as part of the M5 closeout. Each report was produced by a real `inspectra scan`
against a target I own/authorize; no third-party sites were scanned.

Commit: `5a0df0e docs(benchmark): measurement table, replay scope, runbook status`
Date: 2026-11-16

| Report | Target | Port | Command |
|--------|--------|------|---------|
| `target1.*` | Missing HSTS header | 8001 | `inspectra scan http://127.0.0.1:8001/ --yes --skip-ports --allow-private --authorized --format <fmt>` |
| `target2.*` | Missing CSP header | 8002 | `inspectra scan http://127.0.0.1:8002/ --yes --skip-ports --allow-private --authorized --format <fmt>` |
| `target3.*` | Missing X-Frame-Options header | 8003 | `inspectra scan http://127.0.0.1:8003/ --yes --skip-ports --allow-private --authorized --format <fmt>` |

Formats: `html` (self-contained), `json` (machine-readable), `sarif` (SARIF 2.1.0).

**Authorization note:** All scans below were run against targets I own (local lab fixtures),
with `--authorized` and `--allow-private` explicitly passed. No third-party sites were scanned.
