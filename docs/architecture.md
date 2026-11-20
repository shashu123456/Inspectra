# Architecture

Inspectra is a single-pass CLI with explicit stages. Each stage has one job and passes typed models to the next.

```text
Target → Authorize → Resolve & pin → Checks → Findings → Risk → Reports
```

## 1. Authorize

`cli.py` parses the target and scope. `--yes` is an explicit acknowledgement; without it, a consent prompt is shown. Private and loopback addresses require `--allow-private`.

## 2. Resolve and pin

`network.py` resolves DNS once, pins the IP and reuses it for every request. The client is GET-only, redacts secrets, enforces timeouts and rate limits. An SSRF guard rejects private ranges unless explicitly allowed.

## 3. Checks

`checks/` contains small, independent modules:

- `dns.py` — resolution records
- `tls.py` — certificate expiry, self-signed and protocol checks
- `http.py` — cached primary response, status, redirects, server disclosure
- `headers.py` — security header presence
- `robots.py` — disallowed paths in `robots.txt`
- `directories.py` — optional common-path probes
- `ports.py` — optional Nmap-based open ports
- `fingerprint.py` — technology signals from cached responses
- `loader.py` — custom check discovery

Checks run with bounded concurrency and per-host politeness. A missing Nmap binary degrades gracefully.

## 4. Findings

`models.py` defines `Finding` with rule ID, title, category, severity, confidence, description, why-it-matters, evidence, recommendation, fingerprint and `evidence_hash`. Findings are merged deterministically.

## 5. Risk

`analysis/` computes severity × confidence, the 0–100 posture score and the letter grade.

## 6. Reports

`report/` contains four thin renderers:

- `json_report.py` — stable machine-readable schema
- `markdown_report.py` — human-readable Markdown
- `html_report.py` — self-contained HTML
- `sarif_report.py` — SARIF for CI/code-scanning upload

Baselines are compared at this stage: `--save-baseline` writes a snapshot; `--baseline` emits only new findings.

## Extension points

- Custom checks via `checks/loader.py`
- Replay fixtures via `replay.py`
- Pre-commit hook via `precommit.py`

See [results](RESULTS.md), [accuracy](accuracy.md) and the [pipeline diagram](../assets/architecture.svg).
