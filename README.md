<p align="center">
  <img src="https://raw.githubusercontent.com/shashu123456/Inspectra/main/assets/logo-mark.svg" width="64" alt="Inspectra logo">
  <img src="https://raw.githubusercontent.com/shashu123456/Inspectra/main/assets/wordmark.svg" width="300" alt="Inspectra">
</p>

<img src="https://raw.githubusercontent.com/shashu123456/Inspectra/main/assets/banner-light.svg" width="100%" alt="Inspectra banner">

Inspectra performs passive security assessment for authorized targets.
You get a posture score, a findings table with rule IDs, and SARIF output for CI.

```
$ inspectra scan http://127.0.0.1:9999 --yes --skip-ports --allow-private --authorized
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

## Quick start

```bash
pip install inspectra-cli
```

```bash
inspectra scan http://127.0.0.1:9999 --yes --skip-ports --allow-private --authorized --format html
```

```bash
open inspectra-report/report.html
```

## What it checks

| Check | What it looks for | Example rule IDs |
|-------|-------------------|------------------|
| DNS | DNS resolution and IP pinning | DNS-001 |
| TLS | Certificate expiry, self-signed, protocol versions | TLS-001 |
| HTTP | Server disclosure, error states, redirects | HTP-003 |
| Headers | Missing or weak security headers | HDR-001 |
| Robots | Disallowed paths in robots.txt | ROB-002 |
| Directories | Exposed common paths | DIR-001 |
| Ports | Open ports from Nmap discovery | PRT-003 |

## How it works

<img src="https://raw.githubusercontent.com/shashu123456/Inspectra/main/assets/architecture.svg" width="100%"/>

1. Safety gate resolves DNS once and pins the IP.
2. Checks run with per-host rate limiting and concurrency bounds.
3. Each finding carries a rule ID, severity, title, and evidence hash.
4. Severity times confidence yields a posture score and grade.
5. Reports serialize to JSON, Markdown, HTML, or SARIF.

## Use in CI

```yaml
- run: inspectra scan https://example.com --yes --skip-ports --format sarif -o inspectra.sarif --fail-on high
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: inspectra.sarif
```

## Baselines

```bash
inspectra scan https://example.com --yes --skip-ports --save-baseline baseline.json
inspectra scan https://example.com --yes --skip-ports --baseline baseline.json --fail-on high
```

Compare two scans and fail the run when new findings appear.

## Output

| Format | Flag | Purpose |
|--------|------|---------|
| JSON | `--format json` | Machine-readable, stable schema |
| Markdown | `--format markdown` | Human-readable report |
| HTML | `--format html` | Self-contained, polished report |
| SARIF | `--format sarif` | CI pipelines and code scanning |

## Scope

| Not supported | Reason |
|---------------|--------|
| Exploitation | Passive GET-only assessment, no payloads |
| Credential cracking | Out of scope for a passive scanner |
| Vulnerability chaining | Findings are reported, not chained |
| Unauthorized targets | Consent gate is required before scanning |
| Authentication bypass | Observes what a target willingly exposes |

## Safety

- SSRF blocking: DNS resolved once, IP pinned, private addresses blocked by default.
- Consent gate: `--yes` or persisted agreement required before any scan runs.
- Redaction: secrets and header values redacted before reports serialize.
- evidence_hash: SHA-256 of each finding's evidence, stored on every finding.

See [THREAT_MODEL.md](THREAT_MODEL.md).

## Proof

Accuracy is measured against 12 lab targets with hand-audited ground truth.
Results: 100% in-scope recall (49/49), 100% precision, 0 false positives,
deterministic across 3 runs per target. See [docs/accuracy.md](docs/accuracy.md)
for the full table and methodology.

## Contributing

Contributions are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

[MIT](LICENSE) — © 2026 Inspectra contributors.
