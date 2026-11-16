# Inspectra v2.0.0

## What's New

- **SSRF-safe target validation** with DNS rebinding protection, CGNAT blocking, and per-redirect-hop re-validation
- **Deterministic replay** with `--save-fixtures`/`--replay` flags — record scans once, replay offline forever
- **Evidence redaction** — secrets, JWTs, and header values redacted before any report serialization
- **Benchmark suite** — 12 deliberately misconfigured targets with 75% detection rate, 0 false positives

## Install

```bash
# From TestPyPI (current)
pip install -i https://test.pypi.org/simple/ inspectra-cli

# Install with both command names
inspectra --version          # 2.0.0
inspectra-cli --version      # 2.0.0
```

## Quick Start

```bash
# Scan a target (use --allow-private --authorized for localhost/home-lab)
inspectra scan https://example.com --format json -o report.json

# Record datasets for offline replay
inspectra scan https://example.com --save-fixtures ./fixtures --yes --allow-private --authorized

# Replay from disk (zero network I/O)
inspectra scan https://example.com --replay ./fixtures --format json -o report.json
```

## Benchmark Results

| Metric | Value |
|--------|-------|
| Targets scanned | 12 |
| Total findings | 84 |
| Overall detection rate | 75.0% |
| False positives | 0 |
| P95 runtime | ~8.6s per target |

See [benchmark results](https://github.com/shashu123456/Inspectra/blob/main/docs/benchmark.md) for full details.

## Live Demo

[View sample report on GitHub Pages](https://shashu123456.github.io/Inspectra/)

---

**This is inspectra-cli.** An unrelated package named `inspectra` exists on PyPI (an AI code-review tool). Installing this project provides the `inspectra` and `inspectra-cli` commands.