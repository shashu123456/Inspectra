# Inspectra results

All numbers below are recorded from repository runs. Nothing here depends on public users, downloads or third-party endorsements.

## Accuracy

Source: [docs/accuracy.md](accuracy.md).

| Metric | Value | Meaning |
|--------|-------|---------|
| In-scope recall | 49/49 (100%) | Every expected in-scope finding was emitted |
| Precision | 100% | All emitted findings were in scope |
| Emitted findings | 58 | Total across measured workspaces |
| Justified absences | 9 | Expected-but-absent cases documented with reason |
| Unexplained false positives | 0 | No unexplained emitted findings |
| Deterministic | Yes | Identical results across 3 runs per target |
| Measured targets | 8 | `target1`, `2`, `3`, `6`, `9`, `10`, `11`, `12` |

Four lab targets are present but **not measured on this platform** (TLS handshake and path fixtures are unreliable on Windows). They are excluded from all figures above.

## Performance

Source: [docs/benchmark.md](benchmark.md). Generated 2026-11-16 on localhost, Python 3.11.9, Windows, with `--skip-ports --allow-private --authorized`.

| Scenario | Serial | Concurrent | Identical reports |
|----------|--------|------------|-------------------|
| Fixture replay (average per target) | 0.103 s | 0.023 s | Yes |
| Live `target1` spot check | same | same | Yes — `HDR-001`, `HTP-003`, `TLS-001` |

The full 12-target live timed run could **not** be completed in the sandbox, so no aggregate live speedup is claimed.

## Test suite

Verified locally on 2026-11-21:

```text
220 passed in 151.15s (0:02:31)
TOTAL    1771 statements    196 missed    89%
```

## Sample finding

From [docs/reports/target1.json](reports/target1.json), recorded with `inspectra` v2.0.0:

```json
{
  "rule_id": "HDR-001",
  "title": "Missing security header: Strict-Transport-Security",
  "severity": "medium",
  "confidence": "medium",
  "evidence": ["Header not present in the HTTP response"],
  "evidence_hash": "42f70c2ac6396335"
}
```

Full report: [target1.json](reports/target1.json). Rendered HTML: [target1.html](reports/target1.html).

## Sample CLI output

```text
Target   http://127.0.0.1:8001
Posture  61.6 / 100 - D
Summary  3 findings · 0 high · 2 medium · 0 low · 1 info

medium  HDR-001  Missing security header: Strict-Transport-Security
info    HTP-003  Web server software disclosed (with version)
medium  TLS-001  HTTPS not available

Reports written to inspectra-report
```

## Reports produced

| Format | File | Notes |
|--------|------|-------|
| JSON | `inspectra-report/report.json` | Stable schema, evidence hashes included |
| HTML | `inspectra-report/report.html` | Self-contained, no external assets |
| Markdown | `inspectra-report/report.md` | Human-readable summary |
| SARIF | `inspectra-report/report.sarif` | CI/code-scanning upload |

## Release and CI

- PyPI: [`inspectra-cli` v2.3.6](https://pypi.org/project/inspectra-cli/)
- CI: [`.github/workflows/ci.yml`](../.github/workflows/ci.yml)
- Documented release workflow runs (from the master handoff): CI `44602078722`, Docker `44602207462`, Release `44602207465`.

## Health endpoint

Inspectra is a local CLI, not a hosted service. There is no API health endpoint and no health link is included. Readiness is demonstrated by the passing CI workflow, the test suite and the sample reports above.
