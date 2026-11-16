# Inspectra — Benchmark Results

**Generated:** 2026-11-16  
**Scanner:** Inspectra v2.0.0 (M5: bounded concurrency + per-host politeness)  
**Environment:** Localhost, Python 3.11.9, Windows  
**Scan mode:** Passive, `--skip-ports --allow-private --authorized`

## Benchmark method

Two modes were compared against the same committed replay fixtures
(`tests/fixtures/replay`, served from disk, zero network I/O):

- **Serial:** `--concurrency 1 --delay 0`
- **Concurrent:** `--concurrency 8 --delay 0`

Each mode ran 5 fixture replays; wall time below is report assembly only.

## M5 concurrency / politeness result (fixture-based)

| Mode | Runs | Avg wall (s) | Findings | Reports identical |
|---|---:|---:|---:|---|
| Serial (`--concurrency 1 --delay 0`) | 5 | 0.103 | 9 | yes |
| Concurrent (`--concurrency 8 --delay 0`) | 5 | 0.023 | 9 | yes |

**Live lab spot check (target1, port 8001):** started `lab/targets/target1/server.py`, ran
`inspectra scan http://127.0.0.1:8001/ --yes --skip-ports --allow-private --authorized --format json`
with `--concurrency 1 --delay 0` and `--concurrency 8 --delay 0`, then stopped exactly the server
process and verified no lab process remained (`Get-Process python*` showed the target1 pid gone).
Concurrency 1 → `['HDR-001','HTP-003','TLS-001']`; concurrency 8 → `['HDR-001','HTP-003','TLS-001']`;
findings **identical**, exit code 0 both modes. Full 12-target live timed run could not complete in
this sandbox (command duration limits); the table below is therefore the fixture-based record.

> Fixture-based (committed replay data, no network). Measures report assembly only — it does not
> measure network politeness or real-target wall time.
>
> No speedup percentage is reported from fixture data. No performance claim is made in the README.

| Mode | Runs | Avg wall (s) | Findings | Identical (yes/no) | False positives |
|---|---:|---:|---:|---|---:|
| Serial | 5 | 0.103 | 9 | yes | 0 |
| Concurrent | 5 | 0.023 | 9 | yes | 0 |

## Notes

- Concurrency affects report-assembly timing on committed fixtures; it does **not** change findings,
  severity, rule IDs, or evidence hashes (deterministic merge + sort).
- Per-host politeness cap is max 2 in-flight requests regardless of `--concurrency`.
- `--delay` (default 0.2s) is applied per host between requests, sleeping outside the host lock.
