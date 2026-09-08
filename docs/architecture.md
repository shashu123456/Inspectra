# Inspectra — Architecture

> *"An Open-Source Explainable Security Assessment Framework."*
> Inspect. Observe. Assess. Explain. Report. **Never exploit.**

This document is the single source of truth for Inspectra's design. Keep it
current when the architecture changes; the documents in
[`roadmap/`](roadmap/) are planning-only and never affect the V1 codebase.

## 1. Product Vision

Inspectra is a single-command CLI tool that performs safe, passive security
assessments on authorized targets and produces professional, **explainable**
reports. Its differentiator is explainability: every finding answers five
questions — *What was observed? Why does it matter? What is the evidence?
How confident are we? What should I do about it?*

The audience is students, junior security engineers, developers, small teams
and home-lab users. The emphasis is understanding, not raw scan output.

## 2. High-Level Architecture

A linear pipeline with a registry — deliberately simple:

```
CLI ─▶ Orchestrator ─▶ [check modules] ─▶ Risk Engine ─▶ Reporters
```

* **models.py** — `Target`, `Finding`, `Severity`, `Confidence`,
  `ScanResult`, `ScanOptions`, `ScanMetadata` dataclasses. This is the
  shared contract every module works against.
* **checks/** — one module per assessment area. Each exposes
  `run(target, context) -> list[Finding]` and registers in
  `checks/__init__.py`. The orchestrator iterates the registry in order.
* **analysis/** — `risk.py` applies the severity × confidence rubric and
  computes the posture score; `recommendations.py` holds shared advice text.
* **report/** — three thin renderers over the same `ScanResult`. The HTML
  report is fully self-contained (inline CSS, no external assets).

Design patterns are deliberately limited to **Registry** (check discovery),
**Strategy** (report formats) and plain dataclasses. No plugins, no message
bus, no DI framework, no asyncio in V1.

## 3. Module Interaction

```
user ─▶ cli.py ─▶ orchestrator.py ─▶ checks.dns ─▶ dnspython
                         │           checks.ports ─▶ Nmap (subprocess)
                         │           checks.http ─▶ network.py ─▶ httpx
                         │           checks.tls ─▶ ssl + cryptography
                         │           checks.headers/fingerprint/robots
                         │             └─ reuse the response cached by checks.http
                         │           checks.directories (opt-in, rate-limited)
                         ▼
                    analysis.risk ─▶ analysis.recommendations
                         ▼
                    report.json/markdown/html ─▶ inspectra-report/
```

The `ScanContext` object carries shared resources between checks: the HTTP
client, the cached primary response, the cached robots.txt response, DNS
records and TLS details. The HTTP check runs before the checks that consume
its response, so headers, fingerprint and robots never re-fetch.

## 4. Execution Flow

1. Parse CLI arguments → validate target (`utils.normalize_target`).
2. Authorization gate (first-run consent, persisted; `--yes` skips).
3. Run checks in order: dns → ports → http → tls → headers → fingerprint →
   robots → (directories if `--directories`).
4. A failed check degrades gracefully (logged, scan continues); only a
   `FatalCheckError` aborts the scan (e.g. NXDOMAIN, Nmap missing).
5. Risk engine applies the severity × confidence rubric and computes the
   posture score.
6. JSON report (always) + Markdown or HTML report are written; the console
   prints a summary.
7. Exit codes: `0` no actionable findings · `1` findings present · `2` error.

## 5. The Finding Contract

Every finding must explain itself:

| Field | Question it answers |
|-------|--------------------|
| `description` | What was observed? |
| `why_it_matters` | Why should the reader care? |
| `evidence` | What proof was collected? |
| `confidence` | How sure are we (low/medium/high)? |
| `severity` | How severe (info/low/medium/high)? |
| `recommendation` | What should the reader do? |

## 6. Risk Model

Severity (info/low/medium/high) is multiplied by confidence
(low ×0.3, medium ×0.6, high ×1.0) and by a per-severity weight; a single
high-confidence HIGH finding costs 36 points on the 0–100 posture score
(see `analysis/risk.py`). Letter grades: A+ ≥ 95, A ≥ 90, B ≥ 80, C ≥ 70,
D ≥ 60, F below.

## 7. Safety Model

* GET-only requests; no payloads; no exploitation of any kind.
* Timeouts on every network operation (HTTP 15 s, TLS handshake 10 s, DNS
  lifetime 5 s, Nmap host timeout 90 s).
* The directory check is opt-in, single-threaded, rate-limited (0.5 s
  between requests) and reports only 2xx/3xx responses.
* First-run authorization consent, persisted to `~/.config/inspectra/config.json`.
* Subprocess use is limited to Nmap, invoked with argument lists (no shell).

## 8. Key Decisions & Trade-offs

| Decision | Choice | Rationale / trade-off |
|----------|--------|----------------------|
| Interface | CLI + HTML report | One command, no server to run; web dashboard deferred (see `roadmap/v2-roadmap.md`) |
| Concurrency | Sync + no threads | Simpler to reason about and test; Nmap dominates scan time anyway (async = v2) |
| Port scanning | Nmap via python-nmap | Battle-tested output; requires a system install (documented per-OS) |
| Models | Dataclasses, not pydantic | Zero magic, zero dependency |
| CLI | argparse, not typer | Stdlib; rich provides the polish |
| Rules & signatures | JSON in `data/` | Knowledge out of code — versioned, reviewable, extendable |
| Wordlist | Curated ~130 paths | Safe by default; larger lists are opt-in via `--directory-wordlist` |
| Storage | JSON reports, no database | The report *is* the deliverable (trends = v2) |
| Future work | Roadmap docs only | V1 stays one polished release |

## 9. Extending Inspectra

Adding a check is deliberately small:

1. Create `src/inspectra/checks/<name>.py` exposing
   `run(target, context) -> list[Finding]`.
2. Register it in `ALL_CHECKS` and `DEFAULT_CHECK_ORDER`
   (`checks/__init__.py`).
3. Add unit tests (mock the network) and, if it needs rules, add them to
   `src/inspectra/data/`.
4. Document it in `docs/usage.md`.

See [CONTRIBUTING.md](../CONTRIBUTING.md) for the full guide.
