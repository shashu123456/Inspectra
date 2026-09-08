# Inspectra — Architecture Notes

> Decision records for future maintainers (and for anyone reading the code
> and wondering "why is it like this?").

## AD-001 — CLI-first, no web UI in V1
**Decision:** Ship a CLI with JSON/Markdown/HTML reports.
**Why:** The internship deliverable is a working tool; a dashboard would
halve the polish budget. The JSON report is already a stable API, so a v2
dashboard becomes a rendering layer over existing data.

## AD-002 — Sync over asyncio in V1
**Decision:** Synchronous pipeline, no asyncio.
**Why:** One target at a time; Nmap dominates wall time; sync is easier to
test and debug for a solo maintainer. Revisit when scan latency matters
(v2).

## AD-003 — Dataclasses over pydantic
**Decision:** Plain dataclasses for models.
**Why:** The models are internal; validation happens at the boundary
(`normalize_target`). Pydantic would add a dependency and magic for little
gain.

## AD-004 — Registry over plugins
**Decision:** A hardcoded `ALL_CHECKS` registry.
**Why:** V1 has eight checks; a plugin system adds packaging complexity with
no community yet. The registry still guarantees "new check = one file, zero
core changes". Entry-point plugins are a v2 item.

## AD-005 — Knowledge in JSON, not code
**Decision:** Header rules, fingerprints and the wordlist live in `data/`.
**Why:** Non-developers can review and extend them; changes don't touch
code; the files can be versioned with changelogs.

## AD-006 — Graceful degradation, fatal only when meaningless
**Decision:** A failed check logs and continues; only `FatalCheckError`
aborts the scan.
**Why:** A partial report is almost always more useful than no report. DNS
failure and missing Nmap abort because every downstream check would produce
noise or duplicate the error.

## AD-007 — Conservative directory check
**Decision:** Opt-in, GET-only, 0.5 s delay, single-threaded, curated
~150-path wordlist, 2xx/3xx only.
**Why:** Path probing is the most "active" thing Inspectra does; keeping it
slow, small and explicit preserves the passive posture and keeps legal
exposure minimal.

## AD-008 — Severity × confidence scoring
**Decision:** Posture score = 100 − Σ(severity weight × confidence factor ×
12), floored at 0.
**Why:** Simple, explainable, and it lets a single high-confidence HIGH
finding matter more than a pile of speculative LOWs. Alternatives (CVSS
import, per-category weighting) were rejected as over-engineering for V1.

## AD-009 — Exit codes as an API
**Decision:** 0 = clean, 1 = findings, 2 = error.
**Why:** Lets CI and scripts react to scans without parsing reports.

## AD-010 — src layout, single package
**Decision:** `src/inspectra` with hatchling.
**Why:** Prevents accidental imports of the local (uninstalled) package in
tests; one package keeps the mental model small.

## AD-011 — Future work lives in docs, not branches
**Decision:** `docs/roadmap/*` captures every future idea.
**Why:** Keeps the codebase focused on one polished release while making
roadmap thinking visible to contributors and reviewers.
