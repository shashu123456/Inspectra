# Inspectra — Version 2 Roadmap (Planning Only)

> This document is for future planning. Nothing here affects the V1
> codebase; V1 stays focused on one polished release.

## Candidate Features (prioritized)

### 1. Async engine
Migrate network I/O to `asyncio` + `httpx.AsyncClient` for faster scans.
Trade-off: complexity. Trigger: when scan duration becomes a complaint.

### 2. Plugin system
Third-party checks via package entry points (`inspectra.checks`). Includes a
plugin API stability policy and documentation.

### 3. More checks
* CORS misconfiguration detection
* Cookie attribute audit (Secure, HttpOnly, SameSite)
* Deeper CSP analysis (unsafe-inline, wildcards)
* HSTS preload eligibility
* Cookie/session handling observations

### 4. Passive subdomain enumeration
Certificate-transparency lookups (crt.sh) — no brute force, no DNS
enumeration.

### 5. Web dashboard
Read-only viewer for report JSON files; posture-score trend line across
runs. Requires a report schema (already stable via `report.json`).

### 6. Distribution
Docker image, GitHub Action, PDF export via WeasyPrint.

### 7. Knowledge-base growth
Larger opt-in wordlists; expanded fingerprint signatures; a changelog
process for `data/` files.

## Non-Goals (deliberately)

Exploitation, brute force, CVE exploitation tooling, authenticated scanning,
anything that turns Inspectra from an assessment tool into an attack tool.
