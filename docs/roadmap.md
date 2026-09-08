# Inspectra — Roadmap

> Planning documents only. Nothing here is committed for the next release;
> ideas graduate from this page only after a design review. Inspectra's
> founding promise applies to every future version:
> **observe, assess, explain, report — never exploit.**

## Release History

| Version | Status | Focus |
|---------|--------|-------|
| 1.0.0 | ✅ Released | Core framework: 8 checks, risk engine, JSON/Markdown/HTML reports, live demo |

## Version 2 — Candidates (prioritized)

1. **Async engine** — migrate network I/O to `asyncio` +
   `httpx.AsyncClient` for faster scans. Trade-off: complexity.
   Trigger: when scan duration becomes a complaint.
2. **Plugin system** — third-party checks via package entry points
   (`inspectra.checks`), with an API-stability policy and documentation.
3. **More checks** — CORS misconfiguration, cookie attribute audit
   (Secure/HttpOnly/SameSite), deeper CSP analysis, HSTS preload
   eligibility.
4. **Passive subdomain enumeration** — certificate-transparency lookups
   (crt.sh); no brute force, no DNS enumeration.
5. **Web dashboard** — read-only viewer for report JSON files and a
   posture-score trend line across runs. The `report.json` schema is
   already the stable API this needs.
6. **Distribution** — Docker image, GitHub Action, PDF export.
7. **Knowledge-base growth** — larger opt-in wordlists, expanded
   fingerprint signatures, a changelog process for `data/` files.

## Version 3 — Directions

1. **AI-assisted explanations** — optional, locally-run LLM explanations
   for findings (strict privacy: no target data leaves the machine without
   explicit opt-in). The finding contract makes this a rendering layer.
2. **CVE mapping** — map fingerprinted versions to known CVEs via
   NVD/OSV. Needs a false-positive strategy and a data-freshness process.
3. **Multi-target orchestration** — batch scans, run-to-run diffing, trend
   dashboards.
4. **Compliance mapping** — optional report sections mapping findings to
   CIS / OWASP ASVS controls.
5. **Team features** — baseline policies ("this header must never
   regress"), CI gates on posture score, report aggregation.

## Idea Parking Lot

*Checks & analysis:* security.txt inspection, SPF/DMARC/DKIM deep-dive,
HTTP `OPTIONS` observation (read-only), IPv6 posture, DNSSEC presence,
port-diff between runs, pure-Python TCP fallback when Nmap is absent.

*Reporting & UX:* SARIF output for CI, `--diff` mode, `.inspectra.toml`
config files, interactive TUI viewer, shell completions, localized
reports.

## Rejected (on purpose)

* Exploitation or payload modules — contradicts the core philosophy.
* Brute-force modules (passwords, paths, subdomains) — offensive by design.
* Screenshot capture — heavy dependency, flaky in CI, low value per byte.
* Authenticated scanning — changes the threat model entirely.
