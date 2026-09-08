# Inspectra — Future Feature Ideas (Planning Only)

> A parking lot for ideas that are real but not scheduled. Nothing here is
> planned for V1; each item needs a design review before implementation.

## Checks & Analysis
* Cookie attribute audit (Secure, HttpOnly, SameSite)
* CORS misconfiguration detection
* Deep CSP analysis (unsafe-inline, wildcard sources, missing nonces)
* HSTS preload eligibility check
* Security.txt (`/.well-known/security.txt`) inspection
* Email security deep-dive (SPF/DMARC/DKIM record parsing)
* HTTP methods observation (OPTIONS; read-only)
* Server banner deep-dive (full version → known-vulns hinting, v3 CVE map)
* IPv6 posture (AAAA reachability, dual-stack consistency)
* DNSSEC presence check
* Port-scan comparison between runs (new/removed ports)
* Pure-Python TCP port fallback when Nmap is not installed

## Reporting & UX
* SARIF output for CI integration
* PDF export
* `--diff` mode: compare two reports and show deltas
* Config file support (`.inspectra.toml`) for repeated scans
* Interactive TUI report viewer
* Localized report languages

## Platform
* Async engine (see v2-roadmap.md)
* Plugin system (see v2-roadmap.md)
* GitHub Action + Docker image (see v2-roadmap.md)
* Shell completions (bash/zsh/fish)
* Windows service / scheduled scan helper

## Rejected (on purpose)
* Exploitation or payload modules — contradicts the core philosophy
* Brute-force modules (passwords, paths, subdomains) — offensive by design
* Screenshot capture — heavy dependency, flaky in CI, low value per byte
* Authenticated scanning — changes the threat model entirely
