# Inspectra — Version 3 Roadmap (Planning Only)

> Long-term horizon. These ideas are recorded so they are not lost, not
> because they are committed.

## Candidate Directions

### 1. AI-assisted explanations
Optional LLM-generated, context-aware explanations for findings (local
models preferred; strict privacy: no target data leaves the machine without
explicit opt-in). The structured finding contract makes this a rendering
layer, not a rewrite.

### 2. CVE mapping
Map fingerprinted versions to known CVEs via NVD/OSV APIs. Requires a
careful false-positive strategy (version ranges are messy) and a freshness
process for the vulnerability data.

### 3. Multi-target orchestration
Batch scans across a target list with scheduling, diffing between runs and
trend dashboards. Builds on the v2 dashboard and the stable JSON schema.

### 4. Compliance mapping
Map findings to control frameworks (CIS, OWASP ASVS) as optional report
sections.

### 5. Team features
Baseline policies ("this header must never regress"), CI gates on posture
score, organization report aggregation.

## Guiding Principle

Every future version must keep the founding promise: **observe, assess,
explain, report — never exploit.**
