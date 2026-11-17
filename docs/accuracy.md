# Inspectra Accuracy Benchmark

Results of scanning all 12 lab targets against ground truth, run 3 times each
for determinism.

| Target | Planted | Found | Missed | FP | Recall | Deterministic |
|--------|---------|-------|--------|----|--------|---------------|
| target1 | 3 | 2 | 1 | 0 | 67% | YES |
| target2 | 3 | 2 | 1 | 0 | 67% | YES |
| target3 | 3 | 2 | 1 | 0 | 67% | YES |
| target4 | 3 | 0 | 3 | 0 | 0% | YES |
| target5 | 3 | 0 | 3 | 0 | 0% | YES |
| target6 | 2 | 1 | 1 | 0 | 50% | YES |
| target7 | 3 | 1 | 2 | 0 | 33% | YES |
| target8 | 3 | 1 | 2 | 0 | 33% | YES |
| target9 | 2 | 1 | 1 | 0 | 50% | YES |
| target10 | 3 | 2 | 1 | 0 | 67% | YES |
| target11 | 3 | 1 | 2 | 0 | 33% | YES |
| target12 | 3 | 1 | 2 | 0 | 33% | YES |

**Overall: recall=41.2%, precision=100.0%, FP=0, deterministic=YES**

## Known misses

| Target | Missed finding | Reason |
|--------|---------------|--------|
| target1 | HDR-001 (missing HSTS) | Header check runs but target returns 200 with other headers; HSTS absence not detected |
| target2 | HDR-002 (missing CSP) | Same as target1 |
| target3 | HDR-003 (missing X-Frame-Options) | Same as target1 |
| target4 | TLS-001 (self-signed cert) | Scanner does not trust self-signed certificates; HTTPS targets fail TLS handshake |
| target5 | TLS-002 (TLS 1.0) | Same as target4 |
| target6 | HTP-003 (server banner) | Scanner found the banner but rule ID differs |
| target7 | DIR-001 (exposed .git) | Directories check probes common paths but .git/ not in wordlist |
| target8 | DIR-001 (directory listing) | Same as target7 |
| target9 | PRT-003 (open port 3306) | Nmap binary not installed; ports check skipped per P11 portability |
| target10 | ROB-002 (robots.txt secret path) | Robots check found /admin and /config but rule ID mapping differs |
| target11 | FP-001 (default nginx page) | Fingerprint check does not match "Welcome to nginx!" title |
| target12 | HTP-004 (verbose error messages) | Scanner does not probe /error path; directory check doesn't discover it |

## Notes

- All 12 targets are deterministic (identical finding ID sets across 3 runs).
- Precision is 100.0% — no false positives reported.
- The accuracy gate (recall >= 95%, FP <= 2) is not met due to the misses above.
- P11 (optional Nmap) will address target9. P12 (custom checks) allows users to add missing checks.
