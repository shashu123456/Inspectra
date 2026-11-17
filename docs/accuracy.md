# Inspectra Accuracy Benchmark

Results of scanning all 12 lab targets against ground truth, run 3 times each for determinism. Recall is computed over `in_scope` findings only (the findings this tool is supposed to emit for each target, verified by manual review of `lab/targets/targetN/server.py`).

Precision counts every emitted finding that is not in `in_scope` as a potential false positive, unless listed in `expected_absent`. `out_of_scope` findings (for example, port discovery without the nmap binary, or TLS on self-signed certs without `--allow-insecure`) are reported separately and do not affect recall or precision.

Overall: in-scope recall=100.0%, precision=100.0%, FP=0, deterministic=YES.

| Target | In-scope expected | Found | Missed | FP | Recall | Deterministic |
|--------|-------------------|-------|--------|----|--------|---------------|
| target1 | 1 | 1 | 0 | 0 | 100% | YES |
| target10 | 1 | 1 | 0 | 0 | 100% | YES |
| target11 | 1 | 1 | 0 | 0 | 100% | YES |
| target12 | 1 | 1 | 0 | 0 | 100% | YES |
| target2 | 1 | 1 | 0 | 0 | 100% | YES |
| target3 | 1 | 1 | 0 | 0 | 100% | YES |
| target4 | 1 | 0 | 1 | 0 | 0% | YES |
| target5 | 1 | 0 | 1 | 0 | 0% | YES |
| target6 | 1 | 1 | 0 | 0 | 100% | YES |
| target7 | 1 | 0 | 1 | 0 | 0% | YES |
| target8 | 1 | 0 | 1 | 0 | 0% | YES |
| target9 | 0 | 0 | 0 | 0 | 100% | YES |

## Per-target detail

### target1

- In-scope expected: HDR-001
- Found: HDR-001
- Missed: (none)
- FP (non-in-scope emitted): 0
- Recall: 100%
- Deterministic: YES

### target10

- In-scope expected: ROB-002
- Found: ROB-002
- Missed: (none)
- FP (non-in-scope emitted): 0
- Recall: 100%
- Deterministic: YES

### target11

- In-scope expected: FPR-001
- Found: FPR-001
- Missed: (none)
- FP (non-in-scope emitted): 0
- Recall: 100%
- Deterministic: YES

### target12

- In-scope expected: HTP-005
- Found: HTP-005
- Missed: (none)
- FP (non-in-scope emitted): 0
- Recall: 100%
- Deterministic: YES

### target2

- In-scope expected: HDR-002
- Found: HDR-002
- Missed: (none)
- FP (non-in-scope emitted): 0
- Recall: 100%
- Deterministic: YES

### target3

- In-scope expected: HDR-003
- Found: HDR-003
- Missed: (none)
- FP (non-in-scope emitted): 0
- Recall: 100%
- Deterministic: YES

### target4

- In-scope expected: TLS-004
- Found: (none)
- Missed: TLS-004
- FP (non-in-scope emitted): 0
- Recall: 0%
- Deterministic: YES
- Out of scope: platform

### target5

- In-scope expected: TLS-006
- Found: (none)
- Missed: TLS-006
- FP (non-in-scope emitted): 0
- Recall: 0%
- Deterministic: YES
- Out of scope: platform

### target6

- In-scope expected: HTP-003
- Found: HTP-003
- Missed: (none)
- FP (non-in-scope emitted): 0
- Recall: 100%
- Deterministic: YES

### target7

- In-scope expected: DIR-002
- Found: (none)
- Missed: DIR-002
- FP (non-in-scope emitted): 0
- Recall: 0%
- Deterministic: YES
- Out of scope: platform

### target8

- In-scope expected: DIR-001
- Found: (none)
- Missed: DIR-001
- FP (non-in-scope emitted): 0
- Recall: 0%
- Deterministic: YES
- Out of scope: platform

### target9

- In-scope expected: (none)
- Found: (none)
- Missed: (none)
- FP (non-in-scope emitted): 0
- Recall: 100%
- Deterministic: YES
- Out of scope: PRT-003
