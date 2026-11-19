# Inspectra Accuracy Benchmark

Results of scanning all lab targets with ground-truth files, run 3 times each for determinism. Recall is computed over `in_scope` findings only (the findings this tool is supposed to emit for each target, verified by manual review of `lab/targets/targetN/server.py`). Every target with a ground-truth file counts toward the overall recall and precision.

Precision counts every emitted finding that is not in `in_scope` as a potential false positive, unless listed in `expected_absent` with a reason. `out_of_scope` findings are reported separately and do not affect recall or precision.

Overall: in-scope recall=100.0% (49/49), precision=100.0%, emitted=58, justified_absent=9, unexplained(FP)=0, deterministic=YES.

| Target | In-scope expected | Found | Missed | Emitted | Justified | Unexplained | FP | Recall | Deterministic |
|--------|-------------------|-------|--------|---------|-----------|-------------|----|--------|---------------|
| target1 | 2 | 2 | 0 | 3 | 1 | 0 | 0 | 100% | YES |
| target10 | 9 | 9 | 0 | 10 | 1 | 0 | 0 | 100% | YES |
| target11 | 9 | 9 | 0 | 10 | 1 | 0 | 0 | 100% | YES |
| target12 | 9 | 9 | 0 | 10 | 1 | 0 | 0 | 100% | YES |
| target2 | 2 | 2 | 0 | 3 | 1 | 0 | 0 | 100% | YES |
| target3 | 2 | 2 | 0 | 3 | 1 | 0 | 0 | 100% | YES |
| target6 | 8 | 8 | 0 | 10 | 2 | 0 | 0 | 100% | YES |
| target9 | 8 | 8 | 0 | 9 | 1 | 0 | 0 | 100% | YES |

## Per-target detail

### target1

- In-scope expected: HDR-001, TLS-001
- Found: HDR-001, TLS-001
- Missed: (none)
- Emitted total: 3
- Justified absent: 1
- Unexplained (FP): 0
- Recall: 100%
- Deterministic: YES

### target10

- In-scope expected: HDR-001, HDR-002, HDR-003, HDR-004, HDR-005, HDR-006, HDR-007, ROB-002, TLS-001
- Found: HDR-001, HDR-002, HDR-003, HDR-004, HDR-005, HDR-006, HDR-007, ROB-002, TLS-001
- Missed: (none)
- Emitted total: 10
- Justified absent: 1
- Unexplained (FP): 0
- Recall: 100%
- Deterministic: YES

### target11

- In-scope expected: FPR-001, HDR-001, HDR-002, HDR-003, HDR-004, HDR-005, HDR-006, HDR-007, TLS-001
- Found: FPR-001, HDR-001, HDR-002, HDR-003, HDR-004, HDR-005, HDR-006, HDR-007, TLS-001
- Missed: (none)
- Emitted total: 10
- Justified absent: 1
- Unexplained (FP): 0
- Recall: 100%
- Deterministic: YES

### target12

- In-scope expected: HDR-001, HDR-002, HDR-003, HDR-004, HDR-005, HDR-006, HDR-007, HTP-005, TLS-001
- Found: HDR-001, HDR-002, HDR-003, HDR-004, HDR-005, HDR-006, HDR-007, HTP-005, TLS-001
- Missed: (none)
- Emitted total: 10
- Justified absent: 1
- Unexplained (FP): 0
- Recall: 100%
- Deterministic: YES

### target2

- In-scope expected: HDR-002, TLS-001
- Found: HDR-002, TLS-001
- Missed: (none)
- Emitted total: 3
- Justified absent: 1
- Unexplained (FP): 0
- Recall: 100%
- Deterministic: YES

### target3

- In-scope expected: HDR-003, TLS-001
- Found: HDR-003, TLS-001
- Missed: (none)
- Emitted total: 3
- Justified absent: 1
- Unexplained (FP): 0
- Recall: 100%
- Deterministic: YES

### target6

- In-scope expected: HDR-001, HDR-002, HDR-003, HDR-004, HDR-005, HDR-006, HDR-007, TLS-001
- Found: HDR-001, HDR-002, HDR-003, HDR-004, HDR-005, HDR-006, HDR-007, TLS-001
- Missed: (none)
- Emitted total: 10
- Justified absent: 2
- Unexplained (FP): 0
- Recall: 100%
- Deterministic: YES

### target9

- In-scope expected: HDR-001, HDR-002, HDR-003, HDR-004, HDR-005, HDR-006, HDR-007, TLS-001
- Found: HDR-001, HDR-002, HDR-003, HDR-004, HDR-005, HDR-006, HDR-007, TLS-001
- Missed: (none)
- Emitted total: 9
- Justified absent: 1
- Unexplained (FP): 0
- Recall: 100%
- Deterministic: YES
- Out of scope: PRT-003

## Not measured

- **target4**: TLS cert generation / HTTPS handshake not reliable on Windows
- **target5**: TLS cert generation / HTTPS handshake not reliable on Windows
- **target7**: /app/.git path not available on Windows lab harness
- **target8**: /app path not available on Windows lab harness
