Screenshots & transcripts
=========================

The polished visual artifact for Inspectra is the self-contained HTML report.
A committed, regenerable copy lives in `examples/sample-report/` — open
`report.html` in any browser (it has no external assets).

This directory keeps a captured CLI transcript for documentation:

* `cli-output.txt` — console output of a real scan against the local fixture.

To regenerate both after code changes:

    python scripts/generate_sample_report.py

(see the repo root README / run doc for environment setup).
