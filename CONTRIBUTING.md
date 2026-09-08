# Contributing to Inspectra

Thanks for your interest in improving Inspectra! This project follows one
rule above all others:

> **Inspect. Observe. Assess. Explain. Report. Never exploit.**

Any contribution that adds exploitation, brute-forcing, payload delivery or
attack tooling will be declined, no matter how well implemented.

## Project Setup

```bash
git clone <repository-url>
cd inspectra
python -m venv .venv && source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
```

Install [Nmap](https://nmap.org) if you want to work on the port check
(see `docs/usage.md` for per-OS instructions).

## Running the Quality Gates

```bash
ruff check .        # lint
ruff format .       # formatting (run before committing)
mypy                # type checking
pytest              # tests with coverage
```

CI runs all four on Python 3.11 and 3.12. All tests run against a local
fixture server — the suite never touches the internet.

## Adding a Check

This is the most valuable kind of contribution. It is deliberately small:

1. Create `src/inspectra/checks/<name>.py` exposing:

   ```python
   def run(target: Target, context: ScanContext) -> list[Finding]:
   ```

2. Register it in `ALL_CHECKS` and `DEFAULT_CHECK_ORDER`
   (`src/inspectra/checks/__init__.py`). Put it *after* the checks whose
   cached data it consumes (the HTTP check caches the primary response in
   the context).
3. If the check needs rules or signatures, add them to
   `src/inspectra/data/` as JSON — not code.
4. Write unit tests in `tests/` (mock the network; use the fixtures in
   `conftest.py` where possible).
5. Document the check in `docs/usage.md`.
6. Open a pull request using the template.

### The finding contract

Every finding must be explainable. Fill in all six fields:

| Field | Question |
|-------|----------|
| `rule_id` | Stable ID like `HDR-001` (prefix per check, never reused) |
| `description` | What was observed? |
| `why_it_matters` | Why should the reader care? |
| `evidence` | Raw proof, truncated to stay readable |
| `confidence` | low / medium / high |
| `severity` | info / low / medium / high |
| `recommendation` | A concrete next step |

## Code Style

* Python 3.11+, full type hints, `from __future__ import annotations`.
* Dataclasses over classes; docstrings on every public object.
* One module, one responsibility. If a file needs a "misc" section, split it.
* No new runtime dependencies without a written justification in the PR.

## Reporting Issues

Use the issue templates. For security issues in Inspectra itself, see
[SECURITY.md](SECURITY.md) — never open a public issue.

## Roadmap Policy

Ideas that don't fit V1 belong in `docs/roadmap/` as planning documents,
not in the codebase. Propose the move in your issue if that's where your
idea belongs.
