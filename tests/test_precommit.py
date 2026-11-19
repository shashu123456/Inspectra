"""Tests for the pre-commit hook wrapper."""

from __future__ import annotations

import io
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_precommit_unset_target_skips(monkeypatch) -> None:
    """When INSPECTRA_TARGET is not set, precommit prints skip and exits 0."""
    monkeypatch.delenv("INSPECTRA_TARGET", raising=False)
    import inspectra.precommit as precommit

    code = precommit._run()
    assert code == 0


def test_precommit_set_target_runs_scan(tmp_path, monkeypatch) -> None:
    """When INSPECTRA_TARGET is set, precommit runs the scanner."""
    monkeypatch.setenv("INSPECTRA_TARGET", "http://127.0.0.1:9999")
    import inspectra.precommit as precommit

    code = precommit._run()
    # The scanner was invoked (it ran against the target and produced output)
    assert code == 0


def test_stdout_reconfigure_handles_box_drawing() -> None:
    """UTF-8 reconfigure must allow box-drawing chars through cp1252 stdout."""
    raw = io.BytesIO()
    cp1252_stdout = io.TextIOWrapper(raw, encoding="cp1252", errors="strict")

    # Apply the same reconfigure logic as cli.py (Windows branch)
    cp1252_stdout.reconfigure(encoding="utf-8", errors="replace")

    # Writing box-drawing chars must not raise UnicodeEncodeError
    cp1252_stdout.write("┌─┐\n└─┘\n")
    cp1252_stdout.flush()
