"""Tests for the accuracy benchmark documentation consistency."""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "benchmarks" / "accuracy.json"
DOCS_OUTPUT = ROOT / "docs" / "accuracy.md"


def test_docs_accuracy_matches_json() -> None:
    """docs/accuracy.md must be generated from accuracy.json and match exactly."""
    data = json.loads(OUTPUT.read_text(encoding="utf-8"))
    md = DOCS_OUTPUT.read_text(encoding="utf-8")

    overall = data["overall"]
    # Every target row must appear in the markdown.
    for target_id, result in data["targets"].items():
        assert target_id in md
        assert f"{result['recall']:.0%}" in md
        det = "YES" if result["deterministic"] else "NO"
        assert det in md

    # Overall numbers must appear in the markdown.
    assert f"{overall['recall']:.1%}" in md
    assert f"{overall['precision']:.1%}" in md
    assert str(overall["fp"]) in md

    # The file must contain the header and the detail sections.
    assert "# Inspectra Accuracy Benchmark" in md
    assert "## Per-target detail" in md
