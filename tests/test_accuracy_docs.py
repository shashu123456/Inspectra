"""Tests for the accuracy benchmark documentation consistency."""

from __future__ import annotations

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "benchmarks" / "accuracy.json"
DOCS_OUTPUT = ROOT / "docs" / "accuracy.md"
GROUND_TRUTH_DIR = ROOT / "benchmarks" / "ground_truth"


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


def test_overall_matches_rows() -> None:
    """Overall recall must equal sum(found) / sum(expected) computed independently
    from the markdown rows, not just trusted from the JSON."""
    data = json.loads(OUTPUT.read_text(encoding="utf-8"))
    md = DOCS_OUTPUT.read_text(encoding="utf-8")

    # Independently compute overall recall from per-target rows in the markdown.
    total_expected = 0
    total_found = 0
    for line in md.splitlines():
        m = re.match(r"\| (target\d+) \| (\d+) \| (\d+) \|", line)
        if m:
            expected = int(m.group(2))
            found = int(m.group(3))
            total_expected += expected
            total_found += found

    assert total_expected > 0, "No target rows found in markdown"
    computed_recall = total_found / total_expected
    json_recall = data["overall"]["recall"]
    assert abs(computed_recall - json_recall) < 0.0001, (
        f"Markdown recall {computed_recall:.4%} != JSON recall {json_recall:.4%}"
    )


def test_no_target_omitted() -> None:
    """Every ground-truth JSON file must appear in the accuracy table
    (or under 'Not measured')."""
    data = json.loads(OUTPUT.read_text(encoding="utf-8"))
    md = DOCS_OUTPUT.read_text(encoding="utf-8")

    gt_files = {p.stem for p in GROUND_TRUTH_DIR.glob("*.json")}
    json_targets = set(data["targets"].keys())

    # Every ground-truth target must be in the JSON results.
    assert gt_files == json_targets, f"Ground-truth files {gt_files} != JSON targets {json_targets}"

    # Every ground-truth target must appear in the markdown table.
    for target_id in gt_files:
        assert target_id in md, f"Target {target_id} missing from accuracy.md table"


def test_no_zero_row_under_90() -> None:
    """If any target row has recall < 90%, the overall line must not claim 100%."""
    data = json.loads(OUTPUT.read_text(encoding="utf-8"))
    md = DOCS_OUTPUT.read_text(encoding="utf-8")

    any_under_90 = any(r["recall"] < 0.90 for r in data["targets"].values())
    if any_under_90:
        overall_line = [ml for ml in md.splitlines() if ml.startswith("Overall:")]
        assert overall_line, "No overall line found in markdown"
        assert "100%" not in overall_line[0], "Overall claims 100% but some targets are under 90%"
