"""Tests for the risk engine (severity/confidence rubric and posture score)."""

from __future__ import annotations

import pytest

from inspectra.analysis.risk import (
    compute_posture_score,
    finding_penalty,
    grade_for,
)
from inspectra.models import Confidence, Finding, ScanResult, Severity, Target


def _finding(severity: Severity, confidence: Confidence) -> Finding:
    return Finding(
        rule_id="TST-001",
        title="test",
        category="test",
        severity=severity,
        confidence=confidence,
        description="d",
        why_it_matters="w",
        recommendation="r",
    )


def test_clean_scan_scores_100() -> None:
    score, grade = compute_posture_score([])
    assert score == 100.0
    assert grade == "A+"


def test_high_high_finding_penalty() -> None:
    assert finding_penalty(_finding(Severity.HIGH, Confidence.HIGH)) == 36.0


def test_medium_medium_finding_penalty() -> None:
    assert finding_penalty(_finding(Severity.MEDIUM, Confidence.MEDIUM)) == pytest.approx(14.4)


def test_info_findings_do_not_penalize() -> None:
    score, _ = compute_posture_score([_finding(Severity.INFO, Confidence.HIGH)])
    assert score == 100.0


def test_score_never_below_zero() -> None:
    findings = [_finding(Severity.HIGH, Confidence.HIGH)] * 10
    score, grade = compute_posture_score(findings)
    assert score == 0.0
    assert grade == "F"


@pytest.mark.parametrize(
    ("score", "grade"),
    [
        (100.0, "A+"),
        (95.0, "A+"),
        (94.9, "A"),
        (90.0, "A"),
        (85.0, "B"),
        (75.0, "C"),
        (65.0, "D"),
        (55.0, "F"),
    ],
)
def test_grade_bands(score: float, grade: str) -> None:
    assert grade_for(score) == grade


def test_apply_attaches_score_and_grade() -> None:
    result = ScanResult(target=Target(input="x", hostname="example.com"))
    from inspectra.analysis.risk import apply

    apply(result)
    assert result.posture_score == 100.0
    assert result.grade == "A+"
