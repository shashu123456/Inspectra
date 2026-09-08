"""Risk engine: severity/confidence rubric and the posture score.

The rubric is deliberately conservative: findings carry a severity and a
confidence, and the posture score is a weighted penalty model where a single
high-confidence HIGH finding costs 36 points (see :data:`POINTS_PER_HIGH`).
"""

from __future__ import annotations

from inspectra.models import Confidence, Finding, ScanResult, Severity

SEVERITY_WEIGHTS: dict[Severity, int] = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
}

CONFIDENCE_FACTORS: dict[Confidence, float] = {
    Confidence.LOW: 0.3,
    Confidence.MEDIUM: 0.6,
    Confidence.HIGH: 1.0,
}

#: Points deducted from 100 for a single HIGH/HIGH-confidence finding.
POINTS_PER_HIGH = 12.0

GRADE_BANDS: list[tuple[float, str]] = [
    (95.0, "A+"),
    (90.0, "A"),
    (80.0, "B"),
    (70.0, "C"),
    (60.0, "D"),
]


def finding_penalty(finding: Finding) -> float:
    """The posture-score penalty contributed by a single finding."""
    weight = SEVERITY_WEIGHTS[finding.severity]
    factor = CONFIDENCE_FACTORS[finding.confidence]
    return weight * factor * POINTS_PER_HIGH


def grade_for(score: float) -> str:
    """Map a 0-100 score to a letter grade."""
    for threshold, grade in GRADE_BANDS:
        if score >= threshold:
            return grade
    return "F"


def compute_posture_score(findings: list[Finding]) -> tuple[float, str]:
    """Return ``(score, grade)`` for a list of findings."""
    penalty = sum(finding_penalty(finding) for finding in findings)
    score = max(0.0, round(100.0 - penalty, 1))
    return score, grade_for(score)


def apply(result: ScanResult) -> None:
    """Attach the posture score and grade to a scan result (in place)."""
    result.posture_score, result.grade = compute_posture_score(result.findings)
