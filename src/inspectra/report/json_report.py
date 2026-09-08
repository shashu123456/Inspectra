"""JSON report renderer: the machine-readable source of truth.

The JSON report is always written, so other tools can consume scan results
without parsing human-oriented formats.
"""

from __future__ import annotations

import json
from pathlib import Path

from inspectra.models import Finding, ScanResult, Severity


def render(result: ScanResult) -> dict:
    """Serialize a :class:`ScanResult` into a JSON-serializable dictionary."""
    return {
        "tool": result.metadata.tool,
        "version": result.metadata.version,
        "target": result.target.input,
        "started_at": result.metadata.started_at.isoformat(),
        "finished_at": (
            result.metadata.finished_at.isoformat() if result.metadata.finished_at else None
        ),
        "duration_seconds": result.metadata.duration_seconds,
        "posture_score": result.posture_score,
        "grade": result.grade,
        "summary": _summary(result),
        "findings": [_finding(finding) for finding in result.findings],
    }


def _summary(result: ScanResult) -> dict:
    return {
        "total": result.total_findings,
        "info": result.count_by_severity(Severity.INFO),
        "low": result.count_by_severity(Severity.LOW),
        "medium": result.count_by_severity(Severity.MEDIUM),
        "high": result.count_by_severity(Severity.HIGH),
    }


def _finding(finding: Finding) -> dict:
    return {
        "rule_id": finding.rule_id,
        "title": finding.title,
        "category": finding.category,
        "severity": finding.severity.value,
        "confidence": finding.confidence.value,
        "description": finding.description,
        "why_it_matters": finding.why_it_matters,
        "evidence": finding.evidence,
        "recommendation": finding.recommendation,
    }


def write(result: ScanResult, path: Path) -> None:
    """Write the JSON report to ``path``."""
    path.write_text(json.dumps(render(result), indent=2) + "\n", encoding="utf-8")
