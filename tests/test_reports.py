"""Tests for the JSON, Markdown and HTML report renderers."""

from __future__ import annotations

import json
from datetime import UTC, datetime

from inspectra.models import Confidence, Finding, ScanMetadata, ScanResult, Severity, Target
from inspectra.report import html_report, json_report, markdown_report


def _result() -> ScanResult:
    findings = [
        Finding(
            rule_id="TST-002",
            title="Medium finding",
            category="test",
            severity=Severity.MEDIUM,
            confidence=Confidence.MEDIUM,
            description="observed thing",
            why_it_matters="because",
            recommendation="do this",
            evidence=["Header: value"],
        ),
        Finding(
            rule_id="TST-001",
            title="Info finding",
            category="test",
            severity=Severity.INFO,
            confidence=Confidence.HIGH,
            description="informational",
            why_it_matters="context",
            recommendation="nothing needed",
        ),
    ]
    result = ScanResult(
        target=Target(input="example.com", hostname="example.com"),
        findings=findings,
        metadata=ScanMetadata(
            started_at=datetime(2026, 9, 8, 12, 0, tzinfo=UTC),
            finished_at=datetime(2026, 9, 8, 12, 0, 5, tzinfo=UTC),
            duration_seconds=5.0,
            target="example.com",
        ),
    )
    result.posture_score, result.grade = 78.4, "C"
    return result


def test_json_report_structure() -> None:
    data = json.loads(json.dumps(json_report.render(_result())))
    assert data["target"] == "example.com"
    assert data["posture_score"] == 78.4
    assert data["summary"]["medium"] == 1
    assert data["summary"]["total"] == 2
    finding = data["findings"][0]
    assert finding["severity"] in {"high", "medium", "low", "info"}
    for key in ("rule_id", "title", "description", "why_it_matters", "evidence", "recommendation"):
        assert key in finding


def test_json_report_writes_file(tmp_path) -> None:
    path = tmp_path / "report.json"
    json_report.write(_result(), path)
    data = json.loads(path.read_text(encoding="utf-8"))
    assert data["grade"] == "C"


def test_markdown_report_contains_all_sections() -> None:
    markdown = markdown_report.render(_result())
    assert "# Inspectra Security Assessment Report" in markdown
    assert "78.4 / 100 (C)" in markdown
    assert "[MEDIUM] TST-002 — Medium finding" in markdown
    assert "[INFO] TST-001 — Info finding" in markdown  # sorted after medium
    assert "**Why it matters:**" in markdown
    assert "`Header: value`" in markdown
    assert "never exploits" in markdown


def test_markdown_report_empty_findings(tmp_path) -> None:
    result = ScanResult(target=Target(input="x", hostname="example.com"))
    markdown = markdown_report.render(result)
    assert "No findings were recorded" in markdown


def test_html_report_renders(tmp_path) -> None:
    html = html_report.render(_result())
    assert "Inspectra" in html
    assert "78.4" in html
    assert "TST-002" in html
    assert "sev-medium" in html
    assert "<style>" in html  # self-contained CSS


def test_html_report_writes_file(tmp_path) -> None:
    path = tmp_path / "report.html"
    html_report.write(_result(), path)
    content = path.read_text(encoding="utf-8")
    assert content.startswith("<!doctype html>")
