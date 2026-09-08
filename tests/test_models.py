"""Tests for the core domain models."""

from __future__ import annotations

from inspectra.models import Confidence, Finding, ScanResult, Severity, Target


def _finding(severity: Severity) -> Finding:
    return Finding(
        rule_id="TST-001",
        title="test",
        category="test",
        severity=severity,
        confidence=Confidence.HIGH,
        description="d",
        why_it_matters="w",
        recommendation="r",
    )


def test_severity_enum_values() -> None:
    assert Severity("info") is Severity.INFO
    assert Severity("high") is Severity.HIGH


def test_target_base_url_with_port() -> None:
    target = Target(input="x", hostname="example.com", port=8443, scheme="https")
    assert target.base_url == "https://example.com:8443"


def test_target_base_url_default() -> None:
    assert Target(input="x", hostname="example.com").base_url == "https://example.com"


def test_finding_default_evidence() -> None:
    finding = _finding(Severity.LOW)
    assert finding.evidence == []


def test_scan_result_counts() -> None:
    result = ScanResult(
        target=Target(input="x", hostname="example.com"),
        findings=[
            _finding(Severity.HIGH),
            _finding(Severity.HIGH),
            _finding(Severity.MEDIUM),
            _finding(Severity.INFO),
        ],
    )
    assert result.count_by_severity(Severity.HIGH) == 2
    assert result.count_by_severity(Severity.MEDIUM) == 1
    assert result.total_findings == 4
    assert result.has_actionable_findings is True


def test_info_only_scan_is_not_actionable() -> None:
    result = ScanResult(
        target=Target(input="x", hostname="example.com"),
        findings=[_finding(Severity.INFO)],
    )
    assert result.has_actionable_findings is False
