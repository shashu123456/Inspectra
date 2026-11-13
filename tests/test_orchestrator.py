"""Tests for the scan orchestrator."""

from __future__ import annotations

import pytest

from inspectra.checks import ALL_CHECKS, FatalCheckError
from inspectra.models import Confidence, ScanOptions, Severity
from inspectra.orchestrator import ScanAborted, run_scan


def test_full_scan_against_fixture(fixture_server, target) -> None:
    options = ScanOptions(skip_ports=True, allow_private=True, authorized=True)
    seen: list[str] = []
    result = run_scan(target, options, progress=seen.append)

    assert seen[0] == "dns"  # IP-literal target: DNS check returns immediately
    assert "http" in seen
    assert "headers" in seen
    assert "directories" not in seen  # opt-in
    assert result.metadata.duration_seconds >= 0
    assert result.posture_score is not None
    assert result.grade is not None
    rule_ids = {finding.rule_id for finding in result.findings}
    assert "HTP-003" in rule_ids  # server header disclosure
    assert "HDR-008" in rule_ids  # X-Powered-By present
    assert "ROB-002" in rule_ids  # robots disallowed paths


def test_failing_check_degrades_gracefully(fixture_server, target, monkeypatch) -> None:
    def boom(target, context):
        raise RuntimeError("unexpected explosion")

    monkeypatch.setitem(ALL_CHECKS, "headers", boom)
    result = run_scan(target, ScanOptions(skip_ports=True, allow_private=True, authorized=True))
    assert result.findings  # other checks still produced findings


def test_fatal_check_aborts_scan(fixture_server, target, monkeypatch) -> None:
    def fatal(target, context):
        raise FatalCheckError("boom")

    monkeypatch.setitem(ALL_CHECKS, "http", fatal)
    with pytest.raises(ScanAborted):
        run_scan(target, ScanOptions(skip_ports=True, allow_private=True, authorized=True))


def test_posture_score_reflects_findings(fixture_server, target) -> None:
    result = run_scan(target, ScanOptions(skip_ports=True, allow_private=True, authorized=True))
    expected_penalty = sum(
        {Severity.INFO: 0, Severity.LOW: 12, Severity.MEDIUM: 24, Severity.HIGH: 36}[f.severity]
        * {Confidence.LOW: 0.3, Confidence.MEDIUM: 0.6, Confidence.HIGH: 1.0}[f.confidence]
        for f in result.findings
    )
    assert result.posture_score == max(0.0, round(100.0 - expected_penalty, 1))
