"""Tests for the technology fingerprinting check."""

from __future__ import annotations

from inspectra.checks import fingerprint, http
from inspectra.checks.context import ScanContext
from inspectra.network import build_client

TEST_SIGNATURES = [
    {
        "name": "InspectraCMS",
        "category": "cms",
        "patterns": [{"type": "generator", "pattern": "InspectraCMS"}],
    },
    {
        "name": "InspectraTestServer",
        "category": "web_server",
        "patterns": [{"type": "header", "name": "Server", "pattern": "InspectraTest"}],
    },
]


def test_fingerprint_detects_technologies(
    fixture_server, target, scan_options, monkeypatch
) -> None:
    monkeypatch.setattr(fingerprint, "load_json", lambda name: TEST_SIGNATURES)
    with build_client() as client:
        context = ScanContext(client=client, options=scan_options)
        http.run(target, context)
        findings = fingerprint.run(target, context)

    assert len(findings) == 1
    finding = findings[0]
    assert finding.rule_id == "FPR-001"
    assert "InspectraCMS 1.2.3" in finding.description
    assert "InspectraTestServer 1.2.3" in finding.description
    assert any("InspectraTest/1.2.3" in line for line in finding.evidence)


def test_fingerprint_without_matches_returns_empty(
    fixture_server, target, scan_options, monkeypatch
) -> None:
    monkeypatch.setattr(fingerprint, "load_json", lambda name: [])
    with build_client() as client:
        context = ScanContext(client=client, options=scan_options)
        http.run(target, context)
        assert fingerprint.run(target, context) == []


def test_fingerprint_without_http_context_returns_empty(target) -> None:
    assert fingerprint.run(target, ScanContext()) == []
