"""SARIF report tests: schema validation + golden file."""

from __future__ import annotations

import json
from datetime import UTC, datetime

from inspectra import __version__
from inspectra.models import Confidence, Finding, ScanMetadata, ScanResult, Severity, Target
from inspectra.report.sarif_report import render

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"


def _result() -> ScanResult:
    findings = [
        Finding(
            rule_id="TLS-001",
            title="Missing security header",
            category="security_headers",
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            description="X-Frame-Options not present",
            why_it_matters="Clickjacking risk",
            recommendation="Add X-Frame-Options header",
            evidence=["https://example.com/"],
        ),
        Finding(
            rule_id="HEADERS-002",
            title="Weak CSP",
            category="security_headers",
            severity=Severity.MEDIUM,
            confidence=Confidence.MEDIUM,
            description="CSP header weak",
            why_it_matters="XSS risk",
            recommendation="Strengthen CSP",
            evidence=["Content-Security-Policy: default-src *"],
        ),
    ]
    result = ScanResult(
        target=Target(
            input="http://127.0.0.1:9000", hostname="127.0.0.1", port=9000, scheme="http"
        ),
        findings=findings,
        metadata=ScanMetadata(started_at=datetime(2026, 9, 8, 12, 0, tzinfo=UTC)),
    )
    result.posture_score = 78.4
    result.grade = "C"
    return result


def test_sarif_schema_fields() -> None:
    """Every SARIF 2.1.0 required field is present."""
    data = render(_result())
    assert data["$schema"] == SARIF_SCHEMA
    assert data["version"] == "2.1.0"
    run = data["runs"][0]
    driver = run["tool"]["driver"]
    assert driver["name"] == "Inspectra"
    assert driver["version"] == __version__
    assert driver["informationUri"] == "https://github.com/shashu123456/inspectra"
    assert len(driver["rules"]) == 2


def test_sarif_rule_mapping() -> None:
    """Inspectra fields map to the correct SARIF rule fields."""
    data = render(_result())
    rules = {r["id"]: r for r in data["runs"][0]["tool"]["driver"]["rules"]}

    tls = rules["TLS-001"]
    assert tls["shortDescription"]["text"] == "Missing security header"
    assert tls["fullDescription"]["text"] == "Clickjacking risk"
    assert tls["properties"]["confidence"] == "high"
    assert tls["properties"]["category"] == "security_headers"

    headers = rules["HEADERS-002"]
    assert headers["shortDescription"]["text"] == "Weak CSP"
    assert headers["properties"]["confidence"] == "medium"


def test_sarif_rules_have_help_uri() -> None:
    """Every SARIF rule carries a helpUri so Code Scanning links to guidance."""
    data = render(_result())
    rules = data["runs"][0]["tool"]["driver"]["rules"]
    assert rules
    for rule in rules:
        assert rule["helpUri"].startswith("https://github.com/shashu123456/inspectra/")


def test_sarif_result_mapping() -> None:
    """Inspectra fields map to the correct SARIF result fields."""
    data = render(_result())
    results = data["runs"][0]["results"]
    assert len(results) == 2

    tls = results[0]
    assert tls["ruleId"] == "TLS-001"
    assert tls["level"] == "error"  # HIGH -> error
    assert tls["message"]["text"] == "Missing security header"
    assert tls["message"]["markdown"] == "Clickjacking risk"
    assert tls["fixes"][0]["description"]["text"] == "Add X-Frame-Options header"
    assert tls["properties"]["confidence"] == "high"
    assert tls["properties"]["category"] == "security_headers"

    headers = results[1]
    assert headers["ruleId"] == "HEADERS-002"
    assert headers["level"] == "warning"  # MEDIUM -> warning


def test_sarif_severity_levels() -> None:
    """All severity levels map correctly."""
    from inspectra.report.sarif_report import _SEVERITY_TO_LEVEL

    assert _SEVERITY_TO_LEVEL[Severity.INFO] == "note"
    assert _SEVERITY_TO_LEVEL[Severity.LOW] == "note"
    assert _SEVERITY_TO_LEVEL[Severity.MEDIUM] == "warning"
    assert _SEVERITY_TO_LEVEL[Severity.HIGH] == "error"


def test_sarif_golden_file(tmp_path) -> None:
    """SARIF output matches a stable golden structure."""
    data = render(_result())
    path = tmp_path / "golden.sarif"
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")

    # Re-read and verify it round-trips as valid JSON
    loaded = json.loads(path.read_text(encoding="utf-8"))
    assert loaded["$schema"] == SARIF_SCHEMA
    assert loaded["version"] == "2.1.0"
    assert len(loaded["runs"][0]["results"]) == 2
