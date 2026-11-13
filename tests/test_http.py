"""Tests for the HTTP analysis check."""

from __future__ import annotations

from inspectra.checks import http
from inspectra.checks.context import ScanContext
from inspectra.models import Target
from inspectra.network import build_client


def test_http_check_populates_context(fixture_server, target, scan_options) -> None:
    with build_client() as client:
        context = ScanContext(client=client, options=scan_options)
        findings = http.run(target, context)

    assert context.http_response is not None
    assert context.http_response.status_code == 200
    assert context.robots_response is not None
    assert context.robots_response.status_code == 200
    assert target.scheme == "http"

    rule_ids = {finding.rule_id for finding in findings}
    assert "HTP-003" in rule_ids  # Server header disclosure


def test_http_check_reports_error_status(fixture_server, target, scan_options) -> None:
    fixture_server.expect_oneshot_request("/").respond_with_data(b"", status=503)
    with build_client() as client:
        context = ScanContext(client=client, options=scan_options)
        findings = http.run(target, context)
    assert any(finding.rule_id == "HTP-004" for finding in findings)


def test_http_check_unreachable_raises(target, scan_options) -> None:
    unreachable = Target(input="x", hostname="127.0.0.1", port=1, scheme="http")
    with build_client() as client:
        context = ScanContext(client=client, options=scan_options)
        try:
            http.run(unreachable, context)
        except Exception as exc:
            assert exc.__class__.__name__ == "CheckError"
        else:
            raise AssertionError("expected CheckError for unreachable target")
