"""Tests for the security header assessment check."""

from __future__ import annotations

from inspectra.checks import headers, http
from inspectra.checks.context import ScanContext
from inspectra.network import build_client


def _run_headers(fixture_server, target, scan_options) -> list:
    with build_client() as client:
        context = ScanContext(client=client, options=scan_options)
        http.run(target, context)
        return headers.run(target, context)


def test_missing_headers_reported(fixture_server, target, scan_options) -> None:
    findings = _run_headers(fixture_server, target, scan_options)
    rule_ids = {finding.rule_id for finding in findings}
    # HSTS, CSP and X-Frame-Options are absent on the fixture server.
    assert "HDR-001" in rule_ids
    assert "HDR-002" in rule_ids
    assert "HDR-003" in rule_ids
    # X-Powered-By is present and should be removed.
    assert "HDR-008" in rule_ids
    # X-XSS-Protection is absent, which is correct — no finding.
    assert "HDR-009" not in rule_ids


def test_present_headers_do_not_find(fixture_server, target, scan_options) -> None:
    fixture_server.expect_oneshot_request("/").respond_with_data(
        b"<html></html>",
        status=200,
        headers={
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
            "Content-Security-Policy": "default-src 'self'",
            "X-Frame-Options": "DENY",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "strict-origin-when-cross-origin",
            "Permissions-Policy": "camera=()",
            "Cross-Origin-Resource-Policy": "same-origin",
        },
    )
    findings = _run_headers(fixture_server, target, scan_options)
    rule_ids = {finding.rule_id for finding in findings}
    assert "HDR-001" not in rule_ids
    assert "HDR-002" not in rule_ids
    assert "HDR-003" not in rule_ids
    assert "HDR-004" not in rule_ids
    assert "HDR-005" not in rule_ids
    assert "HDR-006" not in rule_ids
    assert "HDR-007" not in rule_ids


def test_weak_header_value_reported(fixture_server, target, scan_options) -> None:
    fixture_server.expect_oneshot_request("/").respond_with_data(
        b"<html></html>",
        status=200,
        headers={"Strict-Transport-Security": "max-age=0"},
    )
    findings = _run_headers(fixture_server, target, scan_options)
    hsts = [finding for finding in findings if finding.rule_id == "HDR-001"]
    assert any("Weak" in finding.title for finding in hsts)


def test_headers_check_without_http_context_returns_empty(target) -> None:
    assert headers.run(target, ScanContext()) == []
