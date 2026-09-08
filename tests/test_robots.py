"""Tests for the robots.txt inspection check."""

from __future__ import annotations

from inspectra.checks import http, robots
from inspectra.checks.context import ScanContext
from inspectra.checks.robots import parse_robots
from inspectra.network import build_client


def test_parse_robots() -> None:
    info = parse_robots(
        "User-agent: *\nDisallow: /admin\nDisallow: /secret\nSitemap: https://x/sitemap.xml\n"
    )
    assert info.user_agents == ["*"]
    assert "/admin" in info.disallowed
    assert "/secret" in info.disallowed
    assert info.sitemaps == ["https://x/sitemap.xml"]


def test_parse_robots_ignores_comments_and_blank_lines() -> None:
    info = parse_robots("# comment\n\nUser-agent: *\n# another\nDisallow: /tmp\n")
    assert info.disallowed == ["/tmp"]


def test_robots_check_finds_disallowed_and_sitemap(fixture_server, target) -> None:
    with build_client() as client:
        context = ScanContext(client=client)
        http.run(target, context)
        findings = robots.run(target, context)

    rule_ids = {finding.rule_id for finding in findings}
    assert "ROB-002" in rule_ids
    assert "ROB-003" in rule_ids
    disallowed = next(finding for finding in findings if finding.rule_id == "ROB-002")
    assert "/admin" in disallowed.evidence


def test_robots_check_missing_file(fixture_server, target) -> None:
    fixture_server.expect_oneshot_request("/robots.txt").respond_with_data(b"", status=404)
    with build_client() as client:
        context = ScanContext(client=client)
        http.run(target, context)
        findings = robots.run(target, context)
    assert any(finding.rule_id == "ROB-001" for finding in findings)


def test_robots_check_without_response_returns_empty(target) -> None:
    assert robots.run(target, ScanContext()) == []
