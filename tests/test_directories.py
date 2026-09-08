"""Tests for the opt-in directory observation check."""

from __future__ import annotations

from pathlib import Path

from inspectra.checks import directories, http
from inspectra.checks.context import ScanContext
from inspectra.models import ScanOptions
from inspectra.network import build_client

WORDLIST = "/admin\n/.git/config\n/health\n/missing\n"


def test_directories_finds_accessible_paths(fixture_server, target, tmp_path: Path) -> None:
    wordlist = tmp_path / "wordlist.txt"
    wordlist.write_text(WORDLIST, encoding="utf-8")
    options = ScanOptions(directory_wordlist=str(wordlist))
    with build_client() as client:
        context = ScanContext(client=client, options=options)
        http.run(target, context)
        findings = directories.run(target, context)

    rule_ids = {finding.rule_id for finding in findings}
    assert "DIR-001" in rule_ids
    assert "DIR-002" in rule_ids  # /.git/config and /admin are sensitive

    summary = next(finding for finding in findings if finding.rule_id == "DIR-001")
    evidence = " | ".join(summary.evidence)
    for path in ("/admin", "/.git/config", "/health"):
        assert path in evidence
    assert "/missing" not in evidence

    git_finding = next(
        finding
        for finding in findings
        if finding.rule_id == "DIR-002" and ".git/config" in finding.title
    )
    assert git_finding.severity.value == "high"
    assert any(".git/config" in line for line in git_finding.evidence)


def test_directories_without_http_context_returns_empty(target) -> None:
    assert directories.run(target, ScanContext()) == []


def test_directories_uses_default_wordlist(fixture_server, target) -> None:
    with build_client() as client:
        context = ScanContext(client=client)
        http.run(target, context)
        findings = directories.run(target, context)
    # With the default wordlist the fixture serves several paths (robots.txt, admin...).
    assert any(finding.rule_id == "DIR-001" for finding in findings)
