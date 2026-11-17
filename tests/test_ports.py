"""Tests for the port discovery check (Nmap binary and scanner are mocked)."""

from __future__ import annotations

import shutil

import pytest

from inspectra.checks import CheckError, ports
from inspectra.checks.context import ScanContext
from inspectra.models import ScanOptions


class FakeHost:
    """Duck-typed stand-in for a python-nmap host scan result."""

    def __init__(self, tcp_ports: dict) -> None:
        self._tcp = tcp_ports

    def all_protocols(self) -> list[str]:
        return ["tcp"]

    def __getitem__(self, key: str):
        if key == "tcp":
            return self._tcp
        raise KeyError(key)


class FakeScanner:
    """Duck-typed stand-in for nmap.PortScanner."""

    def __init__(self, hosts: dict[str, FakeHost]) -> None:
        self._hosts = hosts
        self.calls: list[dict] = []

    def scan(self, **kwargs) -> None:
        self.calls.append(kwargs)

    def all_hosts(self) -> list[str]:
        return list(self._hosts)

    def __getitem__(self, host: str) -> FakeHost:
        return self._hosts[host]


def test_ports_skipped_with_option(target, monkeypatch) -> None:
    monkeypatch.setattr(shutil, "which", lambda name: "/usr/bin/nmap")
    context = ScanContext(options=ScanOptions(skip_ports=True))
    assert ports.run(target, context) == []


def test_ports_missing_nmap_is_skipped(target, monkeypatch) -> None:
    monkeypatch.setattr(shutil, "which", lambda name: None)
    with pytest.raises(CheckError):
        ports.run(target, ScanContext(options=ScanOptions()))


def test_ports_reports_open_and_sensitive(target, monkeypatch) -> None:
    monkeypatch.setattr(shutil, "which", lambda name: "/usr/bin/nmap")
    scanner = FakeScanner(
        {
            target.hostname: FakeHost(
                {
                    22: {"state": "open", "name": "ssh", "product": "OpenSSH", "version": "9.0"},
                    21: {"state": "open", "name": "ftp"},
                    8080: {"state": "closed", "name": "http-proxy"},
                }
            )
        }
    )
    findings = ports._scan(target, ScanContext(options=ScanOptions()), scanner)

    rule_ids = {finding.rule_id for finding in findings}
    assert "PRT-002" in rule_ids
    assert "PRT-003" in rule_ids  # ftp is sensitive
    sensitive = [finding for finding in findings if finding.rule_id == "PRT-003"]
    assert any("ftp" in finding.title for finding in sensitive)
    assert not any("ssh" in finding.title for finding in sensitive)


def test_ports_no_open_ports(target, monkeypatch) -> None:
    monkeypatch.setattr(shutil, "which", lambda name: "/usr/bin/nmap")
    scanner = FakeScanner({target.hostname: FakeHost({})})
    findings = ports._scan(target, ScanContext(options=ScanOptions()), scanner)
    assert any(finding.rule_id == "PRT-001" for finding in findings)


def test_ports_scan_error_is_non_fatal(target, monkeypatch) -> None:
    monkeypatch.setattr(shutil, "which", lambda name: "/usr/bin/nmap")

    class ExplodingScanner:
        def scan(self, **kwargs) -> None:
            raise RuntimeError("nmap exploded")

    with pytest.raises(ports.CheckError):
        ports._scan(target, ScanContext(options=ScanOptions()), ExplodingScanner())
