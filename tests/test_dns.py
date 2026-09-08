"""Tests for the DNS resolution check (resolution is mocked)."""

from __future__ import annotations

import dns.resolver
import pytest

from inspectra.checks import FatalCheckError
from inspectra.checks import dns as dns_module
from inspectra.checks.context import ScanContext
from inspectra.models import Target


def _records(**overrides) -> dict[str, list[str]]:
    records: dict[str, list[str]] = {
        "A": [],
        "AAAA": [],
        "CNAME": [],
        "MX": [],
        "NS": [],
        "TXT": [],
    }
    records.update(overrides)
    return records


def test_dns_ip_literal_skips_resolution() -> None:
    target = Target(input="127.0.0.1", hostname="127.0.0.1")
    context = ScanContext()
    assert dns_module.run(target, context) == []
    assert target.ip_addresses == ["127.0.0.1"]
    assert target.is_private is True


def test_dns_success_populates_target(monkeypatch) -> None:
    monkeypatch.setattr(
        dns_module,
        "_resolve",
        lambda hostname: (_records(A=["93.184.216.34"], MX=["mx.example.com"]), 0.01),
    )
    target = Target(input="example.com", hostname="example.com")
    findings = dns_module.run(target, ScanContext())
    assert target.ip_addresses == ["93.184.216.34"]
    assert target.is_private is False
    # No TXT records -> informational finding.
    assert any(finding.rule_id == "DNS-004" for finding in findings)
    assert not any(finding.rule_id == "DNS-003" for finding in findings)


def test_dns_multiple_addresses(monkeypatch) -> None:
    monkeypatch.setattr(
        dns_module,
        "_resolve",
        lambda hostname: (_records(A=["93.184.216.34", "93.184.216.35"]), 0.01),
    )
    target = Target(input="example.com", hostname="example.com")
    findings = dns_module.run(target, ScanContext())
    assert any(finding.rule_id == "DNS-002" for finding in findings)


def test_dns_nxdomain_is_fatal(monkeypatch) -> None:
    def fail(hostname: str):
        raise dns.resolver.NXDOMAIN()

    monkeypatch.setattr(dns_module, "_resolve", fail)
    with pytest.raises(FatalCheckError):
        dns_module.run(Target(input="missing.example", hostname="missing.example"), ScanContext())


def test_dns_no_addresses_is_fatal(monkeypatch) -> None:
    monkeypatch.setattr(dns_module, "_resolve", lambda hostname: (_records(), 0.01))
    with pytest.raises(FatalCheckError):
        dns_module.run(Target(input="example.com", hostname="example.com"), ScanContext())
