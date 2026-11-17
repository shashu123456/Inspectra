"""Tests for the TLS verification check.

The TLS handshake itself is mocked: these tests exercise the finding logic
against a synthetic :class:`TlsInfo`.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from inspectra.checks import tls
from inspectra.checks.context import ScanContext
from inspectra.models import Target
from inspectra.network import TlsInfo


def _info(**overrides: object) -> TlsInfo:
    now = datetime.now(UTC)
    defaults: dict[str, object] = {
        "version": "TLSv1.3",
        "cipher": "TLS_AES_256_GCM_SHA384",
        "subject_cn": "example.com",
        "issuer": "Example CA",
        "not_valid_before": now - timedelta(days=30),
        "not_valid_after": now + timedelta(days=90),
        "san_dns": ["example.com"],
        "is_self_signed": False,
        "hostname_matches": True,
    }
    defaults.update(overrides)
    return TlsInfo(**defaults)  # type: ignore[arg-type]


def _run(info: TlsInfo, monkeypatch) -> list:
    monkeypatch.setattr(tls, "inspect_tls", lambda hostname, port, insecure=False: info)
    target = Target(input="example.com", hostname="example.com")
    return tls.run(target, ScanContext())


def test_healthy_certificate(monkeypatch) -> None:
    findings = _run(_info(), monkeypatch)
    rule_ids = {finding.rule_id for finding in findings}
    assert rule_ids == {"TLS-008"}


def test_expired_certificate(monkeypatch) -> None:
    info = _info(not_valid_after=datetime.now(UTC) - timedelta(days=1))
    findings = _run(info, monkeypatch)
    expired = [finding for finding in findings if finding.rule_id == "TLS-002"]
    assert len(expired) == 1
    assert expired[0].severity.value == "high"


def test_certificate_expiring_soon(monkeypatch) -> None:
    info = _info(not_valid_after=datetime.now(UTC) + timedelta(days=5))
    findings = _run(info, monkeypatch)
    expiring = [finding for finding in findings if finding.rule_id == "TLS-003"]
    assert len(expiring) == 1
    assert expiring[0].severity.value == "high"


def test_self_signed_certificate(monkeypatch) -> None:
    info = _info(is_self_signed=True)
    findings = _run(info, monkeypatch)
    assert any(finding.rule_id == "TLS-004" for finding in findings)


def test_hostname_mismatch(monkeypatch) -> None:
    info = _info(san_dns=["other.com"], subject_cn="other.com", hostname_matches=False)
    findings = _run(info, monkeypatch)
    assert any(finding.rule_id == "TLS-005" for finding in findings)


def test_weak_protocol(monkeypatch) -> None:
    info = _info(version="TLSv1")
    findings = _run(info, monkeypatch)
    assert any(finding.rule_id == "TLS-006" for finding in findings)


def test_tls12_only_is_informational(monkeypatch) -> None:
    info = _info(version="TLSv1.2")
    findings = _run(info, monkeypatch)
    assert any(finding.rule_id == "TLS-007" for finding in findings)


def test_https_unavailable_on_http_target(monkeypatch) -> None:

    def fail(hostname: str, port: int, insecure: bool = False) -> TlsInfo:
        raise TimeoutError("timed out")

    monkeypatch.setattr(tls, "inspect_tls", fail)
    target = Target(input="http://example.com", hostname="example.com", scheme="http")
    findings = tls.run(target, ScanContext())
    assert any(finding.rule_id == "TLS-001" for finding in findings)
