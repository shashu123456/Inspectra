"""Tests for target normalization and shared helpers."""

from __future__ import annotations

import pytest

from inspectra.utils import TargetValidationError, is_private_address, normalize_target, truncate


def test_normalize_domain_lowercases_and_strips_dot() -> None:
    target = normalize_target("Example.COM.")
    assert target.hostname == "example.com"
    assert target.scheme == "https"
    assert target.port is None


def test_normalize_domain_with_trailing_slash() -> None:
    assert normalize_target("example.com/").hostname == "example.com"


def test_normalize_url_with_port_and_path() -> None:
    target = normalize_target("https://example.com:8443/some/path")
    assert target.hostname == "example.com"
    assert target.port == 8443
    assert target.scheme == "https"


def test_normalize_http_scheme() -> None:
    assert normalize_target("http://example.com").scheme == "http"


def test_normalize_ip_literal() -> None:
    target = normalize_target("127.0.0.1")
    assert target.hostname == "127.0.0.1"
    assert target.is_private is True


def test_normalize_public_ip() -> None:
    assert normalize_target("8.8.8.8").is_private is False


def test_normalize_host_port_form() -> None:
    target = normalize_target("example.com:8080")
    assert target.hostname == "example.com"
    assert target.port == 8080


@pytest.mark.parametrize(
    "bad",
    ["", "not a host", "user@example.com", "ftp://example.com", "example..com", "exa mple.com"],
)
def test_normalize_invalid_targets_raise(bad: str) -> None:
    with pytest.raises(TargetValidationError):
        normalize_target(bad)


def test_is_private_address() -> None:
    assert is_private_address("192.168.1.1") is True
    assert is_private_address("10.0.0.1") is True
    assert is_private_address("8.8.8.8") is False
    assert is_private_address("not-an-ip") is False


def test_truncate() -> None:
    assert truncate("short") == "short"
    assert truncate("x" * 100, limit=10) == "xxxxxxxxx…"
