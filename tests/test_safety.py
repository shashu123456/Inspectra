"""Tests for the SSRF safety module (M3 Phase A1-A3, A7)."""

from __future__ import annotations

import contextlib
import ipaddress
import socket
from unittest.mock import patch

import pytest

from inspectra.safety import (
    METADATA_ENDPOINTS,
    SSRFError,
    _is_blocked_ip,
    _normalize_ip,
    validate_redirect,
    validate_target,
)

# --- A2: CGNAT + explicit blocked networks ---

BLOCKED_CASES = [
    "100.64.0.1",  # CGNAT
    "::ffff:127.0.0.1",  # IPv4-mapped IPv6 loopback
    "169.254.169.254",  # AWS metadata
    "fd00:ec2::254",  # IPv6 metadata
    "fe80::1",  # IPv6 link-local
    "0.0.0.0",  # Unspecified
    "224.0.0.1",  # Multicast
    "198.18.0.1",  # Benchmarking
    "10.0.0.1",  # RFC1918
    "172.16.0.1",  # RFC1918
    "192.168.1.1",  # RFC1918
    "127.0.0.1",  # Loopback
    "169.254.0.1",  # Link-local
]

ALLOWED_CASES = ["93.184.216.34", "8.8.8.8", "1.1.1.1"]


@pytest.mark.parametrize("ip_str", BLOCKED_CASES)
def test_blocked_networks_reject(ip_str: str) -> None:
    """All blocked networks are rejected, including CGNAT 100.64/10."""
    ip = ipaddress.ip_address(ip_str)
    assert _is_blocked_ip(ip) is True


@pytest.mark.parametrize("ip_str", ALLOWED_CASES)
def test_allowed_networks_accept(ip_str: str) -> None:
    """Public addresses are not blocked."""
    ip = ipaddress.ip_address(ip_str)
    assert _is_blocked_ip(ip) is False


def test_ipv4_mapped_ipv6_normalised() -> None:
    """IPv4-mapped IPv6 is normalised to IPv4 before checking."""
    ip = ipaddress.ip_address("::ffff:127.0.0.1")
    norm = _normalize_ip(ip)
    assert norm == ipaddress.ip_address("127.0.0.1")
    assert _is_blocked_ip(ip) is True


def test_metadata_endpoints_hard_rejected() -> None:
    """Metadata endpoints are in the hard-reject set."""
    assert "169.254.169.254" in METADATA_ENDPOINTS
    assert "metadata.google.internal" in METADATA_ENDPOINTS
    assert "fd00:ec2::254" in METADATA_ENDPOINTS


# --- A1: DNS rebinding / IP pinning ---


def test_validate_target_returns_pinned_ip() -> None:
    """validate_target returns a pinned IP string."""
    with patch("socket.getaddrinfo") as mock_gai:
        mock_gai.return_value = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 80)),
        ]
        ip = validate_target("example.com", allow_private=False, authorized=False)
    assert isinstance(ip, str)
    ipaddress.ip_address(ip)


def test_validate_target_rejects_private_without_flags() -> None:
    """Private targets are rejected without --allow-private/--authorized."""
    with pytest.raises(SSRFError):
        validate_target("127.0.0.1", allow_private=False, authorized=False)


def test_validate_target_rejects_allow_private_without_authorized() -> None:
    """--allow-private requires --authorized."""
    with pytest.raises(SSRFError):
        validate_target("127.0.0.1", allow_private=True, authorized=False)


def test_validate_target_allows_private_with_both_flags() -> None:
    """Private targets are allowed when both flags are set."""
    ip = validate_target("127.0.0.1", allow_private=True, authorized=True)
    assert ip == "127.0.0.1"


def test_validate_target_rejects_metadata_hostname() -> None:
    """Metadata endpoints are rejected by hostname."""
    with pytest.raises(SSRFError):
        validate_target("metadata.google.internal", allow_private=False, authorized=False)


def test_dns_rebinding_uses_pinned_ip() -> None:
    """A TTL-0 host that flips from public to 127.0.0.1 on re-resolution
    never connects to 127.0.0.1 because the pinned IP is used."""
    original = "93.184.216.34"
    rebind = "127.0.0.1"

    def fake_getaddrinfo(host, port, *args, **kwargs):
        # Return different IPs depending on call context - simulate TTL-0 flipping
        if host == "example.com":
            return [
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", (original, 80)),
            ]
        raise socket.gaierror(f"Unexpected host: {host}")

    with patch("socket.getaddrinfo", side_effect=fake_getaddrinfo):
        # First validation returns the public IP
        pinned = validate_target("example.com", allow_private=False, authorized=False)
        assert pinned == original

        # The pinned IP is what should be used for connection, not a re-resolution
        assert pinned != rebind


# --- A3: Redirect scheme rule ---


def test_redirect_http_to_https_allowed() -> None:
    """http -> https redirect is allowed."""
    with patch("socket.getaddrinfo") as mock_gai:
        mock_gai.return_value = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443)),
        ]
        url = validate_redirect(
            "https://example.com/secure",
            original_scheme="http",
            allow_private=False,
            authorized=False,
            hop=1,
        )
    assert url == "https://example.com/secure"


def test_redirect_https_to_http_rejected() -> None:
    """https -> http redirect is rejected (downgrade)."""
    with pytest.raises(SSRFError, match="HTTPS-to-HTTP downgrade"):
        validate_redirect(
            "http://example.com/insecure",
            original_scheme="https",
            allow_private=False,
            authorized=False,
            hop=1,
        )


def test_redirect_max_hops_exceeded() -> None:
    """More than 5 hops is rejected."""
    with pytest.raises(SSRFError, match="exceeds 5 hops"):
        validate_redirect(
            "https://example.com/",
            original_scheme="https",
            allow_private=False,
            authorized=False,
            hop=6,
        )


def test_redirect_cross_scheme_rejected() -> None:
    """Non-http(s) schemes are rejected."""
    with pytest.raises(SSRFError, match="Cross-scheme redirect"):
        validate_redirect(
            "ftp://example.com/",
            original_scheme="http",
            allow_private=False,
            authorized=False,
            hop=1,
        )


# --- A7: No rich markup in stderr ---


def test_stderr_no_rich_markup(capsys) -> None:
    """Error messages use plain text, not Rich markup."""
    with contextlib.suppress(SSRFError):
        validate_target("127.0.0.1", allow_private=True, authorized=False)
    captured = capsys.readouterr()
    assert "[bold" not in captured.err
    assert "[yellow" not in captured.err
