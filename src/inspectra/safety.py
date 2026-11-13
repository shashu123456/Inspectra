"""SSRF-safe target validation for Inspectra scans.

Validates target hostnames and IP addresses before any network I/O, pins the
connection to the validated IP (defence against DNS rebinding), and re-validates
after every HTTP redirect hop. Blocks access to private, loopback, link-local,
CGNAT, unique-local, unspecified, multicast, and metadata addresses unless
explicitly allowed.
"""

from __future__ import annotations

import ipaddress
import socket
import sys

#: Hard-rejected metadata endpoints (hostnames and IP addresses).
METADATA_ENDPOINTS = {
    "169.254.169.254",
    "metadata.google.internal",
    "fd00:ec2::254",
}

#: Explicitly blocked networks (ipaddress.is_private is False for 100.64/10 on 3.11).
BLOCKED_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("100.64.0.0/10"),
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("192.0.0.0/24"),
    ipaddress.ip_network("198.18.0.0/15"),
    ipaddress.ip_network("224.0.0.0/4"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
    ipaddress.ip_network("::/128"),
    ipaddress.ip_network("ff00::/8"),
]


class SSRFError(Exception):
    """Raised when a target fails SSRF safety validation."""


def _normalize_ip(
    ip: ipaddress.IPv4Address | ipaddress.IPv6Address,
) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    """Normalise IPv4-mapped IPv6 to IPv4 before network checks."""
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        return ip.ipv4_mapped
    return ip


def _is_blocked_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """True when the IP is in any blocked network."""
    norm = _normalize_ip(ip)
    return any(norm in net for net in BLOCKED_NETWORKS)


def resolve_host(host: str) -> str:
    """Resolve a hostname to a single IP address string.

    Resolves once and returns the first address. Raises SSRFError if the
    hostname cannot be resolved. The caller must pass this IP back for every
    subsequent request so DNS cannot flip between validation and connect.
    """
    try:
        infos = socket.getaddrinfo(host, None)
        for info in infos:
            addr = str(info[4][0])
            try:
                ipaddress.ip_address(addr)
                return addr
            except ValueError:
                continue
    except OSError as exc:
        raise SSRFError(f"Could not resolve hostname {host!r}: {exc}") from exc
    raise SSRFError(f"Could not resolve hostname {host!r}: no usable address")


def validate_target(
    host: str,
    allow_private: bool = False,
    authorized: bool = False,
) -> str:
    """Validate a target host for SSRF safety and return the pinned IP.

    Resolves the hostname once and checks every resolved IP against blocked
    networks. Returns the pinned IP address string that must be used for all
    subsequent connections to this host (preventing DNS rebinding).

    Raises SSRFError if any resolved IP is blocked and not explicitly allowed,
    or if the host is a known metadata endpoint.

    Parameters
    ----------
    host : str
        The hostname to validate.
    allow_private : bool
        If True, allow private/loopback/link-local addresses. Requires
        ``authorized`` to be True.
    authorized : bool
        If True, the user has explicitly authorized private-target scanning.

    Returns
    -------
    str
        The pinned IP address for subsequent connections.
    """
    # Hard-reject metadata endpoints by hostname.
    if host.lower() in METADATA_ENDPOINTS:
        raise SSRFError(f"Access to metadata endpoint {host!r} is prohibited (SSRF protection).")

    ip_str = resolve_host(host)

    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        raise SSRFError(f"Resolved address {ip_str!r} is not a valid IP") from None

    if _is_blocked_ip(ip):
        if not allow_private:
            raise SSRFError(
                f"Target {host!r} ({ip_str}) resolves to a blocked address. "
                "Use --allow-private for home-lab testing only."
            )
        if not authorized:
            print(
                "Error: --allow-private requires --authorized.",
                file=sys.stderr,
            )
            raise SSRFError(
                f"Target {host!r} ({ip_str}) resolves to a private address. "
                "--allow-private requires --authorized."
            )
        print(
            f"Warning: scanning private target {host!r} ({ip_str}). Home-lab testing only.",
            file=sys.stderr,
        )

    return ip_str


def validate_redirect(
    url: str,
    original_scheme: str,
    allow_private: bool = False,
    authorized: bool = False,
    hop: int = 1,
    max_hops: int = 5,
) -> str:
    """Validate an HTTP redirect target for SSRF safety.

    Parses the redirect URL, validates its hostname, enforces max-redirects,
    and enforces the scheme rule: the scheme may only upgrade (http -> https).
    https -> http or any other change is rejected.

    Parameters
    ----------
    url : str
        The redirect target URL.
    original_scheme : str
        The scheme of the original request (used as the baseline for scheme
        downgrade detection).
    allow_private : bool
        If True, allow private addresses.
    authorized : bool
        If True, the user has authorized private-target scanning.
    hop : int
        The current redirect hop number (1-based).
    max_hops : int
        The maximum number of redirects allowed.

    Returns
    -------
    str
        The validated URL.

    Raises
    ------
    SSRFError
        If the redirect target is blocked, exceeds max hops, or uses a
        disallowed scheme change.
    """
    from urllib.parse import urlparse

    if hop > max_hops:
        raise SSRFError(f"Redirect chain exceeds {max_hops} hops (SSRF protection).")

    parsed = urlparse(url)
    scheme = parsed.scheme.lower()
    if scheme not in {"http", "https"}:
        raise SSRFError(f"Cross-scheme redirect to {scheme!r} is prohibited (SSRF protection).")

    # Scheme downgrade rule: http -> https is allowed; https -> http is not.
    # On subsequent hops, the "original" scheme is the scheme of the previous
    # hop (the URL we just validated), so any downgrade from https to http
    # anywhere in the chain is rejected.
    if original_scheme == "https" and scheme == "http":
        raise SSRFError(f"HTTPS-to-HTTP downgrade redirect is prohibited (SSRF protection): {url}")

    # Validate the redirect target hostname.
    validate_target(parsed.hostname or "", allow_private, authorized)
    return url


def scope_metadata(allow_private: bool, authorized: bool) -> dict[str, str] | None:
    """Return report metadata for the scan scope.

    Returns ``{"scope": "private-allowed"}`` when private scanning is
    explicitly allowed, otherwise ``None``.
    """
    if allow_private:
        return {"scope": "private-allowed"}
    return None
