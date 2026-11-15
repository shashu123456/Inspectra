"""HTTP analysis check: fetches the primary page and robots.txt.

All connections are IP-pinned: the target hostname is resolved once via
``safety.validate_target`` and every subsequent request connects to that IP
with the original hostname sent as the ``Host`` header and as the TLS SNI
name. This prevents DNS rebinding between validation and connect. Every
redirect hop is re-resolved and re-pinned the same way.
"""

from __future__ import annotations

import re
from urllib.parse import urljoin, urlparse

import httpx

from inspectra.analysis.recommendations import remove_header
from inspectra.checks import CheckError
from inspectra.checks.context import ScanContext
from inspectra.models import Confidence, Finding, Severity, Target
from inspectra.network import build_client
from inspectra.safety import validate_redirect, validate_target

SERVER_VERSION_RE = re.compile(r"\d+(?:\.\d+)+")
MAX_REDIRECT_EVIDENCE = 6
MAX_REDIRECT_HOPS = 5


def _pinned_url(
    pinned_ip: str,
    scheme: str,
    port: int | None,
    path: str = "/",
) -> str:
    """Build a URL that connects to ``pinned_ip``; the caller sets Host/SNI."""
    port_part = f":{port}" if port else ""
    path_part = path if path else "/"
    return f"{scheme}://{pinned_ip}{port_part}{path_part}"


def _pinned_get(
    client: httpx.Client,
    url: str,
    hostname: str,
    pinned_ip: str,
) -> httpx.Response:
    """GET ``url`` connecting to ``pinned_ip`` with Host + SNI set to ``hostname``.

    SNI is only set for HTTPS URLs; for HTTP we set the Host header and let
    httpx use plain TCP (avoiding spurious TLS handshakes on HTTP servers).
    The query string is preserved and the Host header keeps any non-default port.
    """
    parsed = urlparse(url)
    path = f"{parsed.path or '/'}?{parsed.query}" if parsed.query else (parsed.path or "/")
    pinned = _pinned_url(pinned_ip, parsed.scheme, parsed.port, path)
    host_header = parsed.netloc.rsplit("@", 1)[-1]
    headers = {"Host": host_header}
    extensions = {"sni_hostname": hostname} if parsed.scheme == "https" else None
    return client.get(pinned, headers=headers, extensions=extensions)


def run(target: Target, context: ScanContext) -> list[Finding]:
    """Fetch the target over HTTP(S), store responses, and report observations."""
    client = context.client or build_client()
    allow_private = context.options.allow_private if context.options else False
    authorized = context.options.authorized if context.options else False
    replay_dir = context.options.replay_dir if context.options else None
    response, scheme = _fetch_primary(client, target, allow_private, authorized, replay_dir)
    context.http_response = response
    target.scheme = scheme

    findings: list[Finding] = []
    if scheme == "https":
        findings.extend(
            _check_https_redirect(client, target, allow_private, authorized, replay_dir)
        )
    findings.extend(_transport_findings(response))
    server = response.headers.get("server")
    if server:
        findings.append(_server_header(server))
    _fetch_robots(client, target, context, allow_private, authorized, replay_dir)
    return findings


def _fetch_primary(
    client: httpx.Client,
    target: Target,
    allow_private: bool = False,
    authorized: bool = False,
    replay_dir: str | None = None,
) -> tuple[httpx.Response, str]:
    """Fetch the target, trying the preferred scheme first and the other as fallback.

    Validates the initial target for SSRF safety (unless in replay mode),
    then manually follows redirects with per-hop validation.
    """
    schemes = [target.scheme]
    other = "http" if target.scheme == "https" else "https"
    schemes.append(other)
    last_error: Exception | None = None
    for scheme in schemes:
        url = _url_for(target, scheme)
        try:
            # Validate initial target for SSRF safety; get pinned IP.
            # Skip validation in replay mode (no DNS lookups allowed).
            if replay_dir:
                pinned_ip = target.hostname  # use hostname directly in replay
            else:
                pinned_ip = validate_target(target.hostname, allow_private, authorized)
            response = _follow_redirects(
                client, url, target.hostname, pinned_ip, allow_private, authorized, replay_dir
            )
            return response, scheme
        except httpx.RequestError as exc:
            last_error = exc
    raise CheckError(f"Could not reach {target.hostname} over HTTP or HTTPS: {last_error}")


def _url_for(target: Target, scheme: str) -> str:
    port = f":{target.port}" if target.port else ""
    return f"{scheme}://{target.hostname}{port}"


def _follow_redirects(
    client: httpx.Client,
    url: str,
    hostname: str,
    pinned_ip: str,
    allow_private: bool,
    authorized: bool,
    replay_dir: str | None = None,
    max_hops: int = MAX_REDIRECT_HOPS,
) -> httpx.Response:
    """Manually follow HTTP redirects with per-hop SSRF validation and re-pinning.

    httpx is configured with follow_redirects=False, so we handle redirects
    ourselves. Each hop is re-resolved and re-pinned via safety.validate_target
    to prevent DNS rebinding across hops.
    """
    current_url = url
    current_hostname = hostname
    current_ip = pinned_ip
    for hop in range(1, max_hops + 1):
        response = _pinned_get(client, current_url, current_hostname, current_ip)
        if response.is_redirect:
            location = response.headers.get("location")
            if not location:
                return response
            next_url = urljoin(current_url, location)
            # Validate this redirect hop before following it.
            next_url = validate_redirect(
                next_url, current_url.split("://")[0], allow_private, authorized, hop, max_hops
            )
            next_parsed = urlparse(next_url)
            next_hostname = next_parsed.hostname or current_hostname
            # Re-resolve and re-pin the redirect target's IP.
            # Skip validation in replay mode.
            if replay_dir:
                current_ip = next_hostname
            else:
                current_ip = validate_target(next_hostname, allow_private, authorized)
            current_hostname = next_hostname
            current_url = next_url
        else:
            return response
    # If we exhausted max hops, return the last response (may still be a redirect).
    return _pinned_get(client, current_url, current_hostname, current_ip)


def _check_https_redirect(
    client: httpx.Client,
    target: Target,
    allow_private: bool = False,
    authorized: bool = False,
    replay_dir: str | None = None,
) -> list[Finding]:
    """Verify that plain HTTP redirects to HTTPS when HTTPS is available."""
    try:
        if replay_dir:
            pinned_ip = target.hostname
        else:
            pinned_ip = validate_target(target.hostname, allow_private, authorized)
        response = _pinned_get(client, _url_for(target, "http"), target.hostname, pinned_ip)
    except httpx.RequestError:
        return []  # plain HTTP unavailable; nothing to redirect
    if response.url.scheme == "https":
        return []
    return [
        Finding(
            rule_id="HTP-001",
            title="Plain HTTP does not redirect to HTTPS",
            category="http",
            severity=Severity.MEDIUM,
            confidence=Confidence.MEDIUM,
            description=(
                f"Requesting http://{target.hostname} returned status "
                f"{response.status_code} without redirecting to HTTPS."
            ),
            why_it_matters=(
                "Users and links that use plain HTTP can be intercepted or modified "
                "(downgrade attack) unless traffic is redirected to TLS."
            ),
            recommendation=(
                "Configure the web server to issue a 301 redirect from HTTP to "
                "HTTPS for all resources."
            ),
            evidence=[f"GET http://{target.hostname} -> {response.status_code} {response.url}"],
        )
    ]


def _transport_findings(response: httpx.Response) -> list[Finding]:
    findings: list[Finding] = []
    if response.history:
        chain = [
            f"{hop.status_code} {hop.headers.get('location', hop.url)}" for hop in response.history
        ]
        chain.append(f"{response.status_code} {response.url}")
        findings.append(
            Finding(
                rule_id="HTP-002",
                title="Redirect chain detected",
                category="http",
                severity=Severity.INFO,
                confidence=Confidence.HIGH,
                description=(
                    f"The initial request followed {len(response.history)} redirect(s) "
                    "before reaching the final resource."
                ),
                why_it_matters=(
                    "Long or mixed-scheme redirect chains can leak information and slow "
                    "users down; verify each hop is intentional."
                ),
                recommendation="Minimize redirect hops and ensure every hop uses HTTPS.",
                evidence=chain[:MAX_REDIRECT_EVIDENCE],
            )
        )
    if response.status_code >= 400:
        findings.append(
            Finding(
                rule_id="HTP-004",
                title="Root path returned an error status",
                category="http",
                severity=Severity.LOW,
                confidence=Confidence.MEDIUM,
                description=f"GET {response.url} returned HTTP {response.status_code}.",
                why_it_matters=(
                    "An error status on the root path may indicate misconfiguration or "
                    "that the service is not intended for direct access."
                ),
                recommendation=(
                    "Verify the application serves its intended content on the root path."
                ),
                evidence=[f"GET {response.url} -> {response.status_code}"],
            )
        )
    return findings


def _server_header(server: str) -> Finding:
    versioned = bool(SERVER_VERSION_RE.search(server))
    return Finding(
        rule_id="HTP-003",
        title="Web server software disclosed" + (" (with version)" if versioned else ""),
        category="http",
        severity=Severity.INFO,
        confidence=Confidence.HIGH,
        description=f"The server disclosed its software via the Server header: {server!r}.",
        why_it_matters=(
            "Version numbers help attackers identify known vulnerabilities. Even "
            "without a version, the software name narrows the attack surface."
        ),
        recommendation=remove_header("Server"),
        evidence=[f"Server: {server}"],
    )


def _fetch_robots(
    client: httpx.Client,
    target: Target,
    context: ScanContext,
    allow_private: bool = False,
    authorized: bool = False,
    replay_dir: str | None = None,
) -> None:
    """Fetch robots.txt so the robots check can analyze it without re-fetching."""
    try:
        if replay_dir:
            pinned_ip = target.hostname
        else:
            pinned_ip = validate_target(target.hostname, allow_private, authorized)
        response = _pinned_get(
            client,
            f"{_url_for(target, target.scheme)}/robots.txt",
            target.hostname,
            pinned_ip,
        )
        context.robots_response = response
    except httpx.RequestError:
        context.robots_response = None
