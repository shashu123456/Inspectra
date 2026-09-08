"""HTTP analysis check: fetches the primary page and robots.txt."""

from __future__ import annotations

import re

import httpx

from inspectra.analysis.recommendations import remove_header
from inspectra.checks import CheckError
from inspectra.checks.context import ScanContext
from inspectra.models import Confidence, Finding, Severity, Target
from inspectra.network import build_client

SERVER_VERSION_RE = re.compile(r"\d+(?:\.\d+)+")
MAX_REDIRECT_EVIDENCE = 6


def run(target: Target, context: ScanContext) -> list[Finding]:
    """Fetch the target over HTTP(S), store responses, and report observations."""
    client = context.client or build_client()
    response, scheme = _fetch_primary(client, target)
    context.http_response = response
    target.scheme = scheme

    findings: list[Finding] = []
    if scheme == "https":
        findings.extend(_check_https_redirect(client, target))
    findings.extend(_transport_findings(response))
    server = response.headers.get("server")
    if server:
        findings.append(_server_header(server))
    _fetch_robots(client, target, context)
    return findings


def _fetch_primary(client: httpx.Client, target: Target) -> tuple[httpx.Response, str]:
    """Fetch the target, trying the preferred scheme first and the other as fallback."""
    schemes = [target.scheme]
    other = "http" if target.scheme == "https" else "https"
    schemes.append(other)
    last_error: Exception | None = None
    for scheme in schemes:
        url = _url_for(target, scheme)
        try:
            return client.get(url), scheme
        except httpx.RequestError as exc:
            last_error = exc
    raise CheckError(f"Could not reach {target.hostname} over HTTP or HTTPS: {last_error}")


def _url_for(target: Target, scheme: str) -> str:
    port = f":{target.port}" if target.port else ""
    return f"{scheme}://{target.hostname}{port}"


def _check_https_redirect(client: httpx.Client, target: Target) -> list[Finding]:
    """Verify that plain HTTP redirects to HTTPS when HTTPS is available."""
    try:
        response = client.get(_url_for(target, "http"))
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


def _fetch_robots(client: httpx.Client, target: Target, context: ScanContext) -> None:
    """Fetch robots.txt so the robots check can analyze it without re-fetching."""
    try:
        context.robots_response = client.get(f"{_url_for(target, target.scheme)}/robots.txt")
    except httpx.RequestError:
        context.robots_response = None
