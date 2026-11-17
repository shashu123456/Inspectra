"""TLS verification check: inspects the certificate and protocol version."""

from __future__ import annotations

import ssl

from inspectra.analysis.recommendations import renew_certificate
from inspectra.checks import CheckError
from inspectra.checks.context import ScanContext
from inspectra.models import Confidence, Finding, Severity, Target
from inspectra.network import TlsInfo, inspect_tls

WARN_EXPIRY_DAYS = 30
CRITICAL_EXPIRY_DAYS = 7
MIN_TLS_RANK = 1.2  # TLS 1.2


def run(target: Target, context: ScanContext) -> list[Finding]:
    """Perform a TLS handshake and report certificate and protocol findings."""
    port = target.port if target.port not in (None, 80) else 443
    try:
        info = _inspect_tls_cached(target.hostname, port, context)
    except (TimeoutError, ssl.SSLError, ssl.CertificateError, OSError) as exc:
        if target.scheme == "http":
            return [_https_unavailable(target, port, exc)]
        raise CheckError(f"TLS inspection failed for {target.hostname}: {exc}") from exc

    context.tls = info
    findings: list[Finding] = []
    if info.is_expired:
        findings.append(_expired(info))
    elif info.days_remaining <= CRITICAL_EXPIRY_DAYS:
        findings.append(_expires_soon(info, critical=True))
    elif info.days_remaining <= WARN_EXPIRY_DAYS:
        findings.append(_expires_soon(info, critical=False))
    if info.is_self_signed:
        findings.append(_self_signed(info))
    if not info.hostname_matches:
        findings.append(_hostname_mismatch(info))
    rank = _version_rank(info.version)
    if rank < MIN_TLS_RANK:
        findings.append(_weak_protocol(info))
    elif rank == MIN_TLS_RANK:
        findings.append(_tls12_only(info))
    findings.append(_certificate_summary(info))
    return findings


def _inspect_tls_cached(hostname: str, port: int, context: ScanContext) -> TlsInfo:
    key = (hostname, port)
    with context.cache_lock:
        cached = context.tls_cache.get(key)
    if cached is not None:
        if isinstance(cached, Exception):
            raise cached
        return cached
    try:
        info = inspect_tls(
            hostname, port, insecure=context.options.allow_insecure if context.options else False
        )
    except Exception as exc:
        with context.cache_lock:
            existing = context.tls_cache.get(key)
            if existing is not None:
                if isinstance(existing, Exception):
                    raise existing from None
                return existing
            context.tls_cache[key] = exc
        raise
    with context.cache_lock:
        existing = context.tls_cache.get(key)
        if existing is not None:
            if isinstance(existing, Exception):
                raise existing from None
            return existing
        context.tls_cache[key] = info
    return info


def _https_unavailable(target: Target, port: int, exc: Exception) -> Finding:
    return Finding(
        rule_id="TLS-001",
        title="HTTPS not available",
        category="tls",
        severity=Severity.MEDIUM,
        confidence=Confidence.HIGH,
        description=(f"Could not establish a TLS connection to {target.hostname}:{port}: {exc}"),
        why_it_matters=(
            "Without HTTPS, all traffic — including credentials — is transmitted in plaintext."
        ),
        recommendation="Enable TLS on the server and redirect HTTP traffic to HTTPS.",
        evidence=[f"TLS handshake to {target.hostname}:{port} failed"],
    )


def _expired(info: TlsInfo) -> Finding:
    return Finding(
        rule_id="TLS-002",
        title="TLS certificate is expired",
        category="tls",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        description=(
            f"The certificate for this host expired on "
            f"{info.not_valid_after:%Y-%m-%d} and is no longer trusted by clients."
        ),
        why_it_matters=(
            "Expired certificates break encryption for users and can indicate "
            "neglected infrastructure."
        ),
        recommendation=renew_certificate(0),
        evidence=[f"Not valid after: {info.not_valid_after:%Y-%m-%d}"],
    )


def _expires_soon(info: TlsInfo, critical: bool) -> Finding:
    severity = Severity.HIGH if critical else Severity.MEDIUM
    return Finding(
        rule_id="TLS-003",
        title=f"TLS certificate expires soon ({info.days_remaining} days)",
        category="tls",
        severity=severity,
        confidence=Confidence.HIGH,
        description=(
            f"The certificate expires on {info.not_valid_after:%Y-%m-%d} "
            f"({info.days_remaining} days from now)."
        ),
        why_it_matters="Certificates that expire cause service outages and break trust for users.",
        recommendation=renew_certificate(info.days_remaining),
        evidence=[f"Not valid after: {info.not_valid_after:%Y-%m-%d}"],
    )


def _self_signed(info: TlsInfo) -> Finding:
    return Finding(
        rule_id="TLS-004",
        title="TLS certificate is self-signed",
        category="tls",
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        description="The presented certificate is self-signed and not issued by a trusted CA.",
        why_it_matters=(
            "Self-signed certificates do not protect against man-in-the-middle "
            "attacks unless clients are configured to pin them."
        ),
        recommendation=(
            "Obtain a certificate from a public CA (e.g. Let's Encrypt) or pin "
            "the certificate on all clients."
        ),
        evidence=[f"Issuer: {info.issuer}", f"Subject: {info.subject_cn}"],
    )


def _hostname_mismatch(info: TlsInfo) -> Finding:
    return Finding(
        rule_id="TLS-005",
        title="TLS certificate hostname mismatch",
        category="tls",
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        description=(
            "The certificate does not cover the hostname being scanned "
            f"(SANs: {', '.join(info.san_dns) or 'none'})."
        ),
        why_it_matters=(
            "A certificate for the wrong hostname triggers browser warnings and can "
            "signal a misconfigured or intercepted connection."
        ),
        recommendation="Issue a certificate that includes the scanned hostname in its SANs.",
        evidence=[
            f"Subject CN: {info.subject_cn}",
            f"SANs: {', '.join(info.san_dns) or 'none'}",
        ],
    )


def _weak_protocol(info: TlsInfo) -> Finding:
    return Finding(
        rule_id="TLS-006",
        title="Weak TLS protocol version in use",
        category="tls",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        description=f"The server negotiated {info.version}, which is below TLS 1.2.",
        why_it_matters=(
            "TLS 1.0 and 1.1 have known protocol weaknesses and are deprecated; "
            "modern clients may refuse to connect."
        ),
        recommendation="Disable TLS 1.0/1.1 and require TLS 1.2 or newer.",
        evidence=[f"Negotiated protocol: {info.version}"],
    )


def _tls12_only(info: TlsInfo) -> Finding:
    return Finding(
        rule_id="TLS-007",
        title="TLS 1.2 in use; TLS 1.3 recommended",
        category="tls",
        severity=Severity.INFO,
        confidence=Confidence.HIGH,
        description=f"The server negotiated {info.version}. TLS 1.3 is preferred where supported.",
        why_it_matters=(
            "TLS 1.3 removes legacy algorithms and improves handshake security and performance."
        ),
        recommendation="Enable TLS 1.3 in addition to TLS 1.2.",
        evidence=[f"Negotiated protocol: {info.version}"],
    )


def _certificate_summary(info: TlsInfo) -> Finding:
    return Finding(
        rule_id="TLS-008",
        title="TLS certificate details",
        category="tls",
        severity=Severity.INFO,
        confidence=Confidence.HIGH,
        description="Summary of the certificate presented during the TLS handshake.",
        why_it_matters="Certificate details help confirm the identity and health of the service.",
        recommendation="None required; informational.",
        evidence=[
            f"Protocol: {info.version}",
            f"Cipher: {info.cipher}",
            f"Subject CN: {info.subject_cn}",
            f"Issuer: {info.issuer}",
            f"Valid from: {info.not_valid_before:%Y-%m-%d}",
            f"Valid until: {info.not_valid_after:%Y-%m-%d}",
            f"SANs: {', '.join(info.san_dns) or 'none'}",
        ],
    )


def _version_rank(version: str) -> float:
    """Turn a protocol string like 'TLSv1.3' into a comparable number."""
    if version.startswith("SSLv"):
        return 0.0
    digits = version.removeprefix("TLSv")
    try:
        numbers = [int(part) for part in digits.split(".")]
    except ValueError:
        return 0.0
    if len(numbers) >= 2:
        return float(f"{numbers[0]}.{numbers[1]}")
    return float(numbers[0])
