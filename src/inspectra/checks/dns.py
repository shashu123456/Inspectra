"""DNS resolution check: resolves the target and inspects DNS records."""

from __future__ import annotations

import ipaddress
import time

import dns.exception
import dns.resolver

from inspectra.checks import FatalCheckError
from inspectra.checks.context import ScanContext
from inspectra.models import Confidence, Finding, Severity, Target
from inspectra.utils import is_private_address

RECORD_TYPES = ("A", "AAAA", "CNAME", "MX", "NS", "TXT")


def run(target: Target, context: ScanContext) -> list[Finding]:
    """Resolve the target and report DNS observations."""
    if _is_ip_literal(target.hostname):
        _apply_ip_literal(target, context)
        return []

    try:
        records, elapsed = _resolve(target.hostname)
    except dns.exception.Timeout as exc:
        raise FatalCheckError(f"DNS resolution timed out for {target.hostname}.") from exc
    except dns.resolver.NoNameservers as exc:
        raise FatalCheckError(
            f"Could not reach any configured DNS nameserver for {target.hostname}."
        ) from exc
    except dns.resolver.NXDOMAIN as exc:
        raise FatalCheckError(f"Domain {target.hostname} does not exist (NXDOMAIN).") from exc

    context.dns_records = records
    context.dns_elapsed = elapsed
    target.ip_addresses = [*records["A"], *records["AAAA"]]
    target.is_private = any(is_private_address(ip) for ip in target.ip_addresses)

    findings: list[Finding] = []
    if not target.ip_addresses:
        raise FatalCheckError(f"Could not resolve any A/AAAA record for {target.hostname}.")
    if len(target.ip_addresses) > 1:
        findings.append(_multiple_addresses(target))
    if not records["MX"]:
        findings.append(_missing_record("MX"))
    if not records["TXT"]:
        findings.append(_missing_record("TXT"))
    return findings


def _is_ip_literal(hostname: str) -> bool:
    try:
        ipaddress.ip_address(hostname)
    except ValueError:
        return False
    return True


def _apply_ip_literal(target: Target, context: ScanContext) -> None:
    """Targets given as IP addresses need no DNS resolution."""
    address = ipaddress.ip_address(target.hostname)
    target.ip_addresses = [target.hostname]
    target.is_private = not address.is_global
    context.dns_records = {rtype: [] for rtype in RECORD_TYPES}


def _resolve(hostname: str) -> tuple[dict[str, list[str]], float]:
    resolver = dns.resolver.Resolver(configure=True)
    resolver.lifetime = 5.0
    started = time.monotonic()
    records: dict[str, list[str]] = {rtype: [] for rtype in RECORD_TYPES}
    for rtype in RECORD_TYPES:
        try:
            answers = resolver.resolve(hostname, rtype)
        except dns.resolver.NXDOMAIN:
            if rtype == "A":
                raise
            continue
        except dns.resolver.NoAnswer:
            continue
        for answer in answers:
            records[rtype].append(str(answer).rstrip("."))
    return records, time.monotonic() - started


def _multiple_addresses(target: Target) -> Finding:
    return Finding(
        rule_id="DNS-002",
        title="Multiple A/AAAA records (load balancing)",
        category="dns",
        severity=Severity.INFO,
        confidence=Confidence.MEDIUM,
        description=f"The hostname {target.hostname} resolves to multiple addresses.",
        why_it_matters=(
            "Multiple addresses usually indicate load balancing or failover. "
            "Verify that every address belongs to the organization."
        ),
        recommendation=(
            "Confirm every resolved address is expected and under the organization's control."
        ),
        evidence=[f"{target.hostname} -> {', '.join(target.ip_addresses)}"],
    )


def _missing_record(rtype: str) -> Finding:
    if rtype == "MX":
        return Finding(
            rule_id="DNS-003",
            title="No MX records found",
            category="dns",
            severity=Severity.INFO,
            confidence=Confidence.LOW,
            description="No MX records were found for this domain.",
            why_it_matters=(
                "MX records announce where a domain receives email. Their absence "
                "may be intentional for non-mail domains, but if email is expected "
                "it is a misconfiguration."
            ),
            recommendation=(
                "If this domain should receive email, add MX records pointing to your mail servers."
            ),
            evidence=["MX query returned no records"],
        )
    return Finding(
        rule_id="DNS-004",
        title="No TXT records found",
        category="dns",
        severity=Severity.INFO,
        confidence=Confidence.LOW,
        description="No TXT records were found for this domain.",
        why_it_matters=(
            "TXT records carry SPF and DMARC policies that help prevent email "
            "spoofing; their absence leaves the domain easier to impersonate."
        ),
        recommendation=(
            "Add SPF, DMARC (and DKIM where applicable) TXT records if the domain sends email."
        ),
        evidence=["TXT query returned no records"],
    )
