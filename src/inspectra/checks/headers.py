"""Security header assessment check.

The rules live in ``data/header_rules.json`` (versioned, reviewable, and easy
to extend without touching code). Rules support three outcomes:

* missing — the header is absent and should be present
* weak — the header is present but its value does not meet the rule pattern
* present — the header is present but should not be (e.g. X-Powered-By)
"""

from __future__ import annotations

import re
from typing import Any

import httpx

from inspectra.analysis.recommendations import remove_header
from inspectra.checks.context import ScanContext
from inspectra.models import Confidence, Finding, Severity, Target
from inspectra.utils import load_json


def run(target: Target, context: ScanContext) -> list[Finding]:
    """Evaluate the security headers of the cached HTTP response."""
    if context.http_response is None:
        return []
    findings: list[Finding] = []
    for rule in load_json("header_rules.json"):
        findings.extend(_evaluate_rule(rule, context.http_response.headers, target.hostname))
    return findings


def _evaluate_rule(rule: dict[str, Any], headers: httpx.Headers, hostname: str) -> list[Finding]:
    name = rule["name"]
    value = headers.get(name)
    if value is None:
        if rule.get("severity_when_missing"):
            return [_missing(rule, hostname)]
        return []
    if rule.get("severity_when_present"):
        return [_present(rule, value, hostname)]
    if rule.get("pattern") and not re.search(rule["pattern"], value, re.IGNORECASE):
        return [_weak(rule, value, hostname)]
    return []


def _missing(rule: dict[str, Any], hostname: str) -> Finding:
    return Finding(
        rule_id=rule["id"],
        title=f"Missing security header: {rule['name']}",
        category="security_headers",
        severity=Severity(rule["severity_when_missing"]),
        confidence=Confidence.MEDIUM,
        description=f"The {rule['name']} response header was not present on {hostname}.",
        why_it_matters=rule["explanation"],
        recommendation=rule["recommendation"],
        evidence=["Header not present in the HTTP response"],
    )


def _weak(rule: dict[str, Any], value: str, hostname: str) -> Finding:
    return Finding(
        rule_id=rule["id"],
        title=f"Weak security header value: {rule['name']}",
        category="security_headers",
        severity=Severity(rule.get("severity_when_weak", "low")),
        confidence=Confidence.MEDIUM,
        description=(
            f"The {rule['name']} header on {hostname} is present but its value "
            "does not meet the recommended configuration."
        ),
        why_it_matters=rule["explanation"],
        recommendation=rule["recommendation"],
        evidence=[f"{rule['name']}: {value}"],
    )


def _present(rule: dict[str, Any], value: str, hostname: str) -> Finding:
    return Finding(
        rule_id=rule["id"],
        title=f"Header should be removed: {rule['name']}",
        category="security_headers",
        severity=Severity(rule["severity_when_present"]),
        confidence=Confidence.HIGH,
        description=f"The {rule['name']} header is present on {hostname}.",
        why_it_matters=rule["explanation"],
        recommendation=remove_header(rule["name"]),
        evidence=[f"{rule['name']}: {value}"],
    )
