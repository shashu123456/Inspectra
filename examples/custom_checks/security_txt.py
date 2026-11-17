"""Example custom check: verifies /.well-known/security.txt exists."""

from __future__ import annotations

from inspectra.checks.context import ScanContext
from inspectra.models import Confidence, Finding, Severity, Target

RULE_ID = "CUST-001"
TITLE = "Security.txt file is exposed at /.well-known/security.txt"


def check(target: Target, context: ScanContext) -> list[Finding]:
    """GET /.well-known/security.txt and report if present."""
    client = context.client
    if client is None:
        return []

    url = f"{target.base_url}/.well-known/security.txt"
    try:
        response = client.get(url)
    except Exception:
        return []

    if response.status_code == 200:
        return [
            Finding(
                rule_id=RULE_ID,
                title=TITLE,
                category="custom",
                severity=Severity.INFO,
                confidence=Confidence.HIGH,
                description=(
                    f"A security.txt file was found at {url}. "
                    "This helps security researchers contact you about vulnerabilities."
                ),
                why_it_matters=(
                    "security.txt provides a standard way for security researchers "
                    "to disclose vulnerabilities to an organization."
                ),
                recommendation=(
                    "Review the security.txt contact information and ensure it is current."
                ),
                evidence=[f"GET {url} -> {response.status_code}"],
            )
        ]
    return []
