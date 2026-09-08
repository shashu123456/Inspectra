"""robots.txt inspection check.

The standard library's ``robotparser`` cannot list disallowed paths, so this
check uses a small purpose-built parser for the subset of the robots.txt
format that matters for assessment.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from inspectra.checks.context import ScanContext
from inspectra.models import Confidence, Finding, Severity, Target

MAX_DISALLOWED_EVIDENCE = 15


@dataclass(slots=True)
class RobotsInfo:
    """Parsed subset of a robots.txt file."""

    user_agents: list[str] = field(default_factory=list)
    disallowed: list[str] = field(default_factory=list)
    allowed: list[str] = field(default_factory=list)
    sitemaps: list[str] = field(default_factory=list)


def parse_robots(text: str) -> RobotsInfo:
    """Parse the directives that matter for assessment."""
    info = RobotsInfo()
    current_agents: list[str] = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        key, _, value = line.partition(":")
        key, value = key.strip().lower(), value.strip()
        if key == "user-agent":
            current_agents = [value] if value else []
        elif key == "disallow" and value:
            info.disallowed.append(value)
            if current_agents and current_agents[0] not in info.user_agents:
                info.user_agents.append(current_agents[0])
        elif key == "allow" and value:
            info.allowed.append(value)
        elif key == "sitemap" and value:
            info.sitemaps.append(value)
    return info


def run(target: Target, context: ScanContext) -> list[Finding]:
    """Analyze the robots.txt response cached by the HTTP check."""
    if context.robots_response is None:
        return []
    response = context.robots_response
    if response.status_code == 404 or not response.text.strip():
        return [_missing(target)]
    info = parse_robots(response.text)
    findings: list[Finding] = []
    if info.disallowed:
        findings.append(_disallowed(target, info))
    if info.sitemaps:
        findings.append(_sitemap(info))
    return findings


def _missing(target: Target) -> Finding:
    return Finding(
        rule_id="ROB-001",
        title="robots.txt not found",
        category="robots",
        severity=Severity.INFO,
        confidence=Confidence.MEDIUM,
        description=f"GET {target.base_url}/robots.txt returned HTTP 404 (not found).",
        why_it_matters=(
            "robots.txt is a courtesy for crawlers; its absence is not a "
            "vulnerability, but it may be intentional or an oversight."
        ),
        recommendation=(
            "Add a robots.txt if you want to control crawler access. "
            "Note that it is not a security control."
        ),
        evidence=["GET /robots.txt -> 404"],
    )


def _disallowed(target: Target, info: RobotsInfo) -> Finding:
    return Finding(
        rule_id="ROB-002",
        title="robots.txt disallows crawler access to paths",
        category="robots",
        severity=Severity.INFO,
        confidence=Confidence.HIGH,
        description=(f"robots.txt disallows {len(info.disallowed)} path(s) from crawlers."),
        why_it_matters=(
            "Disallowed paths are excluded from search engines, not from "
            "attackers. Anything listed here should be reviewed for exposure."
        ),
        recommendation=(
            "Review the disallowed paths: sensitive content should be protected by "
            "authentication, not just robots.txt."
        ),
        evidence=info.disallowed[:MAX_DISALLOWED_EVIDENCE],
    )


def _sitemap(info: RobotsInfo) -> Finding:
    return Finding(
        rule_id="ROB-003",
        title="Sitemap referenced in robots.txt",
        category="robots",
        severity=Severity.INFO,
        confidence=Confidence.HIGH,
        description=f"robots.txt references {len(info.sitemaps)} sitemap location(s).",
        why_it_matters=(
            "Sitemaps expose the site structure to crawlers (and to anyone reading robots.txt)."
        ),
        recommendation="Confirm the sitemap does not list sensitive or unpublished URLs.",
        evidence=info.sitemaps[:MAX_DISALLOWED_EVIDENCE],
    )
