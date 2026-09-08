"""Technology fingerprinting check.

Signatures live in ``data/fingerprints.json`` and match against response
headers, cookies, the HTML ``<meta name="generator">`` tag, and body content.
"""

from __future__ import annotations

import re
from typing import Any

import httpx

from inspectra.checks.context import ScanContext
from inspectra.models import Confidence, Finding, Severity, Target
from inspectra.utils import load_json

GENERATOR_RE = re.compile(
    r'<meta[^>]*name=["\']generator["\'][^>]*content=["\']([^"\']+)',
    re.IGNORECASE,
)
VERSION_RE = re.compile(r"\d+(?:\.\d+){1,2}")
MAX_EVIDENCE = 12


def run(target: Target, context: ScanContext) -> list[Finding]:
    """Identify technologies from the cached HTTP response."""
    if context.http_response is None:
        return []
    response = context.http_response
    detected: list[tuple[dict[str, Any], list[str]]] = []
    for signature in load_json("fingerprints.json"):
        evidence = _matches(signature, response)
        if evidence:
            detected.append((signature, evidence))
    if not detected:
        return []

    labels = [
        f"{signature['name']}{_version_suffix(evidence, signature)}"
        for signature, evidence in detected
    ]
    evidence = [line for _, lines in detected for line in lines][:MAX_EVIDENCE]
    return [
        Finding(
            rule_id="FPR-001",
            title="Technologies identified",
            category="fingerprinting",
            severity=Severity.INFO,
            confidence=Confidence.MEDIUM,
            description=(
                f"Identified the following technologies on {target.hostname}: {', '.join(labels)}."
            ),
            why_it_matters=(
                "Known technologies help prioritize patching and reveal the stack "
                "an attacker would study first."
            ),
            recommendation=(
                "Keep all identified components patched and disable version "
                "disclosure where possible."
            ),
            evidence=evidence,
        )
    ]


def _matches(signature: dict[str, Any], response: httpx.Response) -> list[str]:
    evidence: list[str] = []
    for pattern in signature["patterns"]:
        pattern_type = pattern["type"]
        if pattern_type == "header":
            value = response.headers.get(pattern.get("name", ""))
            if value and re.search(pattern["pattern"], value, re.IGNORECASE):
                evidence.append(f"{pattern['name']}: {value}")
        elif pattern_type == "cookie":
            for cookie in response.headers.get_list("set-cookie"):
                if re.search(pattern["pattern"], cookie, re.IGNORECASE):
                    evidence.append(f"Set-Cookie: {cookie}")
        elif pattern_type == "generator":
            match = GENERATOR_RE.search(response.text)
            if match and re.search(pattern["pattern"], match.group(1), re.IGNORECASE):
                evidence.append(f'<meta name="generator" content="{match.group(1)}">')
        elif pattern_type == "body" and re.search(pattern["pattern"], response.text, re.IGNORECASE):
            evidence.append(f"body: /{pattern['pattern']}/")
    return evidence


def _version_suffix(evidence: list[str], signature: dict[str, Any]) -> str:
    """Best-effort version extraction: the first dotted number *after a match*.

    Evidence lines can merge values (e.g. a combined ``Server`` header), so
    the search starts after the position matched by the signature's own
    pattern to avoid borrowing another component's version.
    """
    for line in evidence:
        for pattern in signature["patterns"]:
            matched = re.search(pattern["pattern"], line, re.IGNORECASE)
            if matched:
                version = VERSION_RE.search(line[matched.end() :])
                if version:
                    return f" {version.group(0)}"
    return ""
