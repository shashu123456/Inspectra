"""SARIF report renderer: machine-readable output for CI code scanning.

Produces SARIF 2.1.0 compatible output that GitHub Code Scanning can ingest.
Each Inspectra finding maps to a SARIF result with rule metadata, so GitHub
shows readable rule names and deduplicates across runs.
"""

from __future__ import annotations

import json
from pathlib import Path

from inspectra import __version__
from inspectra.models import Finding, ScanResult, Severity

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
SARIF_VERSION = "2.1.0"
TOOL_NAME = "Inspectra"
TOOL_INFO_URI = "https://github.com/shashu123456/inspectra"

RULE_HELP_URI = f"{TOOL_INFO_URI}/blob/main/docs/usage.md#reading-the-report"

_SEVERITY_TO_LEVEL = {
    Severity.INFO: "note",
    Severity.LOW: "note",
    Severity.MEDIUM: "warning",
    Severity.HIGH: "error",
}


def _rule_id(finding: Finding) -> str:
    return finding.rule_id


def _build_rules(findings: list[Finding]) -> list[dict[str, object]]:
    """One rule entry per unique check id, in first-seen order."""
    seen: dict[str, Finding] = {}
    for finding in findings:
        if finding.rule_id not in seen:
            seen[finding.rule_id] = finding
    rules: list[dict[str, object]] = []
    for finding in seen.values():
        rules.append(
            {
                "id": finding.rule_id,
                "name": finding.title,
                "helpUri": RULE_HELP_URI,
                "shortDescription": {"text": finding.title},
                "fullDescription": {"text": finding.why_it_matters},
                "help": {
                    "text": f"{finding.why_it_matters}\n\nRecommendation: {finding.recommendation}"
                },
                "properties": {
                    "confidence": finding.confidence.value,
                    "category": finding.category,
                },
            }
        )
    return rules


def _build_results(findings: list[Finding]) -> list[dict[str, object]]:
    results: list[dict[str, object]] = []
    for index, finding in enumerate(findings):
        # Build physical location from evidence if a URL/path exists.
        location = None
        if finding.evidence:
            evidence_text = finding.evidence[0]
            region: dict[str, object] = {"startLine": 1, "snippet": {"text": evidence_text[:200]}}
            # If the evidence looks like a URL, put it as artifactLocation.
            if evidence_text.startswith(("http://", "https://")):
                location = {
                    "physicalLocation": {
                        "artifactLocation": {"uri": evidence_text},
                        "region": region,
                    }
                }
            else:
                location = {
                    "physicalLocation": {
                        "region": region,
                    }
                }
        result: dict[str, object] = {
            "ruleId": finding.rule_id,
            "ruleIndex": index,
            "level": _SEVERITY_TO_LEVEL[finding.severity],
            "message": {
                "text": finding.title,
                "markdown": finding.why_it_matters,
            },
            "fixes": [
                {
                    "description": {"text": finding.recommendation},
                }
            ],
            "properties": {
                "confidence": finding.confidence.value,
                "category": finding.category,
                "evidenceHash": finding.evidence_hash,
            },
        }
        if location is not None:
            result["locations"] = [location]
        results.append(result)
    return results


def render(result: ScanResult) -> dict[str, object]:
    """Serialize a :class:`ScanResult` into a SARIF 2.1.0 dictionary."""
    run_properties: dict[str, object] = {}
    if result.scope:
        run_properties["scope"] = result.scope["scope"]
    if result.redaction:
        run_properties["redaction"] = result.redaction["redaction"]

    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": TOOL_NAME,
                        "version": __version__,
                        "informationUri": TOOL_INFO_URI,
                        "rules": _build_rules(result.findings),
                    }
                },
                "results": _build_results(result.findings),
                "properties": run_properties,
            }
        ],
    }


def write(result: ScanResult, path: Path) -> None:
    """Write the SARIF report to ``path``."""
    path.write_text(json.dumps(render(result), indent=2) + "\n", encoding="utf-8")
