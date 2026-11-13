"""Baseline diff support for Inspectra scans.

A baseline is a snapshot of findings from a previous scan. On a subsequent
scan, each finding is classified as ``new`` (not in baseline) or ``existing``
(in baseline). ``--fail-on`` applies only to new findings, so a CI gate can
regress on newly introduced issues without failing on pre-existing ones.
"""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast


def fingerprint_for(rule_id: str, location: str | None, evidence: str | None) -> str:
    """Stable fingerprint for a finding.

    sha256 over the check id plus normalized location and evidence, so the
    same finding produces the same fingerprint across runs even if the
    timestamp or ordering changes.
    """
    parts = [rule_id]
    parts.append(_normalize(location) if location else "")
    parts.append(_normalize(evidence) if evidence else "")
    return hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()


def _normalize(value: str) -> str:
    """Normalize a string for stable fingerprinting."""
    return " ".join(value.lower().split())


def save_baseline(target_input: str, findings: list[dict], path: Path) -> None:
    """Write a baseline file from a list of finding dictionaries."""
    baseline = {
        "target": target_input,
        "generated_at": datetime.now(UTC).isoformat(),
        "findings": findings,
    }
    path.write_text(json.dumps(baseline, indent=2) + "\n", encoding="utf-8")


def load_baseline(path: Path) -> dict[str, Any]:
    """Load a baseline file, returning its parsed contents."""
    return cast(dict[str, Any], json.loads(path.read_text(encoding="utf-8")))


def classify_findings(findings: list[dict], baseline: dict[str, Any] | None) -> dict[str, int]:
    """Mark each finding as ``new`` or ``existing`` against a baseline.

    Returns summary counts: ``{"new": n, "existing": n, "resolved": n}``.
    Each finding dict gains a ``"_baseline_status"`` key.
    """
    baseline_fingerprints: set[str] = set()
    if baseline:
        for bf in baseline.get("findings", []):
            fp = bf.get("fingerprint")
            if fp:
                baseline_fingerprints.add(fp)

    new_count = 0
    existing_count = 0
    for finding in findings:
        fp = finding.get("fingerprint")
        if fp and fp in baseline_fingerprints:
            finding["_baseline_status"] = "existing"
            existing_count += 1
        else:
            finding["_baseline_status"] = "new"
            new_count += 1

    resolved_count = 0
    if baseline:
        current_fingerprints: set[str] = set()
        for finding in findings:
            fp = finding.get("fingerprint")
            if fp:
                current_fingerprints.add(fp)
        for bf in baseline.get("findings", []):
            if bf.get("fingerprint") not in current_fingerprints:
                resolved_count += 1

    return {"new": new_count, "existing": existing_count, "resolved": resolved_count}


def failing_severity(fail_on: str, severity: str) -> bool:
    """True when ``severity`` is at or above ``fail_on`` threshold."""
    order = {"none": -1, "low": 0, "medium": 1, "high": 2}
    threshold = order.get(fail_on, 2)
    level = order.get(severity, 0)
    return level >= threshold
