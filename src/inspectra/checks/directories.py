"""Opt-in directory observation check.

Deliberately conservative: GET-only, one request every
:data:`REQUEST_DELAY_SECONDS`, single-threaded, and only 2xx/3xx responses
are reported. It never follows up, never sends payloads, and never tries to
exploit anything it finds.
"""

from __future__ import annotations

import time
from pathlib import Path

from inspectra.analysis.recommendations import review_exposed_path
from inspectra.checks.context import ScanContext
from inspectra.models import Confidence, Finding, Severity, Target
from inspectra.utils import load_text_lines

REQUEST_DELAY_SECONDS = 0.5
FOUND_STATUSES = {200, 201, 202, 204, 301, 302, 303, 307, 308}
MAX_PATH_EVIDENCE = 20

#: Paths whose exposure is more serious than a generic 2xx response.
SENSITIVE_PATHS: dict[str, Severity] = {
    "/.git/": Severity.HIGH,
    "/.git/config": Severity.HIGH,
    "/.git/HEAD": Severity.HIGH,
    "/.env": Severity.HIGH,
    "/.env.local": Severity.HIGH,
    "/.aws/": Severity.HIGH,
    "/.ssh/": Severity.HIGH,
    "/.htpasswd": Severity.HIGH,
    "/dump.sql": Severity.HIGH,
    "/server.crt": Severity.HIGH,
    "/server.key": Severity.HIGH,
    "/id_rsa": Severity.HIGH,
    "/key.pem": Severity.HIGH,
    "/credentials": Severity.HIGH,
    "/actuator/env": Severity.HIGH,
    "/proc/self/environ": Severity.HIGH,
    "/etc/passwd": Severity.HIGH,
    "/backup": Severity.MEDIUM,
    "/backups": Severity.MEDIUM,
    "/config.php": Severity.MEDIUM,
    "/config.json": Severity.MEDIUM,
    "/server-status": Severity.MEDIUM,
    "/server-info": Severity.MEDIUM,
    "/phpinfo.php": Severity.MEDIUM,
    "/admin": Severity.MEDIUM,
    "/administrator": Severity.MEDIUM,
    "/phpmyadmin": Severity.MEDIUM,
    "/web.config": Severity.MEDIUM,
    "/actuator/beans": Severity.MEDIUM,
}


def run(target: Target, context: ScanContext) -> list[Finding]:
    """Probe the wordlist and report accessible paths (opt-in)."""
    if context.http_response is None or context.client is None:
        return []
    client = context.client
    base = target.base_url
    found: list[tuple[str, int]] = []
    for path in _wordlist(context):
        try:
            response = client.get(f"{base}{path}")
        except Exception:
            continue
        if response.status_code in FOUND_STATUSES:
            found.append((path, response.status_code))
        time.sleep(REQUEST_DELAY_SECONDS)

    if not found:
        return []
    findings = [_summary(target, found)]
    for path, status in found:
        if path in SENSITIVE_PATHS:
            findings.append(_sensitive(path, status))
    return findings


def _wordlist(context: ScanContext) -> list[str]:
    if context.options is not None and context.options.directory_wordlist:
        text = Path(context.options.directory_wordlist).read_text(encoding="utf-8")
        return [
            line.strip()
            for line in text.splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        ]
    return load_text_lines("directory_wordlist.txt")


def _summary(target: Target, found: list[tuple[str, int]]) -> Finding:
    return Finding(
        rule_id="DIR-001",
        title=f"{len(found)} accessible path(s) discovered",
        category="directories",
        severity=Severity.INFO,
        confidence=Confidence.HIGH,
        description=(
            f"{len(found)} of the probed paths on {target.hostname} returned a successful response."
        ),
        why_it_matters=(
            "Accessible paths reveal the application's structure and may expose "
            "dashboards, backups or configuration files."
        ),
        recommendation="Review each discovered path and restrict or remove anything unintended.",
        evidence=[f"{status} {path}" for path, status in found[:MAX_PATH_EVIDENCE]],
    )


def _sensitive(path: str, status: int) -> Finding:
    return Finding(
        rule_id="DIR-002",
        title=f"Sensitive path accessible: {path}",
        category="directories",
        severity=SENSITIVE_PATHS[path],
        confidence=Confidence.MEDIUM,
        description=f"The sensitive path {path!r} returned HTTP {status}.",
        why_it_matters=(
            "This path frequently contains secrets, source code or administrative "
            "interfaces; its exposure is a serious risk."
        ),
        recommendation=review_exposed_path(path),
        evidence=[f"{status} {path}"],
    )
