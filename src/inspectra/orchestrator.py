"""Scan orchestrator: runs the registered checks and applies the risk engine."""

from __future__ import annotations

import logging
from collections.abc import Callable
from datetime import UTC, datetime

from inspectra import __version__
from inspectra.analysis import risk
from inspectra.baseline import fingerprint_for
from inspectra.checks import CheckError, FatalCheckError, ordered_checks
from inspectra.checks.context import ScanContext
from inspectra.models import ScanMetadata, ScanOptions, ScanResult, Target
from inspectra.redact import redact_evidence
from inspectra.utils import truncate

logger = logging.getLogger("inspectra")

ProgressCallback = Callable[[str], None]


class ScanAborted(Exception):
    """Raised when a fatal problem prevents the scan from completing."""


def run_scan(
    target: Target,
    options: ScanOptions,
    progress: ProgressCallback | None = None,
) -> ScanResult:
    """Execute all checks against the target and produce a scored result.

    Individual check failures degrade gracefully (logged, scan continues);
    only :class:`FatalCheckError` aborts the scan.
    """
    started = datetime.now(UTC)
    metadata = ScanMetadata(version=__version__, target=target.input, started_at=started)
    result = ScanResult(target=target, metadata=metadata)
    context = ScanContext(options=options)

    from inspectra.network import build_client  # lazy: keeps CLI startup fast

    with build_client() as client:
        context.client = client
        for name, check in ordered_checks(options.directories):
            if progress is not None:
                progress(name)
            try:
                result.findings.extend(check(target, context))
            except FatalCheckError as exc:
                raise ScanAborted(str(exc)) from exc
            except CheckError as exc:
                logger.warning("Check '%s' skipped: %s", name, exc)
            except Exception as exc:  # defensive: never let one check kill a scan
                logger.warning("Check '%s' failed unexpectedly: %s", name, exc)

    for finding in result.findings:
        finding.evidence = [truncate(line) for line in finding.evidence]
        evidence_text = finding.evidence[0] if finding.evidence else None
        finding.fingerprint = fingerprint_for(
            finding.rule_id, result.target.base_url, evidence_text
        )
    risk.apply(result)
    if not options.no_redact:
        for finding in result.findings:
            finding.evidence = redact_evidence(finding.evidence)
    result.metadata.finished_at = datetime.now(UTC)
    result.metadata.duration_seconds = (result.metadata.finished_at - started).total_seconds()
    return result
