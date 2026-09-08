"""Scan orchestrator: runs the registered checks and applies the risk engine."""

from __future__ import annotations

import logging
from collections.abc import Callable
from datetime import UTC, datetime

from inspectra import __version__
from inspectra.analysis import risk
from inspectra.checks import CheckError, FatalCheckError, ordered_checks
from inspectra.checks.context import ScanContext
from inspectra.models import ScanMetadata, ScanOptions, ScanResult, Target
from inspectra.network import build_client

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

    risk.apply(result)
    result.metadata.finished_at = datetime.now(UTC)
    result.metadata.duration_seconds = (result.metadata.finished_at - started).total_seconds()
    return result
