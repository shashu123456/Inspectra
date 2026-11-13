"""Scan orchestrator: runs the registered checks and applies the risk engine."""

from __future__ import annotations

import hashlib
import json
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
from inspectra.replay import FixtureStore, Recorder, Replayer
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

    # M4: replay mode never opens a socket; record mode wraps the client.
    store: FixtureStore | None = None
    if options.replay_dir:
        store = FixtureStore(options.replay_dir)
        context.client = Replayer(store)
    elif options.save_fixtures:
        from inspectra.network import build_client  # lazy: keeps CLI startup fast

        store = FixtureStore(options.save_fixtures)
        client = build_client()
        context.client = Recorder(client, store)
        _client_context = client
    else:
        from inspectra.network import build_client  # lazy: keeps CLI startup fast

        client = build_client()
        context.client = client
        _client_context = client

    try:
        if options.replay_dir:
            # Replayer has no context manager; run directly.
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
        else:
            with _client_context:
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
    finally:
        if store is not None and not options.replay_dir:
            _client_context.close()

    for finding in result.findings:
        finding.evidence = [truncate(line) for line in finding.evidence]
        evidence_text = finding.evidence[0] if finding.evidence else None
        finding.fingerprint = fingerprint_for(
            finding.rule_id, result.target.base_url, evidence_text
        )
        # M4: evidence_hash over canonical JSON of evidence.
        finding.evidence_hash = _evidence_hash(finding.evidence)
    risk.apply(result)
    if not options.no_redact:
        for finding in result.findings:
            finding.evidence = redact_evidence(finding.evidence)
    result.metadata.finished_at = datetime.now(UTC)
    result.metadata.duration_seconds = (result.metadata.finished_at - started).total_seconds()
    return result


def _evidence_hash(evidence: list[str]) -> str:
    """SHA-256 of canonical JSON of the evidence list, truncated to 16 chars."""
    canonical = json.dumps(evidence, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:16]
