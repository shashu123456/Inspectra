"""Scan orchestrator: runs the registered checks and applies the risk engine."""

from __future__ import annotations

import hashlib
import json
import logging
import threading
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from inspectra import __version__
from inspectra.analysis import risk
from inspectra.baseline import fingerprint_for
from inspectra.checks import CheckError, FatalCheckError, ordered_checks
from inspectra.checks.context import ScanContext
from inspectra.models import Finding, ScanMetadata, ScanOptions, ScanResult, Target
from inspectra.redact import redact_evidence
from inspectra.replay import FixtureStore, Recorder, Replayer, ReplayMissError
from inspectra.utils import truncate

logger = logging.getLogger("inspectra")

ProgressCallback = Callable[[str], None]


class ScanAborted(Exception):
    """Raised when a fatal problem prevents the scan from completing."""


REPLAY_SKIPPED_CHECKS = ("dns", "ports", "tls")
REPLAY_SKIP_REASON = "requires live network; not available in replay"


def run_scan(
    target: Target,
    options: ScanOptions,
    progress: ProgressCallback | None = None,
) -> ScanResult:
    """Execute all checks against the target and produce a scored result.

    Individual check failures degrade gracefully (logged, scan continues);
    only :class:`FatalCheckError` aborts the scan.

    When ``options.concurrency`` is greater than 1, checks run concurrently
    using a thread pool. A per-host semaphore (max 2 in-flight requests)
    prevents overwhelming any single host.
    """
    started = datetime.now(timezone.utc)
    metadata = ScanMetadata(version=__version__, target=target.input, started_at=started)
    result = ScanResult(target=target, metadata=metadata)
    context = ScanContext(options=options)

    # M4: replay mode never opens a socket; record mode wraps the client.
    # Validate the replay directory before any check runs: a missing or empty
    # fixture dir means the scan cannot produce meaningful results and must
    # fail fast instead of going green with zero findings.
    store: FixtureStore | None = None
    _client_context: Any = None
    if options.replay_dir:
        replay_dir = Path(options.replay_dir)
        if not replay_dir.is_dir():
            raise ScanAborted(
                f"Replay directory not found: {replay_dir}. "
                "Run with --save-fixtures first to create fixtures."
            )
        index_path = replay_dir / "index.json"
        if not index_path.is_file():
            raise ScanAborted(
                f"No fixture index in replay directory: {replay_dir}. "
                "Run with --save-fixtures first to create fixtures."
            )
        index = json.loads(index_path.read_text(encoding="utf-8"))
        if not index:
            raise ScanAborted(
                f"Replay directory is empty: {replay_dir}. "
                "Run with --save-fixtures first to create fixtures."
            )
        store = FixtureStore(replay_dir)
        context.client = Replayer(store)
        result.skipped = [
            {"check": name, "reason": REPLAY_SKIP_REASON} for name in REPLAY_SKIPPED_CHECKS
        ]
    elif options.save_fixtures:
        from inspectra.network import RateLimitedClient, build_client  # lazy

        store = FixtureStore(options.save_fixtures)
        client = build_client()
        wrapped = RateLimitedClient(client, max_per_host=2, delay=options.delay)
        context.client = Recorder(wrapped, store)
        _client_context = wrapped
    else:
        from inspectra.network import RateLimitedClient, build_client  # lazy

        client = build_client()
        wrapped = RateLimitedClient(client, max_per_host=2, delay=options.delay)
        context.client = wrapped
        _client_context = wrapped

    checks = list(ordered_checks(options.directories))
    try:
        if options.replay_dir:
            # Replayer has no context manager; run directly.
            # Replay mode serves HTTP fixtures only: skip checks that need raw sockets.
            for name, check in checks:
                if name in REPLAY_SKIPPED_CHECKS:
                    continue
                if progress is not None:
                    progress(name)
                try:
                    result.findings.extend(check(target, context))
                except FatalCheckError as exc:
                    raise ScanAborted(str(exc)) from exc
                except ReplayMissError as exc:
                    raise ScanAborted(
                        f"No replay fixture for {exc.url}. "
                        "Run with --save-fixtures first to create fixtures."
                    ) from exc
                except CheckError as exc:
                    logger.warning("Check '%s' skipped: %s", name, exc)
                    result.skipped.append({"check": name, "reason": str(exc)})
                except Exception as exc:  # defensive: never let one check kill a scan
                    logger.warning("Check '%s' failed unexpectedly: %s", name, exc)
        elif options.concurrency == 1 and options.delay == 0:
            with _client_context:
                for name, check in checks:
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
                _run_concurrently(target, context, options, checks, progress, result)
    finally:
        if _client_context is not None and not options.replay_dir:
            _client_context.close()

    # Sort findings deterministically so concurrency doesn't affect output order.
    result.findings.sort(
        key=lambda f: (
            f.rule_id,
            f.title,
            f.category,
            f.severity.value,
            f.evidence[0] if f.evidence else "",
        )
    )

    result.checks_run = len(checks)
    result.checks_skipped = [item["check"] for item in result.skipped]

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
    result.metadata.finished_at = datetime.now(timezone.utc)
    result.metadata.duration_seconds = (result.metadata.finished_at - started).total_seconds()
    return result


def _run_concurrently(
    target: Target,
    context: ScanContext,
    options: ScanOptions,
    checks: list[tuple[str, Callable[[Target, ScanContext], list[Finding]]]],
    progress: ProgressCallback | None,
    result: ScanResult,
) -> None:
    """Run checks with bounded concurrency while respecting data dependencies.

    - ``dns`` runs first (resolves/populates target state).
    - ``http`` runs in the next phase and populates cached responses.
    - ``headers``, ``fingerprint``, ``robots`` depend on HTTP responses and run
      only after ``http`` completes.
    - Other checks run in the earliest phase where their dependencies are met.
    Findings are merged in canonical check order for deterministic output.
    """
    max_workers = max(1, options.concurrency)
    progress_lock = threading.Lock()
    check_map = dict(checks)
    remaining = [name for name, _ in checks]
    findings_by_name: dict[str, list[Finding]] = {}
    completed: set[str] = set()

    def on_progress(name: str) -> None:
        if progress is None:
            return
        with progress_lock:
            progress(name)

    def ready_names() -> list[str]:
        ready: list[str] = []
        for name in remaining:
            if name in completed:
                continue
            if name == "http":
                deps_ready = "dns" in completed or "dns" not in check_map
            elif name in {"headers", "fingerprint", "robots"}:
                deps_ready = "http" in completed or "http" not in check_map
            elif name == "dns":
                deps_ready = True
            else:
                deps_ready = "dns" in completed or "dns" not in check_map
            if deps_ready:
                ready.append(name)
        return ready

    while remaining:
        batch = ready_names()
        if not batch:
            batch = [remaining[0]]
        # Remove selected batch from remaining, preserving order tracking.
        for name in batch:
            if name in remaining:
                remaining.remove(name)

        if max_workers == 1 or len(batch) == 1:
            for name in batch:
                on_progress(name)
                try:
                    findings_by_name[name] = _run_single_check(target, context, check_map[name])
                except FatalCheckError as exc:
                    raise ScanAborted(str(exc)) from exc
                except CheckError as exc:
                    logger.warning("Check '%s' skipped: %s", name, exc)
                    result.skipped.append({"check": name, "reason": str(exc)})
                    findings_by_name[name] = []
                except Exception as exc:  # defensive: never let one check kill a scan
                    logger.warning("Check '%s' failed unexpectedly: %s", name, exc)
                    findings_by_name[name] = []
                completed.add(name)
            continue

        with ThreadPoolExecutor(max_workers=min(max_workers, len(batch))) as executor:
            futures = {}
            for name in batch:
                on_progress(name)
                futures[executor.submit(_run_single_check, target, context, check_map[name])] = name
            for future in as_completed(futures):
                name = futures[future]
                try:
                    findings_by_name[name] = future.result()
                except FatalCheckError as exc:
                    raise ScanAborted(str(exc)) from exc
                except CheckError as exc:
                    logger.warning("Check '%s' skipped: %s", name, exc)
                    result.skipped.append({"check": name, "reason": str(exc)})
                    findings_by_name[name] = []
                except Exception as exc:  # defensive
                    logger.warning("Check '%s' failed unexpectedly: %s", name, exc)
                    findings_by_name[name] = []
                completed.add(name)

    for name, _ in checks:
        result.findings.extend(findings_by_name.get(name, []))


def _run_single_check(
    target: Target,
    context: ScanContext,
    check: Callable[[Target, ScanContext], list[Finding]],
) -> list[Finding]:
    """Run a single check and return its findings."""
    return check(target, context)


def _evidence_hash(evidence: list[str]) -> str:
    """SHA-256 of canonical JSON of the evidence list, truncated to 16 chars."""
    canonical = json.dumps(evidence, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:16]
