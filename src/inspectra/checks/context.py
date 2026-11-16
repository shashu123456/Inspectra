"""Shared state passed between checks during a scan."""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from typing import Any

import httpx

from inspectra.models import ScanOptions
from inspectra.network import TlsInfo


@dataclass(slots=True)
class ScanContext:
    """Carries shared resources and intermediate results between checks.

    Checks run in a fixed order; later checks consume values that earlier
    checks stored here (for example, the HTTP check stores the primary
    response so the headers and fingerprint checks do not re-fetch).

    Runtime-only per-run object: contains threading locks/caches and must not
    be pickled, deep-copied, or serialized (no ScanContext serialization/copy
    usage exists in src/ or tests/ as of M5).
    """

    client: Any = None
    options: ScanOptions | None = None
    http_response: httpx.Response | None = None
    robots_response: httpx.Response | None = None
    dns_records: dict[str, list[str]] = field(default_factory=dict)
    dns_elapsed: float = 0.0
    tls: TlsInfo | None = None
    dns_cache: dict[str, tuple[dict[str, list[str]], float]] = field(default_factory=dict)
    dns_locks: dict[str, threading.Lock] = field(default_factory=dict)
    tls_cache: dict[tuple[str, int], TlsInfo | Exception] = field(default_factory=dict)
    cache_lock: threading.Lock = field(default_factory=threading.Lock)
