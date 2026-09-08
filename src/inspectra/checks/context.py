"""Shared state passed between checks during a scan."""

from __future__ import annotations

from dataclasses import dataclass, field

import httpx

from inspectra.models import ScanOptions
from inspectra.network import TlsInfo


@dataclass(slots=True)
class ScanContext:
    """Carries shared resources and intermediate results between checks.

    Checks run in a fixed order; later checks consume values that earlier
    checks stored here (for example, the HTTP check stores the primary
    response so the headers and fingerprint checks do not re-fetch).
    """

    client: httpx.Client | None = None
    options: ScanOptions | None = None
    http_response: httpx.Response | None = None
    robots_response: httpx.Response | None = None
    dns_records: dict[str, list[str]] = field(default_factory=dict)
    dns_elapsed: float = 0.0
    tls: TlsInfo | None = None
