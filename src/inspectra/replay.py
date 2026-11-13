"""Deterministic replay for Inspectra scans.

Record every HTTP request/response to a fixtures directory, then replay scans
entirely from disk with zero network I/O. Two runs against the same fixtures
produce byte-identical reports (modulo timestamps), so CI can diff scans and
detect regressions without touching the network.

The Recorder and Replayer both implement the tiny ``get(url, *, headers,
extensions)`` interface that the HTTP check already uses, so checks do not
learn about replay.
"""

from __future__ import annotations

import base64
import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

import httpx

REPLAY_VERSION = "1"


class ReplayMissError(Exception):
    """Raised when a replayed request has no matching fixture."""

    def __init__(self, url: str) -> None:
        super().__init__(f"No replay fixture for {url}")
        self.url = url


def _request_key(method: str, url: str) -> str:
    """Stable fixture key: sha256 of method + space + url."""
    return hashlib.sha256(f"{method} {url}".encode()).hexdigest()


class FixtureStore:
    """Read/write fixture files for a replay directory.

    Each request/response pair is stored as ``<key>.json`` with an
    ``index.json`` mapping keys to metadata. Keys are content-addressed so the
    same request always maps to the same file.
    """

    def __init__(self, directory: Path | str) -> None:
        self.directory = Path(directory)
        self.index: dict[str, dict[str, Any]] = {}
        self._loaded = False

    def _ensure_loaded(self) -> None:
        if self._loaded:
            return
        index_path = self.directory / "index.json"
        if index_path.exists():
            self.index = json.loads(index_path.read_text(encoding="utf-8"))
        else:
            self.index = {}
        self._loaded = True

    def _persist_index(self) -> None:
        self.directory.mkdir(parents=True, exist_ok=True)
        index_path = self.directory / "index.json"
        index_path.write_text(
            json.dumps(self.index, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

    def record(
        self,
        method: str,
        url: str,
        response: httpx.Response,
        elapsed_ms: float,
    ) -> None:
        """Persist one request/response pair to a fixture file."""
        self._ensure_loaded()
        key = _request_key(method, url)

        # Redact headers through the existing redactor so secrets never hit disk.
        from inspectra.redact import redact_headers

        headers = {k.lower(): v for k, v in response.headers.items()}
        headers = redact_headers(headers)

        body_b64 = base64.b64encode(response.content).decode("ascii")

        record = {
            "key": key,
            "method": method,
            "url": str(response.url),
            "status": response.status_code,
            "headers": headers,
            "body_b64": body_b64,
            "elapsed_ms": round(elapsed_ms, 3),
            "recorded_at": datetime.now(UTC).isoformat(),
        }

        fixture_path = self.directory / f"{key}.json"
        fixture_path.write_text(
            json.dumps(record, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

        self.index[key] = {
            "method": method,
            "url": str(response.url),
            "file": f"{key}.json",
        }
        self._persist_index()

    def load(self, method: str, url: str) -> dict[str, Any]:
        """Load one recorded request/response pair by key.

        Raises ReplayMissError when no fixture matches.
        """
        self._ensure_loaded()
        key = _request_key(method, url)
        if key not in self.index:
            raise ReplayMissError(url)
        entry = self.index[key]
        fixture_path = self.directory / entry["file"]
        return cast(dict[str, Any], json.loads(fixture_path.read_text(encoding="utf-8")))


class Recorder:
    """Wrap an httpx.Client and record every request/response to a FixtureStore.

    Implements the ``get(url, *, headers, extensions)`` interface used by the
    HTTP check, so it can be dropped in for ``context.client``.
    """

    def __init__(self, client: httpx.Client, store: FixtureStore) -> None:
        self._client = client
        self._store = store

    def get(
        self,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        extensions: dict[str, Any] | None = None,
    ) -> httpx.Response:
        start = datetime.now(UTC)
        response = self._client.get(url, headers=headers, extensions=extensions)
        elapsed_ms = (datetime.now(UTC) - start).total_seconds() * 1000
        self._store.record("GET", str(response.url), response, elapsed_ms)
        return response


class Replayer:
    """Serve responses from disk with zero network I/O.

    Implements the same ``get(url, *, headers, extensions)`` interface as
    Recorder, but never constructs an httpx.Client or opens a socket. A cache
    miss raises ReplayMissError -- it never falls back to the network.

    Implements ``close()`` for compatibility with ``build_client()`` context
    manager usage.
    """

    def __init__(self, store: FixtureStore) -> None:
        self._store = store

    def get(
        self,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        extensions: dict[str, Any] | None = None,
    ) -> httpx.Response:
        record = self._store.load("GET", url)
        return _response_from_record(record)

    def close(self) -> None:
        """No-op for context-manager compatibility."""


def _response_from_record(record: dict[str, Any]) -> httpx.Response:
    """Reconstruct an httpx.Response from a recorded fixture."""
    body = base64.b64decode(record["body_b64"])
    headers = httpx.Headers(record["headers"])
    request = httpx.Request(record["method"], record["url"])
    return httpx.Response(
        status_code=record["status"],
        headers=headers,
        content=body,
        request=request,
    )
