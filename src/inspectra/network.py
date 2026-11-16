"""HTTP and TLS primitives shared by the network-facing checks."""

from __future__ import annotations

import socket
import ssl
import threading
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlparse

import httpx
from cryptography import x509
from cryptography.x509.oid import ExtensionOID, NameOID

from inspectra import __version__

DEFAULT_TIMEOUT = httpx.Timeout(15.0, connect=10.0)
MAX_REDIRECTS = 5
USER_AGENT = f"Inspectra/{__version__} (passive security assessment; authorized use only)"


def build_client() -> httpx.Client:
    """Create a shared HTTP client for the scan.

    ``trust_env=False`` keeps scans from being silently routed through any
    proxy configured in the environment.
    """
    return httpx.Client(
        timeout=DEFAULT_TIMEOUT,
        follow_redirects=False,
        trust_env=False,
        headers={"User-Agent": USER_AGENT},
    )


class RateLimitedClient:
    """httpx.Client-compatible wrapper enforcing per-host concurrency and delay.

    Each host gets its own semaphore limiting concurrent requests to
    ``max_per_host``. A per-host delay is applied before acquiring the host
    semaphore so sleeping does not hold another host's slot.
    """

    def __init__(self, client: httpx.Client, max_per_host: int = 2, delay: float = 0.0) -> None:
        self._client = client
        self._max_per_host = max_per_host
        self._delay = max(0.0, float(delay))
        self._lock = threading.Lock()
        self._semaphores: dict[str, threading.Semaphore] = {}
        self._last_request: dict[str, float] = {}

    def _get_semaphore(self, host: str) -> threading.Semaphore:
        with self._lock:
            sem = self._semaphores.get(host)
            if sem is None:
                sem = threading.Semaphore(self._max_per_host)
                self._semaphores[host] = sem
            return sem

    def _wait_for_delay(self, host: str) -> None:
        if self._delay <= 0:
            return
        with self._lock:
            now = time.monotonic()
            target = max(now, self._last_request.get(host, 0.0) + self._delay)
            self._last_request[host] = target
        sleep_for = target - time.monotonic()
        if sleep_for > 0:
            time.sleep(sleep_for)

    def get(self, url: str, **kwargs: Any) -> httpx.Response:
        parsed = urlparse(url)
        host = parsed.hostname or ""
        self._wait_for_delay(host)
        sem = self._get_semaphore(host)
        with sem:
            return self._client.get(url, **kwargs)

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> RateLimitedClient:
        self._client.__enter__()
        return self

    def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
        self._client.__exit__(exc_type, exc, tb)  # type: ignore[arg-type]

    def __getattr__(self, name: str) -> Any:
        return getattr(self._client, name)


@dataclass(slots=True)
class TlsInfo:
    """Parsed TLS handshake and certificate details."""

    version: str
    cipher: str
    subject_cn: str
    issuer: str
    not_valid_before: datetime
    not_valid_after: datetime
    san_dns: list[str]
    is_self_signed: bool
    hostname_matches: bool

    @property
    def days_remaining(self) -> int:
        """Whole days until the certificate expires (negative when expired)."""
        return (self.not_valid_after - datetime.now(UTC)).days

    @property
    def is_expired(self) -> bool:
        """True when the certificate is already past its expiry date."""
        return self.days_remaining < 0


def inspect_tls(hostname: str, port: int = 443, timeout: float = 10.0) -> TlsInfo:
    """Perform a real TLS handshake and return parsed certificate details.

    Raises ``ssl.SSLError`` / ``OSError`` when the handshake fails.
    """
    context = ssl.create_default_context()
    with (
        socket.create_connection((hostname, port), timeout=timeout) as sock,
        context.wrap_socket(sock, server_hostname=hostname) as tls_sock,
    ):
        version = tls_sock.version() or "unknown"
        cipher = tls_sock.cipher()
        cipher_name = cipher[0] if cipher else "unknown"
        der_cert = tls_sock.getpeercert(binary_form=True)
    assert der_cert is not None, "verified TLS session must present a certificate"
    cert = x509.load_der_x509_certificate(der_cert)
    try:
        san = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value
        san_dns = list(san.get_values_for_type(x509.DNSName))  # type: ignore[attr-defined]
    except x509.ExtensionNotFound:
        san_dns = []
    subject_cn = _common_name(cert.subject)
    issuer_cn = _common_name(cert.issuer)
    return TlsInfo(
        version=version,
        cipher=cipher_name,
        subject_cn=subject_cn,
        issuer=issuer_cn,
        not_valid_before=cert.not_valid_before_utc,
        not_valid_after=cert.not_valid_after_utc,
        san_dns=san_dns,
        is_self_signed=cert.issuer == cert.subject,
        hostname_matches=_hostname_matches(hostname, san_dns, subject_cn),
    )


def _common_name(name: x509.Name) -> str:
    try:
        value = name.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    except IndexError:
        return ""
    return str(value)


def _hostname_matches(hostname: str, san_dns: list[str], cn: str) -> bool:
    return any(_pattern_matches(hostname, candidate) for candidate in [*san_dns, cn])


def _pattern_matches(hostname: str, pattern: str) -> bool:
    pattern = pattern.lower()
    if pattern.startswith("*."):
        suffix = pattern[1:]
        return hostname.lower().endswith(suffix) and hostname.count(".") >= pattern.count(".")
    return hostname.lower() == pattern
