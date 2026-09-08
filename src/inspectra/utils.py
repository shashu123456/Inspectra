"""Small shared helpers: target normalization, data loading, evidence truncation."""

from __future__ import annotations

import ipaddress
import json
import re
from datetime import UTC, datetime, timedelta, timezone
from importlib.resources import files
from typing import Any

from inspectra.models import Target

#: Indian Standard Time (UTC+05:30, no DST) — the display timezone for reports.
IST_TIMEZONE = timezone(timedelta(hours=5, minutes=30), name="IST")
IST_LABEL = "Asia/Kolkata (UTC+05:30)"

_HOSTNAME_RE = re.compile(
    r"^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)*$"
)


class TargetValidationError(ValueError):
    """Raised when a target string cannot be interpreted safely."""


def normalize_target(raw: str) -> Target:
    """Turn a user-supplied domain, IP or URL into a validated :class:`Target`.

    Raises :class:`TargetValidationError` for anything ambiguous or unsafe.
    """
    value = raw.strip().rstrip("/")
    if not value:
        raise TargetValidationError("Target cannot be empty.")
    if "://" in value:
        return _from_url(value)
    if " " in value or "@" in value:
        raise TargetValidationError(f"Invalid target {raw!r}: unexpected characters.")
    host, _, port_str = value.rpartition(":")
    if port_str.isdigit() and host:
        return _from_hostname(host, int(port_str))
    return _from_hostname(value, None)


def _from_url(value: str) -> Target:
    from urllib.parse import urlparse

    parsed = urlparse(value)
    scheme = parsed.scheme.lower()
    if scheme not in {"http", "https"}:
        raise TargetValidationError(f"Unsupported scheme {scheme!r}; use http or https.")
    if not parsed.hostname:
        raise TargetValidationError(f"Could not extract a hostname from {value!r}.")
    if parsed.username or parsed.password:
        raise TargetValidationError("URLs with embedded credentials are not supported.")
    return _from_hostname(parsed.hostname, parsed.port, scheme=scheme, input_value=value)


def _from_hostname(
    host: str, port: int | None, scheme: str = "https", input_value: str | None = None
) -> Target:
    host = host.lower().rstrip(".")
    if not _HOSTNAME_RE.match(host):
        raise TargetValidationError(f"Invalid hostname: {host!r}")
    if port is not None and not (1 <= port <= 65535):
        raise TargetValidationError(f"Invalid port: {port}")
    target = Target(input=input_value or host, hostname=host, port=port, scheme=scheme)
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        target.is_private = not address.is_global
    return target


def is_private_address(ip: str) -> bool:
    """True when the given IP string is a private or reserved address."""
    try:
        return not ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


def load_json(name: str) -> Any:
    """Load a JSON knowledge-base file shipped inside the package."""
    path = files("inspectra").joinpath("data", name)
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def load_text_lines(name: str) -> list[str]:
    """Load a newline-separated data file, skipping blank lines and comments."""
    path = files("inspectra").joinpath("data", name)
    with path.open("r", encoding="utf-8") as handle:
        return [
            line.strip() for line in handle if line.strip() and not line.lstrip().startswith("#")
        ]


def format_ist(dt: datetime) -> str:
    """Format a datetime for display in Indian Standard Time.

    Naive datetimes are assumed to be UTC. Storage stays UTC (ISO-8601);
    only human-facing output is converted.
    """
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt.astimezone(IST_TIMEZONE).strftime("%Y-%m-%d %H:%M:%S IST")


def truncate(text: str, limit: int = 500) -> str:
    """Truncate evidence strings so reports stay readable."""
    if len(text) <= limit:
        return text
    return text[: limit - 1] + "…"
