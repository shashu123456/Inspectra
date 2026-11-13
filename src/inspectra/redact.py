"""Secret redaction for Inspectra scan evidence.

Redacts sensitive values from finding evidence before any reporter
serializes them. Applied as a single choke point in the orchestrator.
"""

from __future__ import annotations

import re

#: Header names whose values should be fully redacted.
SENSITIVE_HEADERS = {
    "authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "proxy-authorization",
}

#: Pattern for key=value or key: value secrets in evidence text.
#: Negative lookahead avoids double-redacting [REDACTED] / [REDACTED:jwt] values.
SECRET_PATTERN = re.compile(
    r"(?i)(api[_-]?key|secret|token|password)\s*[:=]\s*(?!\[REDACTED[:\]])\S+"
)

#: JWT pattern: three base64url segments separated by dots.
JWT_PATTERN = re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")

#: Header-line pattern: Header-Name: value  (case-insensitive).
HEADER_LINE_PATTERN = re.compile(
    r"(?im)^(authorization|cookie|set-cookie|x-api-key|proxy-authorization)\s*:\s*.*$"
)

#: URL userinfo credentials: scheme://user:pass@host
URL_USERINFO_PATTERN = re.compile(r"(?i)(https?://)[^:/?#]+:[^/?#]+(@)")

#: URL query tokens: ?key=value or &key=value
URL_QUERY_PATTERN = re.compile(r"(?i)([?&])(api[_-]?key|token|secret|password)=([^&\s]+)")


def redact_header_value(header_name: str, value: str) -> str:
    """Redact a sensitive header value.

    Returns ``[REDACTED:<header>]`` for sensitive headers, or the
    original value for non-sensitive ones.
    """
    if header_name.lower() in SENSITIVE_HEADERS:
        return f"[REDACTED:{header_name}]"
    return value


def redact_text(text: str) -> str:
    """Redact secrets and JWTs from arbitrary text.

    - Header lines: sensitive header names redacted entirely.
    - URL userinfo: credentials replaced.
    - URL query tokens: key kept, value redacted.
    - Key=value secrets: keeps the key, redacts the value.
    - JWTs: replaced with ``[REDACTED:jwt]``.
    """
    # Redact header lines first.
    text = HEADER_LINE_PATTERN.sub(lambda m: f"{m.group(1)}: [REDACTED]", text)
    # Redact URL userinfo credentials.
    text = URL_USERINFO_PATTERN.sub(lambda m: m.group(1) + "[REDACTED]" + m.group(2), text)
    # Redact URL query tokens.
    text = URL_QUERY_PATTERN.sub(lambda m: m.group(1) + m.group(2) + "= [REDACTED]", text)
    # Redact JWTs (they can contain key=value-like segments).
    text = JWT_PATTERN.sub("[REDACTED:jwt]", text)
    # Redact key=value / key: value secrets.
    text = SECRET_PATTERN.sub(lambda m: m.group(1) + "= [REDACTED]", text)
    return text


def redact_evidence(evidence: list[str]) -> list[str]:
    """Redact all strings in an evidence list."""
    return [redact_text(line) for line in evidence]


def redact_headers(headers: dict[str, str]) -> dict[str, str]:
    """Redact sensitive headers in a dict."""
    return {name: redact_header_value(name, value) for name, value in headers.items()}


def redaction_metadata(disabled: bool = False) -> dict[str, str] | None:
    """Return report metadata for redaction status.

    Returns ``{"redaction": "disabled"}`` when redaction is disabled,
    otherwise ``None``.
    """
    if disabled:
        return {"redaction": "disabled"}
    return None
