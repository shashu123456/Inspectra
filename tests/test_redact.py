"""Tests for the redaction module (M3 Phase A6)."""

from __future__ import annotations

from inspectra.redact import redact_headers, redact_text


def test_redact_header_line_authorization() -> None:
    """Authorization header line is fully redacted."""
    text = "Authorization: Bearer secret-token-12345"
    result = redact_text(text)
    assert "secret-token-12345" not in result
    assert "Authorization: [REDACTED]" in result


def test_redact_header_line_cookie() -> None:
    """Cookie header line is fully redacted."""
    text = "Cookie: session=abc123; user=jdoe"
    result = redact_text(text)
    assert "abc123" not in result
    assert "Cookie: [REDACTED]" in result


def test_redact_header_line_set_cookie() -> None:
    """Set-Cookie header line is fully redacted."""
    text = "Set-Cookie: sessionid=xyz789; Path=/"
    result = redact_text(text)
    assert "xyz789" not in result
    assert "Set-Cookie: [REDACTED]" in result


def test_redact_header_line_x_api_key() -> None:
    """X-API-Key header line is fully redacted."""
    text = "X-API-Key: sk-1234567890abcdef"
    result = redact_text(text)
    assert "sk-1234567890abcdef" not in result
    assert "X-API-Key: [REDACTED]" in result


def test_redact_header_line_proxy_authorization() -> None:
    """Proxy-Authorization header line is fully redacted."""
    text = "Proxy-Authorization: Basic dXNlcjpwYXNz"
    result = redact_text(text)
    assert "dXNlcjpwYXNz" not in result
    assert "Proxy-Authorization: [REDACTED]" in result


def test_redact_key_value_secret() -> None:
    """key=value secrets keep the key, redact the value."""
    text = "api_key=sk-live-1234567890"
    result = redact_text(text)
    assert "sk-live-1234567890" not in result
    assert "api_key= [REDACTED]" in result


def test_redact_password_colon() -> None:
    """password: value secrets keep the key, redact the value."""
    text = "database_password: hunter2"
    result = redact_text(text)
    assert "hunter2" not in result
    assert "database_password= [REDACTED]" in result


def test_redact_jwt() -> None:
    """JWT tokens are replaced with [REDACTED:jwt]."""
    token = (
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
        "eyJzdWIiOiIxMjM0NTY3ODkwIn0."
        "dozjgNtPovIxRWYB3u7Y9IS3-g7V1B5Y3-KauE8YxSk"
    )
    text = f"Token: {token}"
    result = redact_text(text)
    assert token not in result
    assert "[REDACTED:jwt]" in result


def test_redact_url_userinfo() -> None:
    """URL user:pass@host credentials are redacted."""
    text = "https://admin:password123@example.com/"
    result = redact_text(text)
    assert "admin:password123" not in result
    assert "https://[REDACTED]@example.com/" in result


def test_redact_url_query_token() -> None:
    """URL query tokens keep the key, redact the value."""
    text = "https://example.com/api?api_key=secret123&token=abc456"
    result = redact_text(text)
    assert "secret123" not in result
    assert "abc456" not in result
    assert "api_key= [REDACTED]" in result
    assert "token= [REDACTED]" in result


def test_redact_headers_dict() -> None:
    """redact_headers redacts sensitive headers in a dict."""
    headers = {
        "Authorization": "Bearer token123",
        "Content-Type": "application/json",
        "Cookie": "session=abc",
    }
    result = redact_headers(headers)
    assert result["Authorization"] == "[REDACTED:Authorization]"
    assert result["Content-Type"] == "application/json"
    assert result["Cookie"] == "[REDACTED:Cookie]"


def test_redact_non_sensitive_header_unchanged() -> None:
    """Non-sensitive headers are not redacted."""
    text = "User-Agent: curl/7.68.0"
    result = redact_text(text)
    assert result == "User-Agent: curl/7.68.0"
