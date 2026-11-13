"""Tests for the HTTP analysis check."""

from __future__ import annotations

import httpx

from inspectra.checks import http
from inspectra.checks.context import ScanContext
from inspectra.models import Target
from inspectra.network import build_client


def test_http_check_populates_context(fixture_server, target, scan_options) -> None:
    with build_client() as client:
        context = ScanContext(client=client, options=scan_options)
        findings = http.run(target, context)

    assert context.http_response is not None
    assert context.http_response.status_code == 200
    assert context.robots_response is not None
    assert context.robots_response.status_code == 200
    assert target.scheme == "http"

    rule_ids = {finding.rule_id for finding in findings}
    assert "HTP-003" in rule_ids  # Server header disclosure


def test_http_check_reports_error_status(fixture_server, target, scan_options) -> None:
    fixture_server.expect_oneshot_request("/").respond_with_data(b"", status=503)
    with build_client() as client:
        context = ScanContext(client=client, options=scan_options)
        findings = http.run(target, context)
    assert any(finding.rule_id == "HTP-004" for finding in findings)


def test_http_check_unreachable_raises(target, scan_options) -> None:
    unreachable = Target(input="x", hostname="127.0.0.1", port=1, scheme="http")
    with build_client() as client:
        context = ScanContext(client=client, options=scan_options)
        try:
            http.run(unreachable, context)
        except Exception as exc:
            assert exc.__class__.__name__ == "CheckError"
        else:
            raise AssertionError("expected CheckError for unreachable target")


# --- P1: Query string preserved in pinned URL ---
def test_pinned_url_preserves_query() -> None:
    """Pinned URL keeps the query string, not just the path."""
    pinned = http._pinned_url("93.184.216.34", "https", 8443, "/a/b?token=1&x=2")
    assert pinned == "https://93.184.216.34:8443/a/b?token=1&x=2"


def test_pinned_url_no_query_unchanged() -> None:
    """Pinned URL without query works as before."""
    pinned = http._pinned_url("93.184.216.34", "https", 443, "/a/b")
    assert pinned == "https://93.184.216.34:443/a/b"


# --- P2: Host header includes non-default port ---
def test_pinned_get_host_header_includes_port() -> None:
    """Host header includes the port when it's non-default."""
    captured = {}

    class FakeResponse:
        def __init__(self) -> None:
            self.is_redirect = False

    class FakeClient:
        def get(self, url, *, headers, extensions=None):
            captured["url"] = url
            captured["headers"] = headers
            captured["extensions"] = extensions
            return FakeResponse()

    client = FakeClient()
    url = "https://example.com:8443/a/b?token=abc123"
    http._pinned_get(client, url, "example.com", "93.184.216.34")

    assert captured["url"] == "https://93.184.216.34:8443/a/b?token=abc123"
    assert captured["headers"]["Host"] == "example.com:8443"
    assert captured["extensions"]["sni_hostname"] == "example.com"


def test_pinned_get_host_header_default_port() -> None:
    """Host header drops the port when it's the default (80/443)."""
    captured = {}

    class FakeResponse:
        def __init__(self) -> None:
            self.is_redirect = False

    class FakeClient:
        def get(self, url, *, headers, extensions=None):
            captured["url"] = url
            captured["headers"] = headers
            return FakeResponse()

    client = FakeClient()
    url = "https://example.com/a/b"
    http._pinned_get(client, url, "example.com", "93.184.216.34")

    assert captured["url"] == "https://93.184.216.34/a/b"
    assert captured["headers"]["Host"] == "example.com"


def test_pinned_get_query_preserved_in_request() -> None:
    """The full URL including query string is used for the pinned request."""
    captured = {}

    class FakeResponse:
        def __init__(self) -> None:
            self.is_redirect = False

    class FakeClient:
        def get(self, url, *, headers, extensions=None):
            captured["url"] = url
            return FakeResponse()

    client = FakeClient()
    url = "http://example.com/search?q=hello+world&lang=en"
    http._pinned_get(client, url, "example.com", "93.184.216.34")

    assert captured["url"] == "http://93.184.216.34/search?q=hello+world&lang=en"


# --- Non-blocking leftover: redirect hop preserves its own query string ---
def test_redirect_hop_preserves_query() -> None:
    """A 302 Location with a query string survives urljoin -> _pinned_get on
    the next hop (page=2 and token=SECRET kept)."""
    captured = {}

    class FakeResponse:
        def __init__(self, url: str, status: int) -> None:
            self.url = httpx.URL(url)
            self.status_code = status
            self.headers = {}
            self.is_redirect = status in {301, 302, 307, 308}

    class FakeClient:
        def get(self, url, *, headers, extensions=None):
            captured["url"] = url
            captured["headers"] = headers
            return FakeResponse("http://example.com/page?page=2&token=SECRET", 200)

    client = FakeClient()
    first_url = "http://example.com/page?a=1"
    # Simulate what _follow_redirects does: validate_redirect -> _pinned_get
    resp1 = FakeResponse(first_url, 302)
    resp1.headers["location"] = "/page?page=2&token=SECRET"
    assert resp1.is_redirect

    next_url = str(httpx.URL(first_url).join(resp1.headers["location"]))
    # _pinned_get pins the IP and preserves the query string
    http._pinned_get(client, next_url, "example.com", "93.184.216.34")

    assert captured["url"] == "http://93.184.216.34/page?page=2&token=SECRET"
    assert captured["headers"]["Host"] == "example.com"
