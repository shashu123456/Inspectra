"""Shared fixtures: a local HTTP server that stands in for a scan target.

All network-facing tests run against this fixture server on 127.0.0.1, so the
test suite never touches the internet or third-party targets.
"""

from __future__ import annotations

import pytest
from pytest_httpserver import HTTPServer

from inspectra.models import ScanOptions, Target

INDEX_HTML = b"""<!doctype html>
<html>
<head><meta name="generator" content="InspectraCMS 1.2.3"></head>
<body><h1>Welcome to the fixture site</h1></body>
</html>
"""

ROBOTS_TXT = b"""User-agent: *
Disallow: /admin
Disallow: /secret
Sitemap: https://example.com/sitemap.xml
"""


@pytest.fixture
def fixture_server(httpserver: HTTPServer) -> HTTPServer:
    """A local HTTP server with a small, deterministic site."""
    httpserver.expect_request("/").respond_with_data(
        INDEX_HTML,
        status=200,
        headers={
            "Content-Type": "text/html; charset=utf-8",
            "Server": "InspectraTest/1.2.3",
            "X-Powered-By": "InspectraLang/9.9",
        },
    )
    httpserver.expect_request("/robots.txt").respond_with_data(
        ROBOTS_TXT,
        status=200,
        headers={"Content-Type": "text/plain; charset=utf-8"},
    )
    httpserver.expect_request("/admin").respond_with_data(b"admin area", status=200)
    httpserver.expect_request("/secret").respond_with_data(b"secret", status=403)
    httpserver.expect_request("/health").respond_with_data(b"ok", status=200)
    httpserver.expect_request("/.git/config").respond_with_data(b"[core]", status=200)
    httpserver.expect_request("/missing").respond_with_data(b"", status=404)
    return httpserver


@pytest.fixture
def target(fixture_server: HTTPServer) -> Target:
    """A Target pointing at the fixture server (HTTP only)."""
    return Target(
        input=f"http://127.0.0.1:{fixture_server.port}",
        hostname="127.0.0.1",
        port=fixture_server.port,
        scheme="http",
    )


@pytest.fixture
def fake_home(tmp_path, monkeypatch):
    """Redirect the consent config to a temporary home directory."""
    from inspectra import cli

    home = tmp_path / "home"
    home.mkdir()
    config_dir = home / ".config" / "inspectra"
    monkeypatch.setattr(cli, "CONFIG_DIR", config_dir)
    monkeypatch.setattr(cli, "CONFIG_FILE", config_dir / "config.json")
    return home


@pytest.fixture
def scan_options() -> ScanOptions:
    """ScanOptions with private targets allowed (for localhost fixture testing)."""
    return ScanOptions(allow_private=True, authorized=True)
