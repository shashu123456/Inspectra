"""Inspectra demo server.

Serves a deliberately insecure (but completely harmless) fixture website on
http://127.0.0.1:9000 and exposes JSON endpoints that run REAL Inspectra
scans against it:

  GET  /                demo landing page (also the scan target's index page)
  GET  /robots.txt      robots fixture (disallows /admin, /backup.sql)
  GET  /admin           fake admin login page
  GET  /backup.sql      fake (empty, harmless) database dump
  GET  /health          health endpoint
  GET  /api/scan        run a real Inspectra scan -> JSON results
  GET  /api/report/html serve the last scan's HTML report
  GET  /api/report/md   serve the last scan's Markdown report
  GET  /api/report/json serve the last scan's raw JSON report
  GET  /api/demo-page   serve the demo landing page itself

Only --directories mode touches more than the index/robots (rate-limited,
GET-only). Nothing here is exploitable: every "secret" is fake.
"""

from __future__ import annotations

import json
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "src"))

from inspectra.cli import main as cli_main  # noqa: E402

HOST, PORT = "127.0.0.1", 9000
REPORT_DIR = REPO_ROOT / "demo-output"
SCAN_LOCK = threading.Lock()

INDEX_HTML = """<!doctype html>
<html><head><title>Inspectra Demo Target</title>
<style>
  body {{ font-family: system-ui, sans-serif; background: #f8fafc; color: #0f172a;
         max-width: 640px; margin: 3rem auto; padding: 0 1rem; }}
  .card {{ background: #fff; border: 1px solid #e2e8f0; border-radius: 12px;
          padding: 1.5rem; margin: 1rem 0; }}
  code {{ background: #f1f5f9; padding: .1rem .35rem; border-radius: 4px; }}
</style></head>
<body>
<h1>Inspectra Demo Target</h1>
<div class="card">
  <p>This little site is the <strong>scan target</strong> for the Inspectra demo.
  It is deliberately <em>misconfigured</em> so a scan finds real issues:</p>
  <ul>
    <li>no security headers</li>
    <li>server/software disclosure (<code>Server</code>, <code>X-Powered-By</code>)</li>
    <li>no TLS (HTTP only)</li>
    <li><code>robots.txt</code> hiding an open <code>/admin</code> page
        and a fake <code>/backup.sql</code></li>
  </ul>
  <p>Everything here is fake and harmless. Nothing is exploitable.</p>
</div>
</body></html>
"""

ROBOTS_TXT = "User-agent: *\nDisallow: /admin\nDisallow: /backup.sql\nSitemap: http://127.0.0.1:9000/sitemap.xml\n"

ADMIN_HTML = """<!doctype html><html><head><title>Admin Login</title></head>
<body style="font-family: system-ui; max-width: 480px; margin: 3rem auto">
<h1>Admin Login (demo)</h1>
<form><input placeholder="username"><input type="password" placeholder="password">
<button type="button">Log in</button></form>
<p style="color:#b91c1c">Demo page &mdash; no authentication, no real backend.</p>
</body></html>
"""

LANDING_PATH = REPO_ROOT / "demo" / "index.html"


class DemoHandler(BaseHTTPRequestHandler):
    """Serves the fixture site, the demo UI, and live-scan endpoints."""

    def do_GET(self) -> None:  # noqa: N802 (http.server API)
        path = self.path.split("?")[0]
        routes = {
            "/": (INDEX_HTML, "text/html; charset=utf-8"),
            "/index.html": (INDEX_HTML, "text/html; charset=utf-8"),
            "/robots.txt": (ROBOTS_TXT, "text/plain; charset=utf-8"),
            "/admin": (ADMIN_HTML, "text/html; charset=utf-8"),
            "/backup.sql": ("-- demo dump\nCREATE TABLE nothing (id INT);\n", "application/sql"),
            "/health": ('{"status":"ok"}', "application/json"),
            "/api/demo-page": (self._demo_page(), "text/html; charset=utf-8"),
        }
        if path in routes:
            body, content_type = routes[path]
            self._send(200, body, content_type)
        elif path == "/api/scan":
            self._send(200, self._run_scan(), "application/json")
        elif path == "/api/report/html":
            self._serve_report("report.html", "text/html; charset=utf-8")
        elif path == "/api/report/md":
            self._serve_report("report.md", "text/plain; charset=utf-8")
        elif path == "/api/report/json":
            self._serve_report("report.json", "application/json")
        else:
            self._send(404, "not found", "text/plain; charset=utf-8")

    def _send(self, status: int, body: str, content_type: str) -> None:
        payload = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def _demo_page(self) -> str:
        try:
            return LANDING_PATH.read_text(encoding="utf-8")
        except OSError:
            return "<h1>demo page missing</h1>"

    def _run_scan(self) -> str:
        """Run a real Inspectra scan (ports skipped: fixture is single-port).

        Runs twice so all three report formats are available: Markdown
        (default) and HTML. report.json is always written.
        """
        base = [
            "scan",
            f"http://{HOST}:{PORT}",
            "--yes",
            "--skip-ports",
            "--output-dir",
            str(REPORT_DIR),
        ]
        with SCAN_LOCK:
            code = cli_main([*base, "--format", "markdown"])
            cli_main([*base, "--format", "html"])
            try:
                data = json.loads((REPORT_DIR / "report.json").read_text(encoding="utf-8"))
            except OSError:
                data = {"error": "report.json missing", "exit_code": code}
            data["exit_code"] = code
            return json.dumps(data)

    def _serve_report(self, name: str, content_type: str) -> None:
        try:
            self._send(200, (REPORT_DIR / name).read_text(encoding="utf-8"), content_type)
        except OSError:
            self._send(404, "no scan yet — run the scan first", "text/plain")


def main() -> None:
    REPORT_DIR.mkdir(exist_ok=True)
    server = ThreadingHTTPServer((HOST, PORT), DemoHandler)
    print(f"Inspectra demo server on http://{HOST}:{PORT}")
    print(f"  demo UI:   http://{HOST}:{PORT}/api/demo-page")
    print(f"  live scan: http://{HOST}:{PORT}/api/scan")
    print("Press Ctrl+C to stop.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nstopped.")


if __name__ == "__main__":
    main()
