"""Generate the committed sample report by scanning a local fixture server.

Run from the repo root with the project venv active:

    python scripts/generate_sample_report.py
"""

from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "src"))

from pytest_httpserver import HTTPServer  # noqa: E402

from inspectra.cli import main  # noqa: E402

INDEX_HTML = (
    b"<!doctype html><html><head><title>Welcome</title></head>"
    b"<body><h1>Welcome to the demo site</h1>"
    b"<p>This fixture site is used to generate Inspectra's sample report.</p>"
    b"</body></html>"
)
ROBOTS_TXT = b"User-agent: *\nDisallow: /admin\nDisallow: /private\nSitemap: https://example.com/sitemap.xml\n"


def main_script() -> int:
    server = HTTPServer()
    server.start()
    server.expect_request("/").respond_with_data(
        INDEX_HTML,
        status=200,
        headers={
            "Content-Type": "text/html; charset=utf-8",
            "Server": "nginx/1.24.0",
            "X-Powered-By": "PHP/7.4.3",
        },
    )
    server.expect_request("/robots.txt").respond_with_data(
        ROBOTS_TXT, status=200, headers={"Content-Type": "text/plain"}
    )
    server.expect_request("/admin").respond_with_data(b"admin", status=200)
    server.expect_request("/private").respond_with_data(b"", status=403)
    server.expect_request("/login").respond_with_data(b"login", status=200)

    target = f"http://127.0.0.1:{server.port}"
    output_dir = REPO_ROOT / "examples" / "sample-report"
    base_args = ["scan", target, "--yes", "--skip-ports", "--output-dir", str(output_dir)]
    code = main([*base_args, "--format", "markdown"])
    main([*base_args, "--format", "html"])
    server.stop()
    print(f"sample report written to {output_dir} (exit code {code})")
    return code


if __name__ == "__main__":
    raise SystemExit(main_script())
