"""Generate assets/terminal-demo.svg from REAL inspectra scan output.

Runs `inspectra scan` against the committed replay fixtures (offline,
deterministic) at a fixed terminal width, captures the ANSI-styled output,
and wraps it in an SVG with a window chrome and a monospace font.

Never hand-type fake output: every line shown is produced by a real scan.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
OUT = REPO / "assets" / "terminal-demo.svg"
FIXTURES = REPO / "tests" / "fixtures" / "replay"
TARGET = "http://127.0.0.1:9999"

# Fixed terminal width so output is deterministic.
COLUMNS = 100


def run_scan() -> list[str]:
    """Run inspectra against committed replay fixtures; return stripped lines."""
    cmd = [
        sys.executable,
        "-m",
        "inspectra",
        "scan",
        TARGET,
        "--replay",
        str(FIXTURES),
        "--yes",
        "--skip-ports",
        "--allow-private",
        "--authorized",
        "--format",
        "json",
    ]
    env = {**os.environ, "COLUMNS": str(COLUMNS), "PYTHONIOENCODING": "utf-8"}
    proc = subprocess.run(
        cmd, capture_output=True, text=True, env=env, cwd=REPO, encoding="utf-8", errors="replace"
    )
    if proc.returncode != 0:
        raise SystemExit(f"inspectra scan failed ({proc.returncode}): {proc.stderr}")
    # Keep only real content lines; drop the Rich window/chrome noise that
    # would not survive in SVG.
    lines = [ln for ln in proc.stdout.splitlines() if ln.strip()]
    return lines


def esc(s: str) -> str:
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def build(lines: list[str]) -> str:
    line_height = 22
    pad = 24
    top_chrome = 56
    inner = 18
    width = pad * 2 + COLUMNS * 8.6  # approx mono advance at 14px
    height = top_chrome + pad + len(lines) * line_height + pad + 30

    svg = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{int(width)}" '
        f'height="{int(height)}" viewBox="0 0 {int(width)} {int(height)}">',
        '<rect width="100%" height="100%" fill="#0a0a0a"/>',
        # window chrome
        f'<rect x="{pad}" y="{pad}" width="{width - pad * 2}" height="{top_chrome}" '
        f'rx="10" fill="#141414"/>',
        '<circle cx="38" cy="44" r="4" fill="#ff5f56"/>',
        '<circle cx="54" cy="44" r="4" fill="#feb258"/>',
        '<circle cx="70" cy="44" r="4" fill="#27c93f"/>',
        '<text x="100" y="46" font-family="ui-sans-serif, sans-serif" '
        'font-size="13" fill="#9ca3af">inspectra scan — terminal demo</text>',
        f'<text x="{width - pad - 60}" y="46" font-family="ui-sans-serif, sans-serif" '
        f'font-size="12" fill="#6b7280">127.0.0.1 &middot; replay fixtures</text>',
        f'<rect x="{pad}" y="{top_chrome + 12}" width="{width - pad * 2}" '
        f'height="{height - top_chrome - 12 - pad - 30}" rx="8" fill="#0d0d0d"/>',
    ]
    y = top_chrome + 32
    title_font = (
        'font-family="ui-monospace, SFMono-Regular, Menlo, Consolas, monospace" '
        'font-size="14" fill="#eaeaea"'
    )
    for ln in lines:
        svg.append(f'<text x="{pad + inner}" y="{y}" {title_font}>{esc(ln)}</text>')
        y += line_height
    svg.append("</svg>")
    return "\n".join(svg)


def main() -> None:
    lines = run_scan()
    OUT.write_text(build(lines), encoding="utf-8")
    print(f"wrote {OUT} ({len(lines)} lines)")


if __name__ == "__main__":
    main()
