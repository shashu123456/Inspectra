"""Pre-commit hook wrapper for Inspectra.

Reads INSPECTRA_TARGET environment variable. If unset, prints a skip line
and exits 0 (no target configured). If set, runs the normal scanner with
--no-findings against that target.
"""

from __future__ import annotations

import os
import sys

from inspectra.cli import main


def _run() -> int:
    target = os.environ.get("INSPECTRA_TARGET", "").strip()
    if not target:
        print("inspectra-precommit: INSPECTRA_TARGET not set, skipping scan")
        return 0
    argv = [
        "scan",
        target,
        "--yes",
        "--skip-ports",
        "--allow-private",
        "--authorized",
        "--allow-insecure",
        "--no-findings",
    ]
    return main(argv)


if __name__ == "__main__":
    sys.exit(_run())
