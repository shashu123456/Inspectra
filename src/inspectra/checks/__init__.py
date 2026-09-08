"""Check registry and shared check exceptions.

Each check is a module exposing ``run(target, context) -> list[Finding]``.
Adding a new assessment area means: create the module, add its ``run``
function to :data:`ALL_CHECKS`, and document it (see CONTRIBUTING.md).
"""

from __future__ import annotations

from collections.abc import Callable

from inspectra.checks.context import ScanContext
from inspectra.models import Finding, Target

Check = Callable[[Target, ScanContext], list[Finding]]


class CheckError(Exception):
    """A check failed non-fatally; the scan continues without it."""


class FatalCheckError(CheckError):
    """A check failed in a way that must abort the whole scan."""


def _load_checks() -> dict[str, Check]:
    """Import and index every check module.

    Imported lazily so check modules can safely import ``CheckError`` from
    this package without creating a circular import.
    """
    from inspectra.checks import directories, dns, fingerprint, headers, http, ports, robots, tls

    return {
        "dns": dns.run,
        "ports": ports.run,
        "http": http.run,
        "tls": tls.run,
        "headers": headers.run,
        "fingerprint": fingerprint.run,
        "robots": robots.run,
        "directories": directories.run,
    }


ALL_CHECKS: dict[str, Check] = _load_checks()

DEFAULT_CHECK_ORDER = [
    "dns",
    "ports",
    "http",
    "tls",
    "headers",
    "fingerprint",
    "robots",
]


def ordered_checks(include_directories: bool = False) -> list[tuple[str, Check]]:
    """Return the checks in execution order.

    Order matters: HTTP must run before the checks that consume its cached
    response (headers, fingerprint, robots), and DNS runs first so later
    checks can rely on resolved addresses.
    """
    names = [*DEFAULT_CHECK_ORDER]
    if include_directories:
        names.append("directories")
    return [(name, ALL_CHECKS[name]) for name in names]


__all__ = [
    "ALL_CHECKS",
    "Check",
    "CheckError",
    "FatalCheckError",
    "ScanContext",
    "ordered_checks",
]
