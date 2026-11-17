"""Custom check loader for Inspectra.

Loads *.py modules from a user-supplied rules directory. Each module must
expose RULE_ID, TITLE, and check(ctx) -> list[Finding].
"""

from __future__ import annotations

import importlib.util
from pathlib import Path
from types import ModuleType

from inspectra.checks import CheckError
from inspectra.checks.context import ScanContext
from inspectra.models import Finding, Target


def load_rules_dir(rules_dir: str) -> list[ModuleType]:
    """Load all *.py modules from ``rules_dir``.

    Raises :class:`CheckError` with an actionable message if a module is
    missing required attributes, has a duplicate RULE_ID, or fails to import.
    """
    path = Path(rules_dir)
    if not path.is_dir():
        raise CheckError(f"--rules-dir not found: {rules_dir}")

    modules: list[ModuleType] = []
    seen_ids: set[str] = set()

    for py_file in sorted(path.glob("*.py")):
        spec = importlib.util.spec_from_file_location(py_file.stem, py_file)
        if spec is None or spec.loader is None:
            raise CheckError(f"Cannot load custom check: {py_file}")
        module = importlib.util.module_from_spec(spec)
        try:
            spec.loader.exec_module(module)
        except Exception as exc:
            raise CheckError(f"Custom check {py_file.name} failed to import: {exc}") from exc

        for attr in ("RULE_ID", "TITLE", "check"):
            if not hasattr(module, attr):
                raise CheckError(
                    f"Custom check {py_file.name} is missing required attribute: {attr}"
                )

        if not callable(module.check):
            raise CheckError(f"Custom check {py_file.name} 'check' must be callable")

        if module.RULE_ID in seen_ids:
            raise CheckError(f"Duplicate RULE_ID {module.RULE_ID!r} in {py_file.name}")
        seen_ids.add(module.RULE_ID)
        modules.append(module)

    return modules


def run_custom_checks(
    modules: list[ModuleType],
    target: Target,
    context: ScanContext,
) -> list[Finding]:
    """Run all loaded custom check modules and return their findings."""
    findings: list[Finding] = []
    for module in modules:
        try:
            results = module.check(target, context)
        except Exception as exc:
            raise CheckError(f"Custom check {module.RULE_ID} failed: {exc}") from exc
        for finding in results:
            findings.append(finding)
    return findings
