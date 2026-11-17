"""Tests for the custom check extension point (--rules-dir, --list-checks)."""

from __future__ import annotations

import json

import pytest

from inspectra.checks import CheckError, ordered_checks
from inspectra.checks.context import ScanContext
from inspectra.checks.loader import load_rules_dir, run_custom_checks
from inspectra.models import ScanOptions, Target


class FakeClient:
    """Minimal HTTP client stand-in for tests."""

    def __init__(self, responses: dict[str, tuple[int, str]]):
        self._responses = responses

    def get(self, url):
        class _Resp:
            def __init__(self, status_code, text):
                self.status_code = status_code
                self.text = text

        if url in self._responses:
            status, text = self._responses[url]
            return _Resp(status, text)
        return _Resp(404, "not found")


def _make_target() -> Target:
    return Target(
        input="http://127.0.0.1:9999",
        hostname="127.0.0.1",
        port=9999,
        scheme="http",
    )


def _make_context(client=None) -> ScanContext:
    return ScanContext(options=ScanOptions(), client=client)


def test_custom_check_loads_and_reports(tmp_path) -> None:
    check_file = tmp_path / "my_check.py"
    check_file.write_text(
        'RULE_ID = "CUST-TEST"\n'
        'TITLE = "My custom check"\n'
        "\n"
        "def check(target, context):\n"
        "    from inspectra.models import Finding, Severity, Confidence\n"
        "    return [Finding(\n"
        '        rule_id="CUST-TEST", title="My custom check",\n'
        '        category="custom", severity=Severity.INFO,\n'
        "        confidence=Confidence.HIGH,\n"
        '        description="a custom finding",\n'
        '        why_it_matters="it matters",\n'
        '        recommendation="fix it",\n'
        '        evidence=["http://127.0.0.1:9999/"],\n'
        "    )]\n"
    )
    modules = load_rules_dir(str(tmp_path))
    assert len(modules) == 1
    assert modules[0].RULE_ID == "CUST-TEST"

    target = _make_target()
    context = _make_context()
    findings = run_custom_checks(modules, target, context)
    assert len(findings) == 1
    assert findings[0].rule_id == "CUST-TEST"


def test_missing_attribute_error_is_actionable(tmp_path) -> None:
    check_file = tmp_path / "broken.py"
    check_file.write_text('TITLE = "no rule id"\n')
    with pytest.raises(CheckError) as excinfo:
        load_rules_dir(str(tmp_path))
    assert "broken.py" in str(excinfo.value)
    assert "RULE_ID" in str(excinfo.value)


def test_duplicate_rule_id_rejected(tmp_path) -> None:
    check1 = tmp_path / "a.py"
    check1.write_text(
        'RULE_ID = "DUP"\nTITLE = "A"\n\ndef check(target, context):\n    return []\n'
    )
    check2 = tmp_path / "b.py"
    check2.write_text(
        'RULE_ID = "DUP"\nTITLE = "B"\n\ndef check(target, context):\n    return []\n'
    )
    with pytest.raises(CheckError) as excinfo:
        load_rules_dir(str(tmp_path))
    assert "DUP" in str(excinfo.value)


def test_list_checks_includes_custom(tmp_path, monkeypatch) -> None:
    check_file = tmp_path / "custom.py"
    check_file.write_text(
        'RULE_ID = "CUST-LIST"\nTITLE = "Listed check"\n'
        "\ndef check(target, context):\n    return []\n"
    )
    modules = load_rules_dir(str(tmp_path))
    names_and_sources = [(name, "builtin") for name, _ in ordered_checks(False)]
    for module in modules:
        names_and_sources.append((module.RULE_ID, "custom"))

    ids = {n for n, _ in names_and_sources}
    assert "CUST-LIST" in ids
    assert all(s in ("builtin", "custom") for _, s in names_and_sources)


def test_custom_check_appears_in_sarif(tmp_path, monkeypatch) -> None:
    """Custom check findings are included in SARIF output."""
    check_file = tmp_path / "sarif_check.py"
    check_file.write_text(
        'RULE_ID = "CUST-SARIF"\nTITLE = "SARIF check"\n'
        "\nfrom inspectra.models import Finding, Severity, Confidence\n"
        "def check(target, context):\n"
        "    return [Finding(\n"
        '        rule_id="CUST-SARIF", title="SARIF check",\n'
        '        category="custom", severity=Severity.INFO,\n'
        "        confidence=Confidence.HIGH,\n"
        '        description="a sarif finding",\n'
        '        why_it_matters="it matters",\n'
        '        recommendation="fix it",\n'
        '        evidence=["http://127.0.0.1:9999/"],\n'
        "    )]\n"
    )
    modules = load_rules_dir(str(tmp_path))
    target = _make_target()
    context = _make_context()
    findings = run_custom_checks(modules, target, context)

    out_path = tmp_path / "report.sarif"
    from datetime import datetime, timezone

    from inspectra.models import ScanMetadata, ScanResult
    from inspectra.report.sarif_report import write as sarif_write

    result = ScanResult(
        target=target,
        metadata=ScanMetadata(
            version="2.2.0", target="http://127.0.0.1:9999", started_at=datetime.now(timezone.utc)
        ),
        findings=findings,
    )
    sarif_write(result, out_path)
    data = json.loads(out_path.read_text(encoding="utf-8"))
    rule_ids = {r["id"] for r in data["runs"][0]["tool"]["driver"]["rules"]}
    assert "CUST-SARIF" in rule_ids


def test_rules_dir_not_found_errors() -> None:
    with pytest.raises(CheckError) as excinfo:
        load_rules_dir("/nonexistent/dir")
    assert "not found" in str(excinfo.value)


def test_check_not_callable_rejected(tmp_path) -> None:
    check_file = tmp_path / "bad.py"
    check_file.write_text('RULE_ID = "BAD"\nTITLE = "Bad"\ncheck = 42\n')
    with pytest.raises(CheckError) as excinfo:
        load_rules_dir(str(tmp_path))
    assert "callable" in str(excinfo.value)


def test_custom_check_run_failure(tmp_path) -> None:
    check_file = tmp_path / "failing.py"
    check_file.write_text(
        'RULE_ID = "FAIL"\nTITLE = "Failing"\n'
        '\ndef check(target, context):\n    raise RuntimeError("boom")\n'
    )
    modules = load_rules_dir(str(tmp_path))
    target = _make_target()
    context = _make_context()
    with pytest.raises(CheckError) as excinfo:
        run_custom_checks(modules, target, context)
    assert "FAIL" in str(excinfo.value)


def test_import_failure_in_custom_check(tmp_path) -> None:
    check_file = tmp_path / "badimport.py"
    check_file.write_text(
        'RULE_ID = "BADIMP"\nTITLE = "Bad import"\n'
        "import nonexistent_module_xyz_12345\n"
        "\ndef check(target, context):\n    return []\n"
    )
    with pytest.raises(CheckError) as excinfo:
        load_rules_dir(str(tmp_path))
    assert "badimport.py" in str(excinfo.value)


def test_list_checks_built_in() -> None:
    names = [name for name, _ in ordered_checks(False)]
    assert "dns" in names
    assert "http" in names
    assert "headers" in names
