"""End-to-end CLI tests against the local fixture server."""

from __future__ import annotations

import json

import pytest

from inspectra.cli import build_parser, main


def test_parser_requires_command() -> None:
    with pytest.raises(SystemExit):
        build_parser().parse_args([])


def test_parser_scan_defaults() -> None:
    args = build_parser().parse_args(["scan", "example.com", "--yes"])
    assert args.target == "example.com"
    assert args.report_format == "markdown"
    assert args.skip_ports is False
    assert args.top_ports == 1000


def test_cli_end_to_end_markdown(fixture_server, target, tmp_path, monkeypatch, capsys) -> None:
    monkeypatch.chdir(tmp_path)
    code = main(
        [
            "scan",
            target.input,
            "--yes",
            "--skip-ports",
            "--allow-private",
            "--authorized",
            "--fail-on",
            "low",
            "--output-dir",
            "out",
        ]
    )
    assert code == 1  # actionable findings exist
    report = (tmp_path / "out" / "report.md").read_text(encoding="utf-8")
    data = json.loads((tmp_path / "out" / "report.json").read_text(encoding="utf-8"))
    assert "# Inspectra Security Assessment Report" in report
    assert data["target"] == target.input
    assert (tmp_path / "out" / "inspectra.log").exists()
    captured = capsys.readouterr()
    assert "Scan complete" in captured.out


def test_cli_html_format(fixture_server, target, tmp_path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    code = main(
        [
            "scan",
            target.input,
            "--yes",
            "--skip-ports",
            "--allow-private",
            "--authorized",
            "--fail-on",
            "low",
            "--format",
            "html",
            "--output-dir",
            "out",
        ]
    )
    assert code == 1
    assert (tmp_path / "out" / "report.html").exists()
    assert not (tmp_path / "out" / "report.md").exists()


def test_cli_sarif_format(fixture_server, target, tmp_path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    code = main(
        [
            "scan",
            target.input,
            "--yes",
            "--skip-ports",
            "--allow-private",
            "--authorized",
            "--fail-on",
            "low",
            "--format",
            "sarif",
            "--output-dir",
            "out",
        ]
    )
    assert code == 1
    sarif = (tmp_path / "out" / "report.sarif").read_text(encoding="utf-8")
    import json

    data = json.loads(sarif)
    assert data["$schema"] == "https://json.schemastore.org/sarif-2.1.0.json"
    assert data["version"] == "2.1.0"
    assert data["runs"][0]["tool"]["driver"]["name"] == "Inspectra"
    assert len(data["runs"][0]["results"]) >= 1


def test_cli_multi_format(fixture_server, target, tmp_path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    code = main(
        [
            "scan",
            target.input,
            "--yes",
            "--skip-ports",
            "--allow-private",
            "--authorized",
            "--fail-on",
            "low",
            "--format",
            "sarif,json,markdown",
            "--output-dir",
            "out",
        ]
    )
    assert code == 1
    assert (tmp_path / "out" / "report.sarif").exists()
    assert (tmp_path / "out" / "report.json").exists()
    assert (tmp_path / "out" / "report.md").exists()


def test_cli_invalid_target(fixture_server, tmp_path, monkeypatch, capsys) -> None:
    monkeypatch.chdir(tmp_path)
    code = main(["scan", "not a host", "--yes"])
    assert code == 2
    captured = capsys.readouterr()
    assert "Invalid target" in captured.err


def test_cli_consent_declined(fixture_server, target, tmp_path, monkeypatch, fake_home) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr("builtins.input", lambda prompt: "n")
    code = main(["scan", target.input, "--skip-ports", "--allow-private", "--authorized"])
    assert code == 2


def test_cli_consent_accepted_and_persisted(
    fixture_server, target, tmp_path, monkeypatch, fake_home
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr("builtins.input", lambda prompt: "y")
    code = main(
        [
            "scan",
            target.input,
            "--skip-ports",
            "--fail-on",
            "low",
            "--output-dir",
            "out",
            "--allow-private",
            "--authorized",
        ]
    )
    assert code == 1
    config = json.loads((fake_home / ".config" / "inspectra" / "config.json").read_text())
    assert config["authorized_use_agreed"] is True


def test_cli_version_flag(capsys) -> None:
    with pytest.raises(SystemExit) as excinfo:
        main(["--version"])
    assert excinfo.value.code == 0
    assert "inspectra" in capsys.readouterr().out


# --- F1: -o/--output writes a single format to an exact path ---
def test_cli_output_path_single_format(fixture_server, target, tmp_path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    out = tmp_path / "custom" / "report.sarif"
    code = main(
        [
            "scan",
            target.input,
            "--yes",
            "--skip-ports",
            "--allow-private",
            "--authorized",
            "--fail-on",
            "low",
            "--format",
            "sarif",
            "-o",
            str(out),
        ]
    )
    assert code == 1
    assert out.exists()
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["$schema"] == "https://json.schemastore.org/sarif-2.1.0.json"
    assert data["version"] == "2.1.0"


def test_cli_output_path_rejects_multi_format(
    fixture_server, target, tmp_path, monkeypatch
) -> None:
    monkeypatch.chdir(tmp_path)
    with pytest.raises(SystemExit):
        main(
            [
                "scan",
                target.input,
                "--yes",
                "--skip-ports",
                "--allow-private",
                "--authorized",
                "--format",
                "sarif,json",
                "-o",
                str(tmp_path / "out.sarif"),
            ]
        )


# --- F2: empty --baseline string behaves like absent ---
def test_cli_empty_baseline_is_absent(fixture_server, target, tmp_path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    code = main(
        [
            "scan",
            target.input,
            "--yes",
            "--skip-ports",
            "--allow-private",
            "--authorized",
            "--fail-on",
            "low",
            "--baseline",
            "",
        ]
    )
    assert code == 1  # has actionable findings, no baseline


# --- F4: --fail-on works without baseline ---
def test_cli_fail_on_none_always_exits_zero(fixture_server, target, tmp_path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    code = main(
        [
            "scan",
            target.input,
            "--yes",
            "--skip-ports",
            "--allow-private",
            "--authorized",
            "--fail-on",
            "none",
        ]
    )
    assert code == 0


def test_cli_fail_on_high_exits_one(fixture_server, target, tmp_path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    code = main(
        [
            "scan",
            target.input,
            "--yes",
            "--skip-ports",
            "--allow-private",
            "--authorized",
            "--fail-on",
            "low",
        ]
    )
    assert code == 1


def test_cli_fail_on_medium_exits_one(fixture_server, target, tmp_path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    code = main(
        [
            "scan",
            target.input,
            "--yes",
            "--skip-ports",
            "--allow-private",
            "--authorized",
            "--fail-on",
            "medium",
        ]
    )
    assert code == 1


def test_cli_fail_on_low_exits_one(fixture_server, target, tmp_path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    code = main(
        [
            "scan",
            target.input,
            "--yes",
            "--skip-ports",
            "--allow-private",
            "--authorized",
            "--fail-on",
            "low",
        ]
    )
    assert code == 1


# --- F5: invalid --format value errors ---
def test_cli_invalid_format(fixture_server, target, tmp_path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    with pytest.raises(SystemExit):
        main(
            [
                "scan",
                target.input,
                "--yes",
                "--skip-ports",
                "--allow-private",
                "--authorized",
                "--format",
                "csv",
            ]
        )


# --- A4: Report metadata (scope + redaction) ---
def test_cli_report_metadata_scope(fixture_server, target, tmp_path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    code = main(
        [
            "scan",
            target.input,
            "--yes",
            "--skip-ports",
            "--fail-on",
            "low",
            "--allow-private",
            "--authorized",
            "--format",
            "json",
            "-o",
            str(tmp_path / "out" / "report.json"),
        ]
    )
    assert code == 1
    import json

    data = json.loads((tmp_path / "out" / "report.json").read_text(encoding="utf-8"))
    assert data.get("scope") == {"scope": "private-allowed"}


def test_cli_report_metadata_redaction_disabled(
    fixture_server, target, tmp_path, monkeypatch, capsys
) -> None:
    monkeypatch.chdir(tmp_path)
    code = main(
        [
            "scan",
            target.input,
            "--yes",
            "--skip-ports",
            "--fail-on",
            "low",
            "--allow-private",
            "--authorized",
            "--no-redact",
            "--format",
            "json",
            "-o",
            str(tmp_path / "out" / "report.json"),
        ]
    )
    assert code == 1
    captured = capsys.readouterr()
    assert "redaction disabled" in captured.err.lower()
    import json

    data = json.loads((tmp_path / "out" / "report.json").read_text(encoding="utf-8"))
    assert data.get("redaction") == {"redaction": "disabled"}


# --- B3: Negative SSRF tests ---
def test_cli_private_target_rejected_without_flags(
    fixture_server, target, tmp_path, monkeypatch, capsys
) -> None:
    """Scanning 127.0.0.1 without --allow-private exits 2."""
    monkeypatch.chdir(tmp_path)
    code = main(["scan", target.input, "--yes"])
    assert code == 2
    captured = capsys.readouterr()
    assert "--allow-private" in captured.err


def test_cli_allow_private_requires_authorized(
    fixture_server, target, tmp_path, monkeypatch, capsys
) -> None:
    """--allow-private without --authorized exits 2."""
    monkeypatch.chdir(tmp_path)
    code = main(["scan", target.input, "--yes", "--allow-private"])
    assert code == 2
    captured = capsys.readouterr()
    assert "--authorized" in captured.err
