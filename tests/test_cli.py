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
        ["scan", target.input, "--yes", "--skip-ports", "--format", "html", "--output-dir", "out"]
    )
    assert code == 1
    assert (tmp_path / "out" / "report.html").exists()
    assert not (tmp_path / "out" / "report.md").exists()


def test_cli_invalid_target(fixture_server, tmp_path, monkeypatch, capsys) -> None:
    monkeypatch.chdir(tmp_path)
    code = main(["scan", "not a host", "--yes"])
    assert code == 2
    assert "Invalid target" in capsys.readouterr().out


def test_cli_consent_declined(fixture_server, target, tmp_path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr("builtins.input", lambda prompt: "n")
    code = main(["scan", target.input, "--skip-ports"])
    assert code == 2


def test_cli_consent_accepted_and_persisted(
    fixture_server, target, tmp_path, monkeypatch, fake_home
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr("builtins.input", lambda prompt: "y")
    code = main(["scan", target.input, "--skip-ports", "--output-dir", "out"])
    assert code == 1
    config = json.loads((fake_home / ".config" / "inspectra" / "config.json").read_text())
    assert config["authorized_use_agreed"] is True


def test_cli_version_flag(capsys) -> None:
    with pytest.raises(SystemExit) as excinfo:
        main(["--version"])
    assert excinfo.value.code == 0
    assert "inspectra" in capsys.readouterr().out
