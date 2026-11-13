"""Tests for deterministic replay (M4).

Covers:
- FixtureStore record/load round-trip
- Recorder records and Replayer replays identical responses
- Determinism: two replay runs produce byte-identical JSON (minus timestamps)
- Offline proof: replay works with socket.connect monkeypatched to raise
- ReplayMissError on cache miss, never falls back to network
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import httpx
import pytest

from inspectra.cli import main
from inspectra.models import ScanOptions, Target
from inspectra.orchestrator import run_scan
from inspectra.replay import FixtureStore, ReplayMissError

FIXTURE_DIR = "tests/fixtures/replay"


def _strip_volatile(data: dict) -> dict:
    """Remove timestamp/duration fields for determinism comparison."""
    data = json.loads(json.dumps(data))  # deep copy
    data.pop("started_at", None)
    data.pop("started_at_ist", None)
    data.pop("finished_at", None)
    data.pop("duration_seconds", None)
    return data


# --- FixtureStore record/load ---


def test_fixture_store_record_load_roundtrip(tmp_path) -> None:
    """Record then load returns the same data."""
    store = FixtureStore(tmp_path / "fx")

    request = httpx.Request("GET", "http://example.com/test")
    response = httpx.Response(
        200,
        headers={"content-type": "text/plain"},
        content=b"hello",
        request=request,
    )
    store.record("GET", "http://example.com/test", response, 42.5)

    loaded = store.load("GET", "http://example.com/test")
    assert loaded["status"] == 200
    assert loaded["method"] == "GET"
    assert loaded["url"] == "http://example.com/test"
    assert loaded["elapsed_ms"] == 42.5


def test_fixture_store_load_miss_raises(tmp_path) -> None:
    """Cache miss raises ReplayMissError, never falls back to network."""
    store = FixtureStore(tmp_path / "fx")
    with pytest.raises(ReplayMissError, match="http://example.com/missing"):
        store.load("GET", "http://example.com/missing")


# --- Determinism gate ---


def test_replay_determinism(tmp_path, fixture_server, target) -> None:
    """Two replay runs against the same fixtures produce identical JSON
    after stripping volatile fields."""
    from inspectra.report import json_report

    # Record from the live fixture server once
    record_dir = tmp_path / "recorded"
    options_record = ScanOptions(
        save_fixtures=str(record_dir),
        allow_private=True,
        authorized=True,
    )
    run_scan(target, options_record)

    # Copy recorded fixtures to replay dir
    replay_dir = tmp_path / "replayed"
    replay_dir.mkdir()
    import shutil

    for f in record_dir.iterdir():
        shutil.copy(f, replay_dir / f.name)

    # Replay twice from the same fixtures
    options_replay = ScanOptions(
        replay_dir=str(replay_dir),
        allow_private=True,
        authorized=True,
    )
    result1 = run_scan(target, options_replay)
    result2 = run_scan(target, options_replay)

    # Render both as JSON and compare after stripping volatile fields
    json1 = _strip_volatile(json_report.render(result1))
    json2 = _strip_volatile(json_report.render(result2))
    assert json1 == json2


# --- Offline proof ---


def test_replay_offline_proof(tmp_path, fixture_server, target) -> None:
    """Replay works with socket.connect monkeypatched to raise -- no network."""
    # First record from the live server
    record_dir = tmp_path / "recorded"
    options_record = ScanOptions(
        save_fixtures=str(record_dir),
        allow_private=True,
        authorized=True,
    )
    run_scan(target, options_record)

    # Copy to replay dir
    replay_dir = tmp_path / "replayed"
    replay_dir.mkdir()
    import shutil

    for f in record_dir.iterdir():
        shutil.copy(f, replay_dir / f.name)

    # Now replay with socket blocked
    options_replay = ScanOptions(
        replay_dir=str(replay_dir),
        allow_private=True,
        authorized=True,
    )
    with (
        patch("socket.socket.connect", side_effect=AssertionError("no network")),
        patch("socket.getaddrinfo", side_effect=AssertionError("no DNS")),
    ):
        result2 = run_scan(target, options_replay)

    assert result2.findings  # replay produced findings


# --- evidence_hash on findings ---


def test_evidence_hash_present(tmp_path, fixture_server, target) -> None:
    """Every finding has an evidence_hash after a scan."""
    record_dir = tmp_path / "fx"
    options = ScanOptions(
        save_fixtures=str(record_dir),
        allow_private=True,
        authorized=True,
    )
    result = run_scan(target, options)
    for finding in result.findings:
        assert finding.evidence_hash is not None
        assert len(finding.evidence_hash) == 16


# --- CLI mutually exclusive ---


def test_cli_save_fixtures_and_replay_exclusive(
    fixture_server, target, tmp_path, monkeypatch
) -> None:
    """--save-fixtures and --replay are mutually exclusive."""
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
                "--save-fixtures",
                str(tmp_path / "fx"),
                "--replay",
                str(tmp_path / "fx2"),
            ]
        )


# --- Committed fixture replay ---


def test_replay_committed_fixtures(tmp_path, target) -> None:
    """Replay from committed fixtures works offline."""
    fixtures_dir = Path(__file__).parent / "fixtures" / "replay"
    assert fixtures_dir.exists(), "committed fixtures missing"

    # Committed fixtures were recorded on port 9999
    fixed_target = Target(
        input="http://127.0.0.1:9999",
        hostname="127.0.0.1",
        port=9999,
        scheme="http",
    )
    options = ScanOptions(
        replay_dir=str(fixtures_dir),
        allow_private=True,
        authorized=True,
    )
    result = run_scan(fixed_target, options)
    assert result.findings  # replay produced findings


# --- D3: Determinism diff helper ---


def test_replay_determinism_from_committed_fixtures(tmp_path, target) -> None:
    """Two replay runs from committed fixtures produce identical JSON
    after stripping volatile fields."""
    from inspectra.report import json_report

    fixtures_dir = Path(__file__).parent / "fixtures" / "replay"
    assert fixtures_dir.exists(), "committed fixtures missing"

    fixed_target = Target(
        input="http://127.0.0.1:9999",
        hostname="127.0.0.1",
        port=9999,
        scheme="http",
    )
    options = ScanOptions(
        replay_dir=str(fixtures_dir),
        allow_private=True,
        authorized=True,
    )
    result1 = run_scan(fixed_target, options)
    result2 = run_scan(fixed_target, options)

    json1 = _strip_volatile(json_report.render(result1))
    json2 = _strip_volatile(json_report.render(result2))
    assert json1 == json2, "Two replay runs must produce identical reports"


def test_replay_missing_dir_exits_2(tmp_path, target) -> None:
    """Replay from a missing directory exits 2 with a clear error."""
    missing_dir = tmp_path / "does-not-exist"
    code = main(
        [
            "scan",
            target.input,
            "--yes",
            "--skip-ports",
            "--allow-private",
            "--authorized",
            "--replay",
            str(missing_dir),
        ]
    )
    assert code == 2


def test_replay_empty_dir_exits_2(tmp_path, target) -> None:
    """Replay from an empty directory exits 2."""
    empty_dir = tmp_path / "empty"
    empty_dir.mkdir()
    code = main(
        [
            "scan",
            target.input,
            "--yes",
            "--skip-ports",
            "--allow-private",
            "--authorized",
            "--replay",
            str(empty_dir),
        ]
    )
    assert code == 2


def test_replay_dir_without_index_exits_2(tmp_path, target) -> None:
    """Replay from a directory without index.json exits 2."""
    no_index_dir = tmp_path / "no-index"
    no_index_dir.mkdir()
    (no_index_dir / "somefile.json").write_text("{}")
    code = main(
        [
            "scan",
            target.input,
            "--yes",
            "--skip-ports",
            "--allow-private",
            "--authorized",
            "--replay",
            str(no_index_dir),
        ]
    )
    assert code == 2


def test_replay_empty_index_exits_2(tmp_path, target) -> None:
    """Replay from a directory with an empty index.json exits 2."""
    empty_index_dir = tmp_path / "empty-index"
    empty_index_dir.mkdir()
    (empty_index_dir / "index.json").write_text("{}")
    code = main(
        [
            "scan",
            target.input,
            "--yes",
            "--skip-ports",
            "--allow-private",
            "--authorized",
            "--replay",
            str(empty_index_dir),
        ]
    )
    assert code == 2


def test_replay_missing_response_exits_2(tmp_path, fixture_server, target) -> None:
    """Replay when a required request has no fixture exits 2."""
    # Record from the live server first
    record_dir = tmp_path / "recorded"
    options_record = ScanOptions(
        save_fixtures=str(record_dir),
        allow_private=True,
        authorized=True,
    )
    run_scan(target, options_record)

    # Copy fixtures but delete one response file
    replay_dir = tmp_path / "replayed"
    replay_dir.mkdir()
    import shutil

    for f in record_dir.iterdir():
        shutil.copy(f, replay_dir / f.name)

    # Delete one fixture file but leave index.json referencing it
    index_path = replay_dir / "index.json"
    index = json.loads(index_path.read_text(encoding="utf-8"))
    if index:
        first_key = next(iter(index))
        missing_file = replay_dir / index[first_key]["file"]
        missing_file.unlink()

    code = main(
        [
            "scan",
            target.input,
            "--yes",
            "--skip-ports",
            "--allow-private",
            "--authorized",
            "--replay",
            str(replay_dir),
        ]
    )
    assert code == 2
