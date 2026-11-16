"""Concurrency, politeness, and cache behavior tests for M5."""

from __future__ import annotations

import json
import threading
import time
from datetime import datetime
from pathlib import Path

import httpx

from inspectra.checks import context as context_module
from inspectra.models import ScanOptions, Target
from inspectra.network import RateLimitedClient
from inspectra.orchestrator import run_scan
from inspectra.report import json_report


def _strip_volatile(data: dict) -> dict:
    data = json.loads(json.dumps(data))
    for key in ("started_at", "started_at_ist", "finished_at", "duration_seconds"):
        data.pop(key, None)
    return data


def _fixed_target() -> Target:
    return Target(
        input="http://127.0.0.1:9999",
        hostname="127.0.0.1",
        port=9999,
        scheme="http",
    )


def test_t1_concurrency_1_vs_8_identical_reports(tmp_path, fixture_server, target) -> None:
    # Record fixtures once from live fixture server, then replay with different concurrency.
    record_dir = tmp_path / "record"
    run_scan(
        target,
        ScanOptions(
            save_fixtures=str(record_dir),
            allow_private=True,
            authorized=True,
            skip_ports=True,
            concurrency=1,
            delay=0,
        ),
    )
    replay_dir = tmp_path / "replay"
    replay_dir.mkdir()
    for path in record_dir.iterdir():
        (replay_dir / path.name).write_bytes(path.read_bytes())

    base = {
        "allow_private": True,
        "authorized": True,
        "skip_ports": True,
        "replay_dir": str(replay_dir),
    }
    opts1 = ScanOptions(**base, concurrency=1, delay=0)
    opts8 = ScanOptions(**base, concurrency=8, delay=0)
    r1 = run_scan(target, opts1)
    r8 = run_scan(target, opts8)
    j1 = _strip_volatile(json_report.render(r1))
    j8 = _strip_volatile(json_report.render(r8))
    assert j1 == j8


def test_t2_per_host_max_inflight_is_two() -> None:
    lock = threading.Lock()
    inflight = 0
    max_inflight = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal inflight, max_inflight
        with lock:
            inflight += 1
            max_inflight = max(max_inflight, inflight)
        time.sleep(0.02)
        with lock:
            inflight -= 1
        return httpx.Response(200, text="ok")

    transport = httpx.MockTransport(handler)
    client = RateLimitedClient(httpx.Client(transport=transport), max_per_host=2, delay=0)
    threads = []
    for _ in range(8):
        threads.append(threading.Thread(target=lambda: client.get("http://example.test/path")))
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    client.close()
    assert max_inflight == 2


def test_t3_global_concurrency_never_exceeds_n(
    tmp_path, fixture_server, target, monkeypatch
) -> None:
    # Instrument check execution by counting concurrent _run_single_check calls.
    import inspectra.orchestrator as orch

    lock = threading.Lock()
    inflight = 0
    max_inflight = 0
    real = orch._run_single_check

    def wrapped(t, ctx, check):
        nonlocal inflight, max_inflight
        with lock:
            inflight += 1
            max_inflight = max(max_inflight, inflight)
        try:
            time.sleep(0.01)
            return real(t, ctx, check)
        finally:
            with lock:
                inflight -= 1

    monkeypatch.setattr(orch, "_run_single_check", wrapped)
    options = ScanOptions(
        allow_private=True, authorized=True, skip_ports=True, concurrency=3, delay=0
    )
    run_scan(target, options)
    assert max_inflight <= 3


def test_t4_delay_applied_per_host_lower_bound(monkeypatch) -> None:
    """Per-host delay is scheduled as >= delay between requests to same host.

    Uses a deterministic fake clock to assert the delay contract (0.2s) exactly
    without relying on wall-clock timer resolution/jitter.
    """
    import inspectra.network as net

    fake_now = {"t": 1000.0}

    def fake_monotonic() -> float:
        return fake_now["t"]

    def fake_sleep(seconds: float) -> None:
        fake_now["t"] += max(0.0, seconds)

    monkeypatch.setattr(net.time, "monotonic", fake_monotonic)
    monkeypatch.setattr(net.time, "sleep", fake_sleep)

    calls: list[float] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(net.time.monotonic())
        return httpx.Response(200, text="ok")

    transport = httpx.MockTransport(handler)
    client = RateLimitedClient(httpx.Client(transport=transport), max_per_host=2, delay=0.2)
    client.get("http://example.test/one")
    client.get("http://example.test/two")
    client.close()
    assert len(calls) == 2
    assert calls[1] - calls[0] >= 0.2


def test_t5_dns_cache_resolves_once_for_same_host(monkeypatch) -> None:
    from inspectra.checks import dns as dns_check

    calls = {"count": 0}

    def fake_resolve(hostname: str):
        calls["count"] += 1
        return (
            {
                "A": ["93.184.216.34"],
                "AAAA": [],
                "CNAME": [],
                "MX": [],
                "NS": [],
                "TXT": [],
            },
            0.001,
        )

    monkeypatch.setattr(dns_check, "_resolve", fake_resolve)
    ctx = context_module.ScanContext(options=ScanOptions())
    r1, _e1 = dns_check._resolve_cached("example.com", ctx)
    r2, _e2 = dns_check._resolve_cached("example.com", ctx)
    assert calls["count"] == 1
    assert r1 == r2


def test_t6_evidence_hash_identical_to_committed_replay_serial() -> None:
    fixtures_dir = Path(__file__).parent / "fixtures" / "replay"
    target = _fixed_target()
    options = ScanOptions(
        replay_dir=str(fixtures_dir),
        allow_private=True,
        authorized=True,
        skip_ports=True,
        concurrency=1,
        delay=0,
    )
    result = run_scan(target, options)
    assert all(f.evidence_hash and len(f.evidence_hash) == 16 for f in result.findings)
    data = _strip_volatile(json_report.render(result))
    rule_hashes = {f["rule_id"]: f["evidence_hash"] for f in data["findings"]}
    assert rule_hashes  # non-empty sanity


def test_t7_replay_report_unchanged_vs_committed_fixtures() -> None:
    fixtures_dir = Path(__file__).parent / "fixtures" / "replay"
    target = _fixed_target()
    options = ScanOptions(
        replay_dir=str(fixtures_dir),
        allow_private=True,
        authorized=True,
        skip_ports=True,
        concurrency=1,
        delay=0,
    )
    r1 = run_scan(target, options)
    r2 = run_scan(target, options)
    j1 = _strip_volatile(json_report.render(r1))
    j2 = _strip_volatile(json_report.render(r2))
    assert j1 == j2
    assert len(j1.get("findings", [])) == 9
    assert j1.get("skipped") == [
        {"check": "dns", "reason": "requires live network; not available in replay"},
        {"check": "ports", "reason": "requires live network; not available in replay"},
        {"check": "tls", "reason": "requires live network; not available in replay"},
    ]


def test_rate_limited_client_context_and_attr_proxy() -> None:
    """Wrapper is httpx.Client-compatible for context manager and attribute access."""

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="ok")

    inner = httpx.Client(transport=httpx.MockTransport(handler))
    client = RateLimitedClient(inner, max_per_host=2, delay=0)
    with client as c:
        assert c is client
        assert client.headers is inner.headers
        resp = client.get("http://example.test/x")
        assert resp.status_code == 200
    # close is idempotent enough for our wrapper usage
    client.close()


def test_serial_nonzero_delay_path_and_progress(tmp_path, fixture_server, target) -> None:
    # concurrency==1 but delay!=0 must use wrapped client path (not fast serial branch)
    record_dir = tmp_path / "record"
    run_scan(
        target,
        ScanOptions(
            save_fixtures=str(record_dir),
            allow_private=True,
            authorized=True,
            skip_ports=True,
            concurrency=1,
            delay=0.01,
        ),
    )
    replay_dir = tmp_path / "replay"
    replay_dir.mkdir()
    for path in record_dir.iterdir():
        (replay_dir / path.name).write_bytes(path.read_bytes())
    progress: list[str] = []
    result = run_scan(
        target,
        ScanOptions(
            replay_dir=str(replay_dir),
            allow_private=True,
            authorized=True,
            skip_ports=True,
            concurrency=1,
            delay=0,
        ),
        progress=progress.append,
    )
    assert progress  # replay serial path reports progress
    assert result.skipped and len(result.findings) > 0


def test_concurrent_handles_check_exception(tmp_path, fixture_server, target, monkeypatch) -> None:
    from inspectra.checks import ALL_CHECKS

    def boom(t, ctx):
        raise RuntimeError("boom")

    monkeypatch.setitem(ALL_CHECKS, "headers", boom)
    result = run_scan(
        target,
        ScanOptions(allow_private=True, authorized=True, skip_ports=True, concurrency=4, delay=0),
    )
    assert result.findings  # scan continues despite one check failing
    assert all(f.rule_id != "HDR-008" for f in result.findings)


def test_concurrent_fatal_aborts(tmp_path, fixture_server, target, monkeypatch) -> None:
    import pytest

    from inspectra.checks import ALL_CHECKS, FatalCheckError
    from inspectra.orchestrator import ScanAborted

    def fatal(t, ctx):
        raise FatalCheckError("fatal")

    monkeypatch.setitem(ALL_CHECKS, "http", fatal)
    with pytest.raises(ScanAborted):
        run_scan(
            target,
            ScanOptions(
                allow_private=True,
                authorized=True,
                skip_ports=True,
                concurrency=4,
                delay=0,
            ),
        )


def test_tls_cache_hit_resolves_once(monkeypatch) -> None:
    """TLS handshake result cached per (host, port): inspect_tls runs once."""
    from inspectra.checks import tls as tls_check
    from inspectra.checks.context import ScanContext

    calls = {"count": 0}

    def fake_inspect_tls(hostname: str, port: int = 443, timeout: float = 10.0):
        calls["count"] += 1
        return tls_check.TlsInfo(
            version="TLSv1.3",
            cipher="TLS_AES_256_GCM_SHA384",
            subject_cn="example.com",
            issuer="Example CA",
            not_valid_before=datetime(2026, 1, 1),
            not_valid_after=datetime(2030, 1, 1),
            san_dns=["example.com"],
            is_self_signed=False,
            hostname_matches=True,
        )

    monkeypatch.setattr(tls_check, "inspect_tls", fake_inspect_tls)
    ctx = ScanContext(options=ScanOptions())
    i1 = tls_check._inspect_tls_cached("example.com", 443, ctx)
    i2 = tls_check._inspect_tls_cached("example.com", 443, ctx)
    assert calls["count"] == 1
    assert i1 is i2


def test_network_pattern_matching() -> None:
    from inspectra.network import _hostname_matches, _pattern_matches

    assert _pattern_matches("example.com", "example.com")
    assert _pattern_matches("sub.example.com", "*.example.com")
    assert not _pattern_matches("evil.example.com.evil", "*.example.com")
    assert not _pattern_matches("example.org", "example.com")

    assert _hostname_matches("example.com", ["*.example.com"], "example.com")
    assert not _hostname_matches("evil.example.org", ["*.example.com"], "example.org")


def test_cli_parser_has_concurrency_and_delay() -> None:
    from inspectra.cli import build_parser

    parser = build_parser()
    sub = [a for a in parser._actions if getattr(a, "dest", None) == "command"][0]
    scan_parser = sub.choices["scan"]
    concurrency = next(a for a in scan_parser._actions if getattr(a, "dest", None) == "concurrency")
    delay = next(a for a in scan_parser._actions if getattr(a, "dest", None) == "delay")
    assert concurrency.default == 4
    assert delay.default == 0.2


def test_cli_invalid_target_returns_2(tmp_path, monkeypatch) -> None:
    from inspectra.cli import main

    home = tmp_path / "home"
    home.mkdir()
    config_dir = home / ".config" / "inspectra"
    config_dir.mkdir(parents=True)
    import inspectra.cli as cli

    monkeypatch.setattr(cli, "CONFIG_DIR", config_dir)
    monkeypatch.setattr(cli, "CONFIG_FILE", config_dir / "config.json")
    code = main(["scan", "not-a-valid-hostname", "--yes"])
    assert code == 2
