#!/usr/bin/env python3
"""Benchmark script: runs Inspectra scan against each lab target and compares
results to expected.json. Produces a markdown report and per-target JSON results."""

from __future__ import annotations

import json
import subprocess
import time
from datetime import datetime
from pathlib import Path

LAB_DIR = Path(__file__).resolve().parent.parent / "lab"
EXPECTED_FILE = LAB_DIR / "expected.json"
RESULTS_DIR = LAB_DIR / "results"
DOCKER_COMPOSE = LAB_DIR / "docker-compose.yml"

EXPECTED: dict = json.loads(EXPECTED_FILE.read_text())


def run_command(cmd: list[str], timeout: int = 120) -> tuple[int, str, str]:
    """Run a command and return (returncode, stdout, stderr)."""
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    return proc.returncode, proc.stdout, proc.stderr


def start_docker_compose() -> None:
    """Start the docker-compose services."""
    print("Starting docker-compose services...")
    rc, out, err = run_command(
        ["docker-compose", "-f", str(DOCKER_COMPOSE), "up", "-d"], timeout=120
    )
    if rc != 0:
        print(f"WARNING: docker-compose up failed: {err}")
    print("Waiting for services to be ready...")
    time.sleep(10)


def stop_docker_compose() -> None:
    """Stop the docker-compose services."""
    print("Stopping docker-compose services...")
    run_command(["docker-compose", "-f", str(DOCKER_COMPOSE), "down"], timeout=60)


def scan_target(target_name: str, port: int) -> dict:
    """Run `inspectra scan` against a single target and return parsed JSON."""
    target_url = f"http://localhost:{port}/"
    output_file = RESULTS_DIR / f"{target_name}.json"

    cmd = [
        "inspectra",
        "scan",
        target_url,
        "--yes",
        "--skip-ports",
        "--format",
        "json",
        "-o",
        str(output_file),
    ]

    start = time.time()
    rc, out, err = run_command(cmd, timeout=120)
    elapsed_ms = (time.time() - start) * 1000

    if rc != 0:
        return {
            "target": target_name,
            "port": port,
            "exit_code": rc,
            "error": err or out,
            "elapsed_ms": elapsed_ms,
            "findings": [],
        }

    try:
        data = json.loads(output_file.read_text())
        findings = data.get("findings", [])
    except (json.JSONDecodeError, FileNotFoundError) as exc:
        return {
            "target": target_name,
            "port": port,
            "exit_code": rc,
            "error": str(exc),
            "elapsed_ms": elapsed_ms,
            "findings": [],
        }

    return {
        "target": target_name,
        "port": port,
        "exit_code": rc,
        "error": None,
        "elapsed_ms": elapsed_ms,
        "findings": findings,
    }


def compare_findings(
    expected_ids: list[str], detected_findings: list[dict]
) -> tuple[int, int, int, list[str]]:
    """Compare expected findings to detected findings.

    Returns: (expected_count, detected_count, missed_count, false_positives)
    """
    detected_ids = {f.get("rule_id", "") for f in detected_findings}
    expected_set = set(expected_ids)

    detected_count = len(expected_set & detected_ids)
    missed_count = len(expected_set - detected_ids)
    false_positives = sorted(detected_ids - expected_set)

    return len(expected_set), detected_count, missed_count, false_positives


def generate_markdown(results: list[dict]) -> str:
    """Generate markdown benchmark report."""
    lines = []
    lines.append("# Benchmark Results")
    lines.append("")
    lines.append(f"Generated: {datetime.now().isoformat()}")
    lines.append("")
    lines.append("| Target | Expected | Detected | Missed | False Positives | Runtime (ms) |")
    lines.append("|--------|----------|----------|--------|-----------------|--------------|")

    total_expected = 0
    total_detected = 0
    total_missed = 0
    total_fp = 0
    total_time = 0

    for r in results:
        total_expected += r["expected_count"]
        total_detected += r["detected_count"]
        total_missed += r["missed_count"]
        total_fp += len(r["false_positives"])
        total_time += r["elapsed_ms"]

        fp_str = ", ".join(r["false_positives"]) if r["false_positives"] else "-"
        lines.append(
            f"| {r['target']} | {r['expected_count']} | {r['detected_count']} | "
            f"{r['missed_count']} | {fp_str} | {r['elapsed_ms']:.0f} |"
        )

    lines.append("")
    total_line = (
        f"| **Total** | **{total_expected}** | **{total_detected}** | "
        f"**{total_missed}** | **{total_fp}** | **{total_time:.0f}** |"
    )
    lines.append(total_line)
    lines.append("")
    lines.append("## Detection Rate")
    if total_expected > 0:
        rate = (total_detected / total_expected) * 100
        lines.append(f"- Overall detection rate: {rate:.1f}%")
    else:
        rate = 0.0
        lines.append("- Overall detection rate: N/A (no expected findings)")

    detection_rate_ok = rate >= 85.0 if total_expected > 0 else False
    fp_ok = total_fp <= 2
    p95_ok = True  # Will be calculated below

    # Calculate p95 runtime
    elapsed_times = sorted([r["elapsed_ms"] for r in results if r["elapsed_ms"] > 0])
    if elapsed_times:
        p95_index = int(len(elapsed_times) * 0.95) - 1
        p95_index = max(0, min(p95_index, len(elapsed_times) - 1))
        p95_time = elapsed_times[p95_index]
        p95_ok = p95_time < 15000  # 15 seconds
    else:
        p95_time = 0
        p95_ok = False

    p95_line = (
        f"- P95 runtime: {p95_time:.0f}ms (threshold: <15000ms) - {'PASS' if p95_ok else 'FAIL'}"
    )
    lines.append(p95_line)
    fp_line = f"- False positives: {total_fp} (threshold: <=2) - {'PASS' if fp_ok else 'FAIL'}"
    lines.append(fp_line)
    rate_line = (
        f"- Detection rate: {rate:.1f}% "
        f"(threshold: >=85%) - "
        f"{'PASS' if detection_rate_ok else 'FAIL'}"
    )
    lines.append(rate_line)

    all_pass = detection_rate_ok and fp_ok and p95_ok
    lines.append("")
    lines.append(f"## Overall: {'PASS' if all_pass else 'FAIL'}")

    return "\n".join(lines)


def main() -> None:
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)

    print("=== EcoMind Inspectra Benchmark ===")
    print()

    # Step 1: Start docker-compose
    start_docker_compose()

    try:
        # Step 2: Run scans against each target
        results = []
        for target_name, info in EXPECTED.items():
            port = info["port"]
            print(f"\nScanning {target_name} (port {port})...")
            result = scan_target(target_name, port)
            results.append(result)

            if result["error"]:
                print(f"  ERROR: {result['error']}")
            else:
                print(f"  Found {len(result['findings'])} findings in {result['elapsed_ms']:.0f}ms")

        # Step 3: Compare results to expected
        print("\n=== Comparison ===")
        for r in results:
            target_name = r["target"]
            expected_info = EXPECTED.get(target_name, {})
            expected_ids = expected_info.get("expected_findings", [])

            exp_count, det_count, missed_count, false_positives = compare_findings(
                expected_ids, r["findings"]
            )

            r["expected_count"] = exp_count
            r["detected_count"] = det_count
            r["missed_count"] = missed_count
            r["false_positives"] = false_positives

            status = "PASS" if missed_count == 0 and len(false_positives) == 0 else "FAIL"
            print(
                f"  {target_name}: expected={exp_count}, detected={det_count}, "
                f"missed={missed_count}, fp={false_positives} [{status}]"
            )

        # Step 4: Generate markdown report
        md = generate_markdown(results)
        report_path = LAB_DIR / "docs" / "benchmark.md"
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text(md)
        print(f"\nReport written to {report_path}")

        # Step 5: Save raw results
        results_path = RESULTS_DIR / "benchmark_results.json"
        raw_results = {
            "timestamp": datetime.now().isoformat(),
            "results": results,
        }
        results_path.write_text(json.dumps(raw_results, indent=2))
        print(f"Raw results written to {results_path}")

        # Step 6: Print summary
        print("\n=== Benchmark Summary ===")
        print(md)

    finally:
        # Step 7: Stop docker-compose
        stop_docker_compose()


if __name__ == "__main__":
    main()
