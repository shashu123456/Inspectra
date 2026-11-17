"""Accuracy benchmark runner for Inspectra.

Starts each lab target server, runs inspectra scan against it, compares
findings against ground truth, computes recall/precision, and asserts
3-run determinism.
"""

from __future__ import annotations

import json
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
GROUND_TRUTH_DIR = ROOT / "benchmarks" / "ground_truth"
OUTPUT = ROOT / "benchmarks" / "accuracy.json"

PORTS = {
    "target1": 8001,
    "target2": 8002,
    "target3": 8003,
    "target4": 8004,
    "target5": 8005,
    "target6": 8006,
    "target7": 8007,
    "target8": 8008,
    "target9": 8009,
    "target10": 8010,
    "target11": 8011,
    "target12": 8012,
}


def run_scan(target: str, port: int) -> list[str]:
    """Run inspectra scan against a target and return finding rule IDs."""
    scheme = "https" if target in ("target4", "target5") else "http"
    url = f"{scheme}://127.0.0.1:{port}"
    report_path = ROOT / "benchmarks" / f"{target}_report.json"

    subprocess.run(
        [
            "inspectra",
            "scan",
            url,
            "--yes",
            "--skip-ports",
            "--allow-private",
            "--authorized",
            "--format",
            "json",
            "-o",
            str(report_path),
        ],
        capture_output=True,
        text=True,
        timeout=120,
    )

    if not report_path.exists():
        return []
    try:
        data = json.loads(report_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return []
    return [f["rule_id"] for f in data.get("findings", [])]


def load_ground_truth(target: str) -> dict:
    path = GROUND_TRUTH_DIR / f"{target}.json"
    return json.loads(path.read_text(encoding="utf-8"))


def main() -> int:
    results: dict[str, dict] = {}
    overall_expected = 0
    overall_found = 0
    overall_missed = 0
    overall_fp = 0
    all_deterministic = True

    for target in sorted(PORTS.keys()):
        port = PORTS[target]
        truth = load_ground_truth(target)
        expected_set = set(truth["expected"])
        known_absent = set(truth.get("known_absent", []))

        server_proc = subprocess.Popen(
            [sys.executable, str(ROOT / "lab" / "targets" / target / "server.py")],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

        try:
            time.sleep(1.5)

            runs: list[list[str]] = []
            for _ in range(3):
                found = run_scan(target, port)
                runs.append(found)

            deterministic = all(r == runs[0] for r in runs)
            found_set = set(runs[0])

            planted = len(expected_set)
            found_count = len(found_set & expected_set)
            missed = len(expected_set - found_set)
            fp = len(found_set & known_absent)

            overall_expected += planted
            overall_found += found_count
            overall_missed += missed
            overall_fp += fp
            if not deterministic:
                all_deterministic = False

            recall = found_count / planted if planted > 0 else 1.0
            precision = found_count / (found_count + fp) if (found_count + fp) > 0 else 1.0

            results[target] = {
                "planted": planted,
                "found": found_count,
                "missed": missed,
                "fp": fp,
                "recall": round(recall, 4),
                "precision": round(precision, 4),
                "deterministic": deterministic,
                "expected": sorted(expected_set),
                "found_ids": sorted(found_set),
            }
        finally:
            server_proc.terminate()
            try:
                server_proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                server_proc.kill()

    overall_recall = overall_found / overall_expected if overall_expected > 0 else 1.0
    overall_precision = (
        overall_found / (overall_found + overall_fp) if (overall_found + overall_fp) > 0 else 1.0
    )

    summary = {
        "overall": {
            "planted": overall_expected,
            "found": overall_found,
            "missed": overall_missed,
            "fp": overall_fp,
            "recall": round(overall_recall, 4),
            "precision": round(overall_precision, 4),
            "all_deterministic": all_deterministic,
        },
        "targets": results,
    }

    OUTPUT.write_text(json.dumps(summary, indent=2), encoding="utf-8")

    print("| Target | Planted | Found | Missed | FP | Recall | Deterministic |")
    print("|--------|---------|-------|--------|----|--------|---------------|")
    for t in sorted(results.keys()):
        r = results[t]
        det = "YES" if r["deterministic"] else "NO"
        print(
            f"| {t} | {r['planted']} | {r['found']} | {r['missed']} | {r['fp']} | "
            f"{r['recall']:.0%} | {det} |"
        )
    print()
    print(
        f"Overall: recall={overall_recall:.1%}, precision={overall_precision:.1%}, "
        f"FP={overall_fp}, deterministic={all_deterministic}"
    )

    if overall_recall < 0.95:
        print("FAIL: recall below 95%", file=sys.stderr)
        return 1
    if overall_fp > 2:
        print("FAIL: false positives above 2", file=sys.stderr)
        return 1
    if not all_deterministic:
        print("FAIL: not all targets deterministic", file=sys.stderr)
        return 1

    print("PASS: accuracy gate met")
    return 0


if __name__ == "__main__":
    sys.exit(main())
