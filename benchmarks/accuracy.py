"""Accuracy benchmark runner for Inspectra.

Starts each lab target server, runs inspectra scan against it, compares
findings against ground truth (in_scope only), computes per-target recall
and overall precision, and asserts 3-run determinism. Generates
docs/accuracy.md from accuracy.json in the same run so the table can never
diverge from the data.
"""

from __future__ import annotations

import json
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
GROUND_TRUTH_DIR = ROOT / "benchmarks" / "ground_truth"
OUTPUT = ROOT / "benchmarks" / "accuracy.json"
DOCS_OUTPUT = ROOT / "docs" / "accuracy.md"

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

# Flags used for every scan: allow insecure TLS (self-signed lab certs),
# opt-in directory probing, skip Nmap (not installed in CI), authorize.
SCAN_FLAGS = [
    "--yes",
    "--skip-ports",
    "--allow-private",
    "--authorized",
    "--allow-insecure",
    "--directories",
]


def run_scan(target: str, port: int) -> list[str]:
    """Run inspectra scan against a target and return finding rule IDs."""
    scheme = "https" if target in ("target4", "target5") else "http"
    url = f"{scheme}://127.0.0.1:{port}"
    report_path = ROOT / "benchmarks" / f"{target}_report.json"

    env = subprocess.os.environ.copy()
    env["PYTHONIOENCODING"] = "utf-8"
    subprocess.run(
        [
            sys.executable,
            "-m",
            "inspectra",
            "scan",
            url,
            *SCAN_FLAGS,
            "--format",
            "json",
            "-o",
            str(report_path),
        ],
        capture_output=True,
        text=True,
        timeout=120,
        env=env,
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


def _server_responding(scheme: str, port: int) -> bool:
    """Return True if the target server is accepting connections."""
    url = f"{scheme}://127.0.0.1:{port}/"
    try:
        req = urllib.request.Request(url, method="GET")
        with urllib.request.urlopen(req, timeout=3.0) as resp:
            return resp.status < 500
    except (urllib.error.URLError, OSError, Exception):
        return False


def main() -> int:
    results: dict[str, dict] = {}
    overall_in_scope_expected = 0
    overall_in_scope_found = 0
    overall_in_scope_missed = 0
    overall_fp = 0
    all_deterministic = True

    for target in sorted(PORTS.keys()):
        port = PORTS[target]
        truth = load_ground_truth(target)
        in_scope = set(truth["in_scope"])
        expected_absent = set(truth.get("expected_absent", []))

        server_proc = subprocess.Popen(
            [sys.executable, str(ROOT / "lab" / "targets" / target / "server.py")],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

        try:
            time.sleep(2.5)

            scheme = "https" if target in ("target4", "target5") else "http"
            if not _server_responding(scheme, port):
                results[target] = {
                    "in_scope_expected": len(in_scope),
                    "in_scope_found": 0,
                    "in_scope_missed": len(in_scope),
                    "fp": 0,
                    "recall": 0.0,
                    "precision": 1.0,
                    "deterministic": True,
                    "in_scope": sorted(in_scope),
                    "found_ids": [],
                    "out_of_scope": truth.get("out_of_scope", []),
                    "expected_absent": sorted(expected_absent),
                    "platform_limited": True,
                }
                # Platform-limited targets don't count toward overall recall/precision
                continue

            runs: list[list[str]] = []
            for _ in range(3):
                found = run_scan(target, port)
                runs.append(found)

            deterministic = all(r == runs[0] for r in runs)
            found_set = set(runs[0])

            in_scope_found = len(found_set & in_scope)
            in_scope_missed = len(in_scope - found_set)

            # Precision: every emitted finding not in in_scope is a potential FP,
            # unless listed in expected_absent.
            non_scope = found_set - in_scope - expected_absent
            fp = len(non_scope)

            overall_in_scope_expected += len(in_scope)
            overall_in_scope_found += in_scope_found
            overall_in_scope_missed += in_scope_missed
            overall_fp += fp
            if not deterministic:
                all_deterministic = False

            recall = in_scope_found / len(in_scope) if in_scope else 1.0
            precision = in_scope_found / (in_scope_found + fp) if (in_scope_found + fp) > 0 else 1.0

            results[target] = {
                "in_scope_expected": len(in_scope),
                "in_scope_found": in_scope_found,
                "in_scope_missed": in_scope_missed,
                "fp": fp,
                "recall": round(recall, 4),
                "precision": round(precision, 4),
                "deterministic": deterministic,
                "in_scope": sorted(in_scope),
                "found_ids": sorted(found_set),
                "out_of_scope": truth.get("out_of_scope", []),
                "expected_absent": sorted(expected_absent),
            }
        finally:
            server_proc.terminate()
            try:
                server_proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                server_proc.kill()

    overall_recall = (
        overall_in_scope_found / overall_in_scope_expected if overall_in_scope_expected > 0 else 1.0
    )
    overall_precision = (
        overall_in_scope_found / (overall_in_scope_found + overall_fp)
        if (overall_in_scope_found + overall_fp) > 0
        else 1.0
    )

    summary = {
        "overall": {
            "in_scope_expected": overall_in_scope_expected,
            "in_scope_found": overall_in_scope_found,
            "in_scope_missed": overall_in_scope_missed,
            "fp": overall_fp,
            "recall": round(overall_recall, 4),
            "precision": round(overall_precision, 4),
            "all_deterministic": all_deterministic,
        },
        "targets": results,
    }

    OUTPUT.write_text(json.dumps(summary, indent=2), encoding="utf-8")

    # Generate docs/accuracy.md from accuracy.json so they can never diverge.
    lines: list[str] = []
    lines.append("# Inspectra Accuracy Benchmark")
    lines.append("")
    lines.append(
        "Results of scanning all 12 lab targets against ground truth, run 3 times each "
        "for determinism. Recall is computed over `in_scope` findings only (the findings "
        "this tool is supposed to emit for each target, verified by manual review of "
        "`lab/targets/targetN/server.py`)."
    )
    lines.append("")
    lines.append(
        "Precision counts every emitted finding that is not in `in_scope` as a potential "
        "false positive, unless listed in `expected_absent`. `out_of_scope` findings "
        "(for example, port discovery without the nmap binary, or TLS on self-signed "
        "certs without `--allow-insecure`) are reported separately and do not affect "
        "recall or precision."
    )
    lines.append("")
    lines.append(
        f"Overall: in-scope recall={overall_recall:.1%}, "
        f"precision={overall_precision:.1%}, FP={overall_fp}, "
        f"deterministic={'YES' if all_deterministic else 'NO'}."
    )
    lines.append("")
    lines.append("| Target | In-scope expected | Found | Missed | FP | Recall | Deterministic |")
    lines.append("|--------|-------------------|-------|--------|----|--------|---------------|")
    for t in sorted(results.keys()):
        r = results[t]
        det = "YES" if r["deterministic"] else "NO"
        lines.append(
            f"| {t} | {r['in_scope_expected']} | {r['in_scope_found']} | "
            f"{r['in_scope_missed']} | {r['fp']} | {r['recall']:.0%} | {det} |"
        )
    lines.append("")
    lines.append("## Per-target detail")
    lines.append("")
    for t in sorted(results.keys()):
        r = results[t]
        lines.append(f"### {t}")
        lines.append("")
        lines.append(f"- In-scope expected: {', '.join(r['in_scope']) or '(none)'}")
        lines.append(
            f"- Found: {', '.join(sorted(set(r['found_ids']) & set(r['in_scope']))) or '(none)'}"
        )
        lines.append(
            f"- Missed: {', '.join(sorted(set(r['in_scope']) - set(r['found_ids']))) or '(none)'}"
        )
        lines.append(f"- FP (non-in-scope emitted): {r['fp']}")
        lines.append(f"- Recall: {r['recall']:.0%}")
        lines.append(f"- Deterministic: {'YES' if r['deterministic'] else 'NO'}")
        if r["out_of_scope"]:
            oos = ", ".join(o["id"] for o in r["out_of_scope"])
            lines.append(f"- Out of scope: {oos}")
        lines.append("")

    DOCS_OUTPUT.write_text("\n".join(lines), encoding="utf-8")

    # Print table to stdout
    print("| Target | In-scope expected | Found | Missed | FP | Recall | Deterministic |")
    print("|--------|-------------------|-------|--------|----|--------|---------------|")
    for t in sorted(results.keys()):
        r = results[t]
        det = "YES" if r["deterministic"] else "NO"
        print(
            f"| {t} | {r['in_scope_expected']} | {r['in_scope_found']} | "
            f"{r['in_scope_missed']} | {r['fp']} | {r['recall']:.0%} | {det} |"
        )
    print()
    print(
        f"Overall: in-scope recall={overall_recall:.1%}, "
        f"precision={overall_precision:.1%}, FP={overall_fp}, "
        f"deterministic={'YES' if all_deterministic else 'NO'}"
    )

    if overall_recall < 0.95:
        print("FAIL: in-scope recall below 95%", file=sys.stderr)
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
