"""Accuracy benchmark runner for Inspectra.

Starts each lab target server, runs inspectra scan against it, compares
findings against ground truth (in_scope only), computes per-target recall
and overall precision, and asserts 3-run determinism. Generates
docs/accuracy.md from accuracy.json in the same run so the table can never
diverge from the data.

Every target with a ground-truth file counts toward the overall recall and
precision. A target may be excluded only by deleting its json file and
listing it under "Not measured" in docs/accuracy.md.
"""

from __future__ import annotations

import argparse
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

MAX_EXPECTED_ABSENT = 3

NOT_MEASURED_FILE = ROOT / "benchmarks" / "not_measured.json"


def load_not_measured() -> dict[str, str]:
    """Load not-measured targets and their reasons from source of truth."""
    if NOT_MEASURED_FILE.exists():
        return json.loads(NOT_MEASURED_FILE.read_text(encoding="utf-8"))
    return {}


def validate_targets_not_measured(not_measured: dict[str, str]) -> None:
    """Ensure only allowed targets are marked as not measured."""
    allowed = {"target4", "target5", "target7", "target8"}
    actual = set(not_measured.keys())
    disallowed = actual - allowed
    if disallowed:
        raise SystemExit(
            f"Benchmark error: targets {sorted(disallowed)} are marked as not measured "
            f"but only {sorted(allowed)} are permitted in not_measured.json."
        )


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

# Targets that need --directories (directory observation check).
DIRECTORY_TARGETS = {"target7", "target8"}

# Base flags: no --directories (too slow, noisy on simple servers).
BASE_FLAGS = [
    "--yes",
    "--skip-ports",
    "--allow-private",
    "--authorized",
    "--allow-insecure",
    "--delay",
    "0",
]


def run_scan(target: str, port: int, use_directories: bool = False) -> list[str]:
    """Run inspectra scan against a target and return finding rule IDs."""
    scheme = "https" if target in ("target4", "target5") else "http"
    url = f"{scheme}://127.0.0.1:{port}"
    report_path = ROOT / "benchmarks" / f"{target}_report.json"

    flags = list(BASE_FLAGS)
    if use_directories:
        flags.append("--directories")

    env = subprocess.os.environ.copy()
    env["PYTHONIOENCODING"] = "utf-8"
    subprocess.run(
        [
            sys.executable,
            "-m",
            "inspectra",
            "scan",
            url,
            *flags,
            "--format",
            "json",
            "-o",
            str(report_path),
        ],
        capture_output=True,
        encoding="utf-8",
        errors="replace",
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
        if scheme == "https":
            import ssl as _ssl

            ctx = _ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = _ssl.CERT_NONE
            with urllib.request.urlopen(req, timeout=3.0, context=ctx) as resp:
                return resp.status < 500
        with urllib.request.urlopen(req, timeout=3.0) as resp:
            return resp.status < 500
    except (urllib.error.URLError, OSError, Exception):
        return False


def _normalize_expected_absent(truth: dict) -> list[dict]:
    """Return expected_absent entries, each with id and reason, capped at 3."""
    absent = truth.get("expected_absent", [])
    normalized: list[dict] = []
    for entry in absent:
        if isinstance(entry, str):
            normalized.append({"id": entry, "reason": "expected absent"})
        elif isinstance(entry, dict):
            normalized.append({"id": entry.get("id", ""), "reason": entry.get("reason", "")})
    return normalized[:MAX_EXPECTED_ABSENT]


def main() -> int:
    parser = argparse.ArgumentParser(description="Inspectra accuracy benchmark")
    parser.add_argument(
        "--all",
        action="store_true",
        help="Run all targets and print verbose breakdown.",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Print per-target and overall breakdown.",
    )
    parser.add_argument(
        "--min-in-scope-recall",
        type=float,
        default=0.95,
        help="Minimum in-scope recall to pass (default: 0.95).",
    )
    args = parser.parse_args()

    results: dict[str, dict] = {}
    overall_in_scope_expected = 0
    overall_in_scope_found = 0
    overall_in_scope_missed = 0
    overall_emitted = 0
    overall_justified_absent = 0
    overall_unexplained = 0
    all_deterministic = True

    not_measured = load_not_measured()
    validate_targets_not_measured(not_measured)

    for gt_file in sorted(GROUND_TRUTH_DIR.glob("*.json")):
        target = gt_file.stem
        port = PORTS[target]
        truth = load_ground_truth(target)
        in_scope = set(truth["in_scope"])
        expected_absent = _normalize_expected_absent(truth)
        absent_ids = {e["id"] for e in expected_absent}
        use_dirs = target in DIRECTORY_TARGETS

        # Skip targets explicitly listed as not measured
        if target in not_measured:
            results[target] = {
                "in_scope_expected": len(in_scope),
                "in_scope_found": 0,
                "in_scope_missed": len(in_scope),
                "emitted_total": 0,
                "justified_absent": 0,
                "unexplained": 0,
                "fp": 0,
                "recall": 0.0,
                "precision": 1.0,
                "deterministic": True,
                "in_scope": sorted(in_scope),
                "found_ids": [],
                "out_of_scope": truth.get("out_of_scope", []),
                "expected_absent": expected_absent,
                "server_responding": False,
                "not_measured": True,
            }
            continue

        # Measured target: must start and scan successfully, otherwise FAIL
        server_proc = subprocess.Popen(
            [sys.executable, str(ROOT / "lab" / "targets" / target / "server.py")],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

        try:
            time.sleep(1.5)

            scheme = "https" if target in ("target4", "target5") else "http"
            if not _server_responding(scheme, port):
                server_proc.terminate()
                try:
                    server_proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    server_proc.kill()
                raise SystemExit(
                    f"Benchmark error: measured target {target} did not respond on "
                    f"port {port}. If this target cannot run on this platform, add "
                    f"it to benchmarks/not_measured.json."
                )

            runs: list[list[str]] = []
            for _ in range(3):
                found = run_scan(target, port, use_dirs)
                runs.append(found)

            deterministic = all(r == runs[0] for r in runs)
            found_set = set(runs[0])
            emitted_total = len(found_set)

            in_scope_found = len(found_set & in_scope)
            in_scope_missed = len(in_scope - found_set)

            justified = found_set & absent_ids
            unexplained = found_set - in_scope - absent_ids
            fp = len(unexplained)

            overall_in_scope_expected += len(in_scope)
            overall_in_scope_found += in_scope_found
            overall_in_scope_missed += in_scope_missed
            overall_emitted += emitted_total
            overall_justified_absent += len(justified)
            overall_unexplained += fp
            if not deterministic:
                all_deterministic = False

            recall = in_scope_found / len(in_scope) if in_scope else 1.0
            precision = in_scope_found / (in_scope_found + fp) if (in_scope_found + fp) > 0 else 1.0

            results[target] = {
                "in_scope_expected": len(in_scope),
                "in_scope_found": in_scope_found,
                "in_scope_missed": in_scope_missed,
                "emitted_total": emitted_total,
                "justified_absent": len(justified),
                "unexplained": fp,
                "fp": fp,
                "recall": round(recall, 4),
                "precision": round(precision, 4),
                "deterministic": deterministic,
                "in_scope": sorted(in_scope),
                "found_ids": sorted(found_set),
                "out_of_scope": truth.get("out_of_scope", []),
                "expected_absent": expected_absent,
                "server_responding": True,
                "not_measured": False,
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
        overall_in_scope_found / (overall_in_scope_found + overall_unexplained)
        if (overall_in_scope_found + overall_unexplained) > 0
        else 1.0
    )

    summary = {
        "overall": {
            "in_scope_expected": overall_in_scope_expected,
            "in_scope_found": overall_in_scope_found,
            "in_scope_missed": overall_in_scope_missed,
            "emitted_total": overall_emitted,
            "justified_absent": overall_justified_absent,
            "unexplained": overall_unexplained,
            "fp": overall_unexplained,
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
        "Results of scanning all lab targets with ground-truth files, run 3 times each "
        "for determinism. Recall is computed over `in_scope` findings only (the findings "
        "this tool is supposed to emit for each target, verified by manual review of "
        "`lab/targets/targetN/server.py`). Every target with a ground-truth file counts "
        "toward the overall recall and precision."
    )
    lines.append("")
    lines.append(
        "Precision counts every emitted finding that is not in `in_scope` as a potential "
        "false positive, unless listed in `expected_absent` with a reason. "
        "`out_of_scope` findings are reported separately and do not affect recall or "
        "precision."
    )
    lines.append("")
    lines.append(
        f"Overall: in-scope recall={overall_recall:.1%} "
        f"({overall_in_scope_found}/{overall_in_scope_expected}), "
        f"precision={overall_precision:.1%}, "
        f"emitted={overall_emitted}, justified_absent={overall_justified_absent}, "
        f"unexplained(FP)={overall_unexplained}, "
        f"deterministic={'YES' if all_deterministic else 'NO'}."
    )
    lines.append("")
    lines.append(
        "| Target | In-scope expected | Found | Missed | Emitted |"
        " Justified | Unexplained | FP | Recall | Deterministic |"
    )
    lines.append(
        "|--------|-------------------|-------|--------|---------|-----------|-------------|----|--------|---------------|"
    )
    for t in sorted(results.keys()):
        r = results[t]
        det = "YES" if r["deterministic"] else "NO"
        nm = " (not measured)" if r.get("not_measured") else ""
        lines.append(
            f"| {t}{nm} | {r['in_scope_expected']} | {r['in_scope_found']} | "
            f"{r['in_scope_missed']} | {r['emitted_total']} | {r['justified_absent']} | "
            f"{r['unexplained']} | {r['fp']} | {r['recall']:.0%} | {det} |"
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
        lines.append(f"- Emitted total: {r['emitted_total']}")
        lines.append(f"- Justified absent: {r['justified_absent']}")
        lines.append(f"- Unexplained (FP): {r['unexplained']}")
        lines.append(f"- Recall: {r['recall']:.0%}")
        lines.append(f"- Deterministic: {'YES' if r['deterministic'] else 'NO'}")
        if r["out_of_scope"]:
            oos = ", ".join(o["id"] for o in r["out_of_scope"])
            lines.append(f"- Out of scope: {oos}")
        lines.append("")

    # Not measured section (from source of truth)
    not_measured = load_not_measured()
    if not_measured:
        lines.append("## Not measured")
        lines.append("")
        for t in sorted(not_measured.keys()):
            lines.append(f"- **{t}**: {not_measured[t]}")
        lines.append("")

    DOCS_OUTPUT.write_text("\n".join(lines), encoding="utf-8")

    # Print table to stdout
    print(
        "| Target | In-scope expected | Found | Missed | Emitted |"
        " Justified | Unexplained | FP | Recall | Deterministic |"
    )
    print(
        "|--------|-------------------|-------|--------|---------|-----------|-------------|----|--------|---------------|"
    )
    for t in sorted(results.keys()):
        r = results[t]
        det = "YES" if r["deterministic"] else "NO"
        nm = " (not measured)" if r.get("not_measured") else ""
        print(
            f"| {t}{nm} | {r['in_scope_expected']} | {r['in_scope_found']} | "
            f"{r['in_scope_missed']} | {r['emitted_total']} | {r['justified_absent']} | "
            f"{r['unexplained']} | {r['fp']} | {r['recall']:.0%} | {det} |"
        )
    print()
    print(
        f"Overall: in-scope recall={overall_recall:.1%} "
        f"({overall_in_scope_found}/{overall_in_scope_expected}), "
        f"precision={overall_precision:.1%}, "
        f"emitted={overall_emitted}, justified_absent={overall_justified_absent}, "
        f"unexplained(FP)={overall_unexplained}, "
        f"deterministic={'YES' if all_deterministic else 'NO'}"
    )

    if overall_recall < args.min_in_scope_recall:
        print(
            f"FAIL: in-scope recall {overall_recall:.1%} below {args.min_in_scope_recall:.0%}",
            file=sys.stderr,
        )
        return 1
    if overall_unexplained > 2:
        print("FAIL: unexplained findings above 2", file=sys.stderr)
        return 1
    if not all_deterministic:
        print("FAIL: not all targets deterministic", file=sys.stderr)
        return 1

    print("PASS: accuracy gate met")
    return 0


if __name__ == "__main__":
    sys.exit(main())
