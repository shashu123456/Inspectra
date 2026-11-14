#!/usr/bin/env python3
"""Run benchmark scans against all targets sequentially."""
import subprocess
import json
import time
from pathlib import Path

RESULTS_DIR = Path("lab/results")
RESULTS_DIR.mkdir(parents=True, exist_ok=True)

targets = {
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

results = {}

for name, port in targets.items():
    url = f"http://127.0.0.1:{port}/"
    print(f"\nScanning {name} on port {port}...")
    
    try:
        proc = subprocess.run(
            [
                ".venv\\Scripts\\python.exe", "-m", "inspectra",
                "scan", url,
                "--yes", "--skip-ports",
                "--allow-private", "--authorized",
                "--format", "json",
                "-o", str(RESULTS_DIR / f"{name}.json")
            ],
            capture_output=True, text=True, timeout=60
        )
        
        if proc.returncode == 0:
            try:
                data = json.loads((RESULTS_DIR / f"{name}.json").read_text())
                findings = data.get("findings", [])
                rule_ids = [f.get("rule_id", "?") for f in findings]
                posture = data.get("posture_score", "N/A")
                grade = data.get("grade", "N/A")
                print(f"  {name}: {len(findings)} findings, score={posture}, grade={grade}")
                print(f"    Rules: {rule_ids}")
                results[name] = {
                    "port": port,
                    "status": "success",
                    "posture_score": data.get("posture_score"),
                    "grade": data.get("grade"),
                    "findings_count": len(findings),
                    "rule_ids": rule_ids,
                }
            except Exception as e:
                print(f"  {name}: JSON parse error: {e}")
                results[name] = {
                    "port": port,
                    "status": "parse_error",
                    "error": str(e),
                    "findings_count": 0,
                    "rule_ids": [],
                }
        else:
            print(f"  {name}: Exit code {proc.returncode}")
            print(f"  stderr: {(proc.stderr or '')[:200]}")
            results[name] = {
                "port": port,
                "status": "error",
                "exit_code": proc.returncode,
                "error": proc.stderr[:500] if proc.stderr else "N/A",
                "findings_count": 0,
                "rule_ids": [],
            }
    except Exception as e:
        print(f"  {name}: Exception {e}")
        results[name] = {
            "port": port,
            "status": "exception",
            "error": str(e),
            "findings_count": 0,
            "rule_ids": [],
        }

print("\n" + "=" * 60)
print("BENCHMARK RESULTS SUMMARY")
print("=" * 60)

total_expected = 0
total_detected = 0
total_missed = 0
total_fp = 0
total_time = 0

for name, r in sorted(results.items()):
    if r["status"] == "success":
        print(f"  {name:10s}: score={r['posture_score']}, grade={r['grade']}, "
              f"findings={r['findings_count']}, rules={r['rule_ids']}")
    else:
        print(f"  {name:10s}: {r['status']} - {r.get('error', 'N/A')[:80]}")

# Write results
output = {
    "timestamp": __import__("datetime").datetime.now().isoformat(),
    "results": results,
}
RESULTS_DIR.joinpath("benchmark_results.json").write_text(json.dumps(output, indent=2))
print(f"\nResults saved to lab/results/benchmark_results.json")