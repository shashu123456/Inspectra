"""Tests for benchmark specification.

Validates that expected.json covers at least 12 targets and that every
expected rule id exists in the rule registry. No docker required for CI.
"""

import json
import re
from pathlib import Path

LAB_DIR = Path(__file__).resolve().parent.parent / "lab"
EXPECTED_FILE = LAB_DIR / "expected.json"
DOCKER_COMPOSE_FILE = LAB_DIR / "docker-compose.yml"


def test_expected_json_exists() -> None:
    """expected.json must exist."""
    assert EXPECTED_FILE.exists(), f"expected.json not found at {EXPECTED_FILE}"


def test_expected_json_has_at_least_12_targets() -> None:
    """expected.json must cover at least 12 targets."""
    data = json.loads(EXPECTED_FILE.read_text())
    assert len(data) >= 12, f"Expected at least 12 targets, found {len(data)}"


def test_expected_json_has_expected_findings() -> None:
    """Every target in expected.json must have expected_findings."""
    data = json.loads(EXPECTED_FILE.read_text())
    for target_name, info in data.items():
        assert "expected_findings" in info, f"Target {target_name} missing 'expected_findings'"
        assert len(info["expected_findings"]) > 0, (
            f"Target {target_name} has empty expected_findings"
        )


def test_expected_findings_are_valid_rule_ids() -> None:
    """Every expected finding ID must match the pattern XXX-NNN."""
    rule_id_pattern = re.compile(r"^[A-Z]{2,4}-\d{3}$")
    data = json.loads(EXPECTED_FILE.read_text())
    for target_name, info in data.items():
        for finding_id in info["expected_findings"]:
            assert rule_id_pattern.match(finding_id), (
                f"Target {target_name}: invalid rule id '{finding_id}'"
            )


def test_docker_compose_exists() -> None:
    """docker-compose.yml must exist."""
    assert DOCKER_COMPOSE_FILE.exists(), f"docker-compose.yml not found at {DOCKER_COMPOSE_FILE}"


def test_docker_compose_has_12_targets() -> None:
    """docker-compose.yml must define 12 target services."""
    content = DOCKER_COMPOSE_FILE.read_text()
    # Count service names (lines starting with "  targetN:")
    service_pattern = re.compile(r"^  target\d+:$", re.MULTILINE)
    services = service_pattern.findall(content)
    assert len(services) >= 12, (
        f"docker-compose.yml defines {len(services)} services, expected at least 12"
    )


def test_benchmark_script_exists() -> None:
    """scripts/benchmark.py must exist."""
    script_file = Path(__file__).resolve().parent.parent / "scripts" / "benchmark.py"
    assert script_file.exists(), f"benchmark.py not found at {script_file}"
