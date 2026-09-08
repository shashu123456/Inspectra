"""Core domain models shared across Inspectra.

These dataclasses are the contract every module works against: checks emit
:class:`Finding` objects, the risk engine scores them, and reporters render
the resulting :class:`ScanResult`.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum

from inspectra import __version__


class Severity(StrEnum):
    """Risk severity of a finding, ordered from least to most severe."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class Confidence(StrEnum):
    """How sure we are that a finding reflects reality."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


@dataclass(slots=True)
class Finding:
    """A single observation produced by a check.

    Every finding is explainable: it states what was observed, why it
    matters, the evidence, the confidence, the severity and a practical
    recommendation.
    """

    rule_id: str
    title: str
    category: str
    severity: Severity
    confidence: Confidence
    description: str
    why_it_matters: str
    recommendation: str
    evidence: list[str] = field(default_factory=list)


@dataclass(slots=True)
class Target:
    """A validated scan target.

    ``ip_addresses`` and ``is_private`` are populated by the DNS check once
    resolution has happened, which is why the dataclass is mutable.
    """

    input: str
    hostname: str
    port: int | None = None
    scheme: str = "https"
    ip_addresses: list[str] = field(default_factory=list)
    is_private: bool = False

    @property
    def base_url(self) -> str:
        """The URL used to reach the target over its working scheme."""
        port = f":{self.port}" if self.port else ""
        return f"{self.scheme}://{self.hostname}{port}"


@dataclass(slots=True)
class ScanOptions:
    """User-selected options that influence how a scan runs."""

    output_dir: str = "inspectra-report"
    report_format: str = "markdown"
    ports: str | None = None
    top_ports: int = 1000
    skip_ports: bool = False
    directories: bool = False
    directory_wordlist: str | None = None


@dataclass(slots=True)
class ScanMetadata:
    """Provenance and timing information embedded in every report."""

    tool: str = "inspectra"
    version: str = __version__
    target: str = ""
    started_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    finished_at: datetime | None = None
    duration_seconds: float = 0.0


@dataclass(slots=True)
class ScanResult:
    """The complete output of a scan: target, findings, score and metadata."""

    target: Target
    findings: list[Finding] = field(default_factory=list)
    metadata: ScanMetadata = field(default_factory=ScanMetadata)
    posture_score: float | None = None
    grade: str | None = None

    def count_by_severity(self, severity: Severity) -> int:
        """Count findings at the given severity."""
        return sum(1 for finding in self.findings if finding.severity is severity)

    @property
    def total_findings(self) -> int:
        """Total number of findings recorded during the scan."""
        return len(self.findings)

    @property
    def has_actionable_findings(self) -> bool:
        """True when any finding is at least LOW severity (drives exit codes)."""
        return any(finding.severity is not Severity.INFO for finding in self.findings)
