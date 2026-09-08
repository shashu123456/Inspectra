"""HTML report renderer: a polished, fully self-contained report.

The template ships inline CSS (no external assets), so ``report.html`` can be
shared, archived or attached to an email and always renders correctly.
"""

from __future__ import annotations

from pathlib import Path

from jinja2 import Environment, PackageLoader, select_autoescape

from inspectra.models import ScanResult, Severity

SEVERITY_ORDER = ["high", "medium", "low", "info"]
GOOD_GRADES = {"A+", "A", "B"}
BAD_GRADES = {"D", "F"}

_env = Environment(
    loader=PackageLoader("inspectra.report", "templates"),
    autoescape=select_autoescape(["html", "xml"]),
    trim_blocks=True,
    lstrip_blocks=True,
)


def render(result: ScanResult) -> str:
    """Render a :class:`ScanResult` as a self-contained HTML document."""
    template = _env.get_template("report.html.j2")
    findings = sorted(
        result.findings,
        key=lambda finding: (SEVERITY_ORDER.index(finding.severity.value), finding.rule_id),
    )
    summary = {
        severity: result.count_by_severity(Severity(severity)) for severity in SEVERITY_ORDER
    }
    return template.render(
        result=result,
        findings=findings,
        summary=summary,
        grade_class=_grade_class(result.grade or "F"),
    )


def _grade_class(grade: str) -> str:
    if grade in GOOD_GRADES:
        return "good"
    if grade in BAD_GRADES:
        return "bad"
    return "warn"


def write(result: ScanResult, path: Path) -> None:
    """Write the HTML report to ``path``."""
    path.write_text(render(result), encoding="utf-8")
