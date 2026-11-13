"""Command-line interface for Inspectra."""

from __future__ import annotations

import argparse
import json
import logging
import sys
from collections.abc import Sequence
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from inspectra import __version__
from inspectra.models import ScanResult, Severity
from inspectra.report import html_report, json_report, markdown_report, sarif_report
from inspectra.utils import TargetValidationError, format_ist, normalize_target

CONFIG_DIR = Path.home() / ".config" / "inspectra"
CONFIG_FILE = CONFIG_DIR / "config.json"
DEFAULT_OUTPUT_DIR = "inspectra-report"

CONSENT_BANNER = (
    "[bold yellow]Inspectra[/] performs [bold]passive security assessment[/]. "
    "Scan only systems you [bold]own[/] or are [bold]authorized[/] to test. "
    "Unauthorized scanning may be illegal in your jurisdiction. "
    "Inspectra observes, assesses, explains and reports — it never exploits."
)

console = Console()


def build_parser() -> argparse.ArgumentParser:
    """Build the command-line argument parser."""
    parser = argparse.ArgumentParser(
        prog="inspectra",
        description=(
            "Open-source explainable security assessment framework. "
            "Inspect. Observe. Assess. Explain. Report. Never exploit."
        ),
    )
    parser.add_argument("--version", action="version", version=f"inspectra {__version__}")
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan = subparsers.add_parser("scan", help="Run a security assessment against a target.")
    scan.add_argument(
        "target",
        help="Domain, IP address or URL to assess (e.g. example.com).",
    )
    scan.add_argument(
        "--format",
        dest="report_format",
        default="markdown",
        help="Report format(s): markdown, html, json, sarif. "
        "Repeat or comma-separate for multiple (default: markdown).",
    )
    scan.add_argument(
        "-o",
        "--output",
        dest="output_path",
        metavar="PATH",
        help="Write a single-format report to this exact path (requires a single format).",
    )
    scan.add_argument(
        "--output-dir",
        default=DEFAULT_OUTPUT_DIR,
        help=f"Directory for reports (default: {DEFAULT_OUTPUT_DIR}/).",
    )
    scan.add_argument(
        "--ports",
        help="Explicit comma-separated port list for Nmap (e.g. 80,443,8080).",
    )
    scan.add_argument(
        "--top-ports",
        type=int,
        default=1000,
        help="Scan the N most common ports with Nmap (default: 1000).",
    )
    scan.add_argument(
        "--skip-ports",
        action="store_true",
        help="Skip Nmap port discovery (useful when Nmap is not installed).",
    )
    scan.add_argument(
        "--directories",
        action="store_true",
        help="Also probe a curated wordlist of common paths (rate-limited, GET-only).",
    )
    scan.add_argument(
        "--directory-wordlist",
        help="Path to a custom wordlist for --directories (one path per line, # comments allowed).",
    )
    scan.add_argument(
        "--yes",
        action="store_true",
        help="Accept the authorization agreement without prompting.",
    )
    scan.add_argument(
        "--verbose",
        action="store_true",
        help="Enable debug logging.",
    )
    scan.add_argument(
        "--fail-on",
        dest="fail_on",
        default="high",
        choices=["none", "low", "medium", "high"],
        help=(
            "Exit non-zero when new findings at or above this severity exist: "
            "none|low|medium|high (default: high)."
        ),
    )
    scan.add_argument(
        "--allow-private",
        action="store_true",
        help="Allow scanning private/loopback/local addresses (home-lab only).",
    )
    scan.add_argument(
        "--authorized",
        action="store_true",
        help="Required with --allow-private; confirms explicit authorization.",
    )
    scan.add_argument(
        "--no-redact",
        action="store_true",
        help="Disable secret redaction in evidence (debug only).",
    )
    scan.add_argument(
        "--save-baseline",
        dest="save_baseline",
        metavar="PATH",
        help="Write baseline fingerprint file to PATH after scanning.",
    )
    scan.add_argument(
        "--baseline",
        dest="baseline",
        metavar="PATH",
        help="Compare against a baseline file at PATH; only new findings count toward fail-on.",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """CLI entry point. Returns the process exit code."""
    args = build_parser().parse_args(argv)
    if args.command != "scan":
        return 2

    # Validate --format values after comma-split (F5).
    formats = [f.strip().lower() for f in args.report_format.split(",") if f.strip()]
    valid_formats = {"markdown", "html", "json", "sarif"}
    for fmt in formats:
        if fmt not in valid_formats:
            build_parser().error(f"Invalid format {fmt!r}; choose from {sorted(valid_formats)}.")

    # Validate -o/--output requires a single format (F1).
    if args.output_path and len(formats) != 1:
        build_parser().error(
            "-o/--output requires a single report format (no comma-separated lists)."
        )

    # Treat empty --baseline string as absent (F2).
    if args.baseline == "":
        args.baseline = None

    if not _confirm_authorization(args.yes):
        console.print("[yellow]Scan cancelled: authorization not confirmed.[/]")
        return 2

    try:
        target = normalize_target(args.target)
    except TargetValidationError as exc:
        print(f"Error: Invalid target: {exc}", file=sys.stderr)
        return 2
    if target.is_private:
        console.print("[dim]Note: target is a private/local address — home-lab testing.[/]")

    # SSRF safety validation before any network I/O (M3).
    from inspectra.safety import SSRFError, validate_target

    try:
        validate_target(target.hostname, args.allow_private, args.authorized)
    except SSRFError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2

    # --no-redact warning to stderr (M3).
    if args.no_redact:
        print("Warning: redaction disabled - evidence may contain secrets.", file=sys.stderr)

    # Imported lazily: keeps `inspectra --version` fast by deferring the
    # heavy scan stack (httpx, dnspython, cryptography).
    from inspectra.models import ScanOptions
    from inspectra.orchestrator import ScanAborted, run_scan

    options = ScanOptions(
        output_dir=args.output_dir,
        report_format=args.report_format,
        ports=args.ports,
        top_ports=args.top_ports,
        skip_ports=args.skip_ports,
        directories=args.directories,
        directory_wordlist=args.directory_wordlist,
        fail_on=args.fail_on,
        save_baseline=args.save_baseline,
        baseline=args.baseline,
        output_path=args.output_path,
        allow_private=args.allow_private,
        authorized=args.authorized,
        no_redact=args.no_redact,
    )
    output_dir = None
    if not args.output_path:
        output_dir = Path(args.output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        _setup_logging(args.verbose, output_dir / "inspectra.log")

    try:
        with console.status(f"[bold green]Scanning[/] {target.hostname} …") as status:
            result = run_scan(
                target,
                options,
                progress=lambda name: status.update(
                    f"[bold green]Scanning[/] {target.hostname} — {name} check"
                ),
            )
    except ScanAborted as exc:
        print(f"Error: Scan aborted: {exc}", file=sys.stderr)
        return 2

    # Set scope/redaction metadata from options (M3).
    from inspectra.redact import redaction_metadata
    from inspectra.safety import scope_metadata

    result.scope = scope_metadata(args.allow_private, args.authorized)
    result.redaction = redaction_metadata(args.no_redact)

    # Write reports (F1: -o/--output writes a single format to an exact path).
    if args.output_path:
        output_path = Path(args.output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        fmt = formats[0]
        if fmt == "json":
            json_report.write(result, output_path)
        elif fmt == "markdown":
            markdown_report.write(result, output_path)
        elif fmt == "html":
            html_report.write(result, output_path)
        elif fmt == "sarif":
            sarif_report.write(result, output_path)
        console.print(f"Report written to [cyan]{output_path.resolve()}[/]")
    else:
        output_dir = Path(args.output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        _setup_logging(args.verbose, output_dir / "inspectra.log")
        _write_reports(result, output_dir, args.report_format)
        _print_summary(result, output_dir)
    baseline_summary = None
    if args.save_baseline:
        from inspectra.baseline import save_baseline

        baseline_findings = [
            {
                "id": f.rule_id,
                "check": f.category,
                "severity": f.severity.value,
                "fingerprint": f.fingerprint,
            }
            for f in result.findings
        ]
        save_baseline(target.input, baseline_findings, Path(args.save_baseline))

    if args.baseline:
        from inspectra.baseline import classify_findings, load_baseline

        baseline_data = load_baseline(Path(args.baseline))
        finding_dicts = [
            {
                "rule_id": f.rule_id,
                "severity": f.severity.value,
                "fingerprint": f.fingerprint,
            }
            for f in result.findings
        ]
        baseline_summary = classify_findings(finding_dicts, baseline_data)
        result._baseline_summary = baseline_summary
        # Attach status back to findings for JSON output
        for finding, fd in zip(result.findings, finding_dicts, strict=True):
            finding._baseline_status = fd.get("_baseline_status")

    if output_dir is not None:
        _print_summary(result, output_dir)

    # Exit code: --fail-on applies to all findings without baseline,
    # only to new findings with baseline (F4).
    from inspectra.baseline import failing_severity

    if baseline_summary:
        new_highs = sum(
            1
            for f in result.findings
            if getattr(f, "_baseline_status", None) == "new"
            and failing_severity(args.fail_on, f.severity.value)
        )
        return 1 if new_highs > 0 else 0
    # No baseline: fail-on applies to all findings; none => always exit 0.
    if args.fail_on == "none":
        return 0
    return (
        1 if any(failing_severity(args.fail_on, f.severity.value) for f in result.findings) else 0
    )


def _confirm_authorization(yes: bool) -> bool:
    """Show the authorization gate on first use; ``--yes`` skips it."""
    if yes or _consent_on_file():
        return True
    console.print(Panel(CONSENT_BANNER, title="Authorization required", border_style="yellow"))
    answer = input("Do you agree to scan only authorized targets? [y/N] ").strip().lower()
    if answer in {"y", "yes"}:
        _save_consent()
        return True
    return False


def _consent_on_file() -> bool:
    try:
        data = json.loads(CONFIG_FILE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return False
    return bool(data.get("authorized_use_agreed"))


def _save_consent() -> None:
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    CONFIG_FILE.write_text(
        json.dumps({"authorized_use_agreed": True, "version": __version__}),
        encoding="utf-8",
    )


def _setup_logging(verbose: bool, log_path: Path) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    formatter = logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s")
    file_handler = logging.FileHandler(log_path, encoding="utf-8")
    file_handler.setLevel(level)
    file_handler.setFormatter(formatter)
    stderr_handler = logging.StreamHandler(sys.stderr)
    stderr_handler.setLevel(logging.WARNING)
    stderr_handler.setFormatter(formatter)
    logging.basicConfig(level=level, handlers=[file_handler, stderr_handler])


def _write_reports(result: ScanResult, output_dir: Path, report_format: str) -> None:
    """Write reports in all requested formats (comma-separated or repeated).

    JSON is always written; human-readable formats are written on request.
    """
    formats = [f.strip().lower() for f in report_format.split(",") if f.strip()]
    if not formats:
        formats = ["markdown"]
    json_report.write(result, output_dir / "report.json")
    if "markdown" in formats:
        markdown_report.write(result, output_dir / "report.md")
    if "html" in formats:
        html_report.write(result, output_dir / "report.html")
    if "sarif" in formats:
        sarif_report.write(result, output_dir / "report.sarif")


def _print_summary(result: ScanResult, output_dir: Path) -> None:
    table = Table(title=f"Scan complete — {result.target.hostname}", show_lines=True)
    table.add_column("Severity", style="bold")
    table.add_column("Count")
    for severity in (Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO):
        table.add_row(severity.value.upper(), str(result.count_by_severity(severity)))
    table.add_row("Posture score", f"{result.posture_score:.1f} / 100 ({result.grade})")
    table.add_row(
        "Completed (IST)",
        format_ist(result.metadata.finished_at or result.metadata.started_at),
    )
    console.print(table)
    console.print(f"Reports written to [cyan]{output_dir.resolve()}[/]")
