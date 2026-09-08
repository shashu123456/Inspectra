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
from inspectra.models import ScanOptions, ScanResult, Severity
from inspectra.orchestrator import ScanAborted, run_scan
from inspectra.report import html_report, json_report, markdown_report
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
        choices=["markdown", "html"],
        default="markdown",
        help="Human-readable report format (default: markdown).",
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
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """CLI entry point. Returns the process exit code."""
    args = build_parser().parse_args(argv)
    if args.command != "scan":
        return 2

    if not _confirm_authorization(args.yes):
        console.print("[yellow]Scan cancelled: authorization not confirmed.[/]")
        return 2

    try:
        target = normalize_target(args.target)
    except TargetValidationError as exc:
        console.print(f"[bold red]Invalid target:[/] {exc}")
        return 2
    if target.is_private:
        console.print("[dim]Note: target is a private/local address — home-lab testing.[/]")

    options = ScanOptions(
        output_dir=args.output_dir,
        report_format=args.report_format,
        ports=args.ports,
        top_ports=args.top_ports,
        skip_ports=args.skip_ports,
        directories=args.directories,
        directory_wordlist=args.directory_wordlist,
        yes=args.yes,
        verbose=args.verbose,
    )
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
        console.print(f"[bold red]Scan aborted:[/] {exc}")
        return 2

    _write_reports(result, output_dir, args.report_format)
    _print_summary(result, output_dir)
    return 1 if result.has_actionable_findings else 0


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
    json_report.write(result, output_dir / "report.json")
    if report_format == "html":
        html_report.write(result, output_dir / "report.html")
    else:
        markdown_report.write(result, output_dir / "report.md")


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
