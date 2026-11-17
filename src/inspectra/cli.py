"""Command-line interface for Inspectra."""

from __future__ import annotations

import argparse
import json
import logging
import sys
from collections.abc import Sequence
from datetime import datetime
from pathlib import Path
from types import ModuleType

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from inspectra import __version__
from inspectra.models import ScanResult, Severity
from inspectra.report import html_report, json_report, markdown_report, sarif_report
from inspectra.utils import TargetValidationError, normalize_target

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

SEVERITY_STYLE = {
    "HIGH": "bold red",
    "MEDIUM": "yellow",
    "LOW": "cyan",
    "INFO": "dim",
}

SEVERITY_ORDER = {
    Severity.HIGH: 0,
    Severity.MEDIUM: 1,
    Severity.LOW: 2,
    Severity.INFO: 3,
}


def build_parser() -> argparse.ArgumentParser:
    """Build the command-line argument parser."""
    parser = argparse.ArgumentParser(
        prog="inspectra",
        description=(
            "Open-source explainable security assessment framework. "
            "Inspect. Observe. Assess. Explain. Report. Never exploit."
        ),
        epilog=(
            "Examples:\n"
            "  inspectra scan https://example.com --yes\n"
            "  inspectra scan https://example.com --format sarif --fail-on high\n"
            "  inspectra scan --replay evidence.jsonl\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="version", version=f"inspectra {__version__}")
    subparsers = parser.add_subparsers(
        dest="command",
        required=True,
        title="subcommands",
        description="Available commands:",
    )

    scan = subparsers.add_parser(
        "scan",
        help="Run a security assessment against a target.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    target_group = scan.add_argument_group("TARGET")
    target_group.add_argument(
        "target",
        help="Domain, IP address or URL to assess (e.g. example.com).",
    )

    run_group = scan.add_argument_group("WHAT TO RUN")
    run_group.add_argument(
        "--ports",
        help="PORTS comma-separated port list for Nmap (e.g. 80,443,8080).",
    )
    run_group.add_argument(
        "--top-ports",
        type=int,
        default=1000,
        help="N scan the N most common ports with Nmap (default: 1000).",
    )
    run_group.add_argument(
        "--skip-ports",
        action="store_true",
        help="Skip Nmap port discovery (useful when Nmap is not installed).",
    )
    run_group.add_argument(
        "--directories",
        action="store_true",
        help="Probe a curated wordlist of common paths (rate-limited, GET-only).",
    )
    run_group.add_argument(
        "--directory-wordlist",
        help="PATH custom wordlist for --directories (one path per line, # comments allowed).",
    )
    run_group.add_argument(
        "--concurrency",
        dest="concurrency",
        type=int,
        default=4,
        help="N max concurrent checks per target (default: 4).",
    )
    run_group.add_argument(
        "--delay",
        dest="delay",
        type=float,
        default=0.2,
        help="SECONDS delay between per-host requests (default: 0.2).",
    )
    run_group.add_argument(
        "--rules-dir",
        dest="rules_dir",
        action="append",
        metavar="PATH",
        help="PATH load custom checks from this directory (repeatable).",
    )
    run_group.add_argument(
        "--list-checks",
        action="store_true",
        help="Print every built-in and loaded check with ID, title, and source.",
    )

    output_group = scan.add_argument_group("OUTPUT")
    output_group.add_argument(
        "--format",
        dest="report_format",
        default="html",
        help="FORMAT html | json | markdown | sarif (default: html).",
    )
    output_group.add_argument(
        "-o",
        "--output",
        dest="output_path",
        metavar="PATH",
        help="PATH write a single-format report to this exact path (requires a single format).",
    )
    output_group.add_argument(
        "--output-dir",
        default=DEFAULT_OUTPUT_DIR,
        help=f"DIR directory for reports (default: {DEFAULT_OUTPUT_DIR}/).",
    )
    output_group.add_argument(
        "--save-baseline",
        dest="save_baseline",
        metavar="PATH",
        help="PATH write baseline fingerprint file to PATH after scanning.",
    )
    output_group.add_argument(
        "--baseline",
        dest="baseline",
        metavar="PATH",
        help="PATH compare against a baseline file; only new findings count toward fail-on.",
    )
    output_group.add_argument(
        "--save-fixtures",
        dest="save_fixtures",
        metavar="DIR",
        help="DIR record every HTTP request/response to DIR for later replay.",
    )
    output_group.add_argument(
        "--replay",
        dest="replay_dir",
        metavar="DIR",
        help="DIR replay all HTTP requests from DIR fixtures (offline, no network).",
    )
    output_group.add_argument(
        "--no-findings",
        action="store_true",
        help="Suppress the findings table (summary panel still prints).",
    )
    output_group.add_argument(
        "--findings-limit",
        dest="findings_limit",
        type=int,
        default=25,
        help="N max findings to print in the terminal table (default: 25).",
    )
    output_group.add_argument(
        "--quiet",
        action="store_true",
        help="Print the summary panel and counts only (CI logs).",
    )

    safety_group = scan.add_argument_group("SAFETY")
    safety_group.add_argument(
        "--yes",
        action="store_true",
        help="Accept the authorization agreement without prompting.",
    )
    safety_group.add_argument(
        "--verbose",
        action="store_true",
        help="Enable debug logging.",
    )
    safety_group.add_argument(
        "--fail-on",
        dest="fail_on",
        default="high",
        choices=["none", "low", "medium", "high"],
        help="LEVEL exit non-zero when findings at or above this severity exist: "
        "none|low|medium|high (default: high).",
    )
    safety_group.add_argument(
        "--allow-private",
        action="store_true",
        help="Allow scanning private/loopback/local addresses (home-lab only).",
    )
    safety_group.add_argument(
        "--authorized",
        action="store_true",
        help="Required with --allow-private; confirms explicit authorization.",
    )
    safety_group.add_argument(
        "--no-redact",
        action="store_true",
        help="Disable secret redaction in evidence (debug only).",
    )
    safety_group.add_argument(
        "--allow-insecure",
        action="store_true",
        help="Accept self-signed / untrusted TLS certificates (lab only).",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """CLI entry point. Returns the process exit code."""
    args = build_parser().parse_args(argv)
    if args.command != "scan":
        return 2

    formats = [f.strip().lower() for f in args.report_format.split(",") if f.strip()]
    valid_formats = {"markdown", "html", "json", "sarif"}
    for fmt in formats:
        if fmt not in valid_formats:
            build_parser().error(f"Invalid format {fmt!r}; choose from {sorted(valid_formats)}.")

    if args.output_path and len(formats) != 1:
        build_parser().error(
            "-o/--output requires a single report format (no comma-separated lists)."
        )

    if args.baseline == "":
        args.baseline = None

    if args.save_fixtures and args.replay_dir:
        build_parser().error("--save-fixtures and --replay are mutually exclusive.")

    if not _confirm_authorization(args.yes):
        console.print("[yellow]Scan cancelled: authorization not confirmed.[/]")
        return 2

    try:
        target = normalize_target(args.target)
    except TargetValidationError as exc:
        print(f"Error: Invalid target: {exc}", file=sys.stderr)
        return 2
    if target.is_private:
        console.print("[dim]Note: target is a private/local address - home-lab testing.[/]")

    from inspectra.safety import SSRFError, validate_target

    try:
        validate_target(target.hostname, args.allow_private, args.authorized)
    except SSRFError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2

    if args.no_redact:
        print("Warning: redaction disabled - evidence may contain secrets.", file=sys.stderr)

    from inspectra.checks.context import ScanContext
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
        save_fixtures=args.save_fixtures,
        replay_dir=args.replay_dir,
        concurrency=args.concurrency,
        delay=args.delay,
        no_findings=args.no_findings,
        findings_limit=args.findings_limit,
        quiet=args.quiet,
        rules_dir=args.rules_dir,
        list_checks=args.list_checks,
        allow_insecure=args.allow_insecure,
    )

    from inspectra.checks import ordered_checks

    if args.list_checks:
        table = Table(title="Available checks")
        table.add_column("ID", style="bold", no_wrap=True)
        table.add_column("Title", no_wrap=True)
        table.add_column("Source", no_wrap=True)
        for name, _ in ordered_checks(args.directories):
            table.add_row(name, name, "builtin")
        if args.rules_dir:
            from inspectra.checks.loader import load_rules_dir

            for rd in args.rules_dir:
                for module in load_rules_dir(rd):
                    table.add_row(module.RULE_ID, module.TITLE, "custom")
        console.print(table)
        return 0

    custom_modules: list[ModuleType] = []
    custom_context: ScanContext | None = None
    if args.rules_dir:
        from inspectra.checks.loader import load_rules_dir

        custom_context = ScanContext(options=options)
        for rd in args.rules_dir:
            custom_modules.extend(load_rules_dir(rd))
    output_dir = None
    if not args.output_path:
        output_dir = Path(args.output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        _setup_logging(args.verbose, output_dir / "inspectra.log")

    console.print()
    console.print(
        Panel(
            f"[bold blue]INSPECTRA[/bold blue]  [bold cyan]LIVE SCAN[/bold cyan]\n"
            f"[bold]{target.hostname}[/bold]  │  [bold]{target.scheme.upper()}://{target.hostname}[/bold]\n"
            f"Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} IST",
            border_style="blue",
            padding=(1, 2),
        )
    )
    console.print()

    try:
        with console.status(f"[bold green]Scanning[/] {target.hostname} ...") as status:
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

    if custom_modules and custom_context is not None:
        from inspectra.checks.loader import run_custom_checks

        custom_findings = run_custom_checks(custom_modules, target, custom_context)
        result.findings.extend(custom_findings)

    if result.skipped:
        skipped_names = ", ".join(item["check"] for item in result.skipped)
        console.print(f"Skipped (replay): {skipped_names} - these need live network access")

    from inspectra.redact import redaction_metadata
    from inspectra.safety import scope_metadata

    result.scope = scope_metadata(args.allow_private, args.authorized)
    result.redaction = redaction_metadata(args.no_redact)

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
        if not args.quiet:
            _print_summary(result, output_dir, args)

    baseline_summary: dict[str, int] | None = None
    if args.save_baseline:
        from inspectra.baseline import save_baseline

        baseline_findings: list[dict[str, object]] = [
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
        finding_dicts: list[dict[str, object]] = [
            {
                "rule_id": f.rule_id,
                "severity": f.severity.value,
                "fingerprint": f.fingerprint,
            }
            for f in result.findings
        ]
        baseline_summary = classify_findings(finding_dicts, baseline_data)
        result._baseline_summary = baseline_summary
        for finding, fd in zip(result.findings, finding_dicts, strict=True):
            baseline_status = fd.get("_baseline_status")
            finding._baseline_status = baseline_status if isinstance(baseline_status, str) else None

    if output_dir is not None and args.quiet:
        _print_summary(result, output_dir, args)

    from inspectra.baseline import failing_severity

    if baseline_summary:
        new_highs = sum(
            1
            for f in result.findings
            if getattr(f, "_baseline_status", None) == "new"
            and failing_severity(args.fail_on, f.severity.value)
        )
        return 1 if new_highs > 0 else 0
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


def _where_text(evidence: list[str], width: int = 40) -> str:
    """Return the first evidence line truncated to width without splitting words or ellipsis."""
    text = evidence[0] if evidence else "-"
    if len(text) <= width:
        return text
    cut = text.rfind(" ", 0, width)
    if cut <= 0:
        return text[:width]
    return text[:cut]


def _title_text(title: str, width: int = 40) -> str:
    """Return a finding title truncated to width without splitting words or ellipsis."""
    if len(title) <= width:
        return title
    cut = title.rfind(" ", 0, width)
    if cut <= 0:
        return title[:width]
    return title[:cut]


def _print_summary(result: ScanResult, output_dir: Path, args: argparse.Namespace) -> None:
    """Print the scan summary panel and, unless quiet, the findings table."""
    grid = Table.grid(padding=(0, 2))
    grid.add_column(style="bold")
    grid.add_column()
    grid.add_row("Target", f"{result.target.hostname} - {result.target.base_url}")
    grid.add_row("Posture", f"{result.posture_score:.1f} / 100 - {result.grade}")
    for severity in (Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO):
        grid.add_row(f"{severity.value.upper()} findings", str(result.count_by_severity(severity)))
    grid.add_row("Elapsed", f"{result.metadata.duration_seconds:.1f}s")
    grid.add_row("Checks run", str(result.checks_run))
    grid.add_row("Skipped", ", ".join(result.checks_skipped) or "none")
    console.print(
        Panel(grid, title=f"Scan complete - {result.target.hostname}", border_style="blue")
    )
    console.print(f"Reports written to [cyan]{output_dir.resolve()}[/]")

    if args.quiet or args.no_findings:
        return

    ordered = sorted(
        result.findings,
        key=lambda f: (SEVERITY_ORDER[f.severity], f.rule_id, f.title),
    )
    if not ordered:
        return

    if not ordered:
        return

    console.print("[bold]Sev   Rule     Title                                       Where[/]")
    console.print("[bold]-" * 78 + "[/]")
    limit = max(0, args.findings_limit)
    for finding in ordered[:limit]:
        style = SEVERITY_STYLE.get(finding.severity.value.upper(), "white")
        sev_text = f"[{style}]{finding.severity.value.upper():<5}[/]"
        console.print(
            f"{sev_text} {finding.rule_id:<8} {_title_text(finding.title, 38)} "
            f"{_where_text(finding.evidence, 38)}"
        )
    if len(ordered) > limit:
        console.print(f"... and {len(ordered) - limit} more - see the report")
