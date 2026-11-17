"""Port discovery check: wraps Nmap for safe, passive TCP scanning."""

from __future__ import annotations

import shutil
from dataclasses import dataclass

from inspectra.analysis.recommendations import restrict_service
from inspectra.checks import CheckError
from inspectra.checks.context import ScanContext
from inspectra.models import Confidence, Finding, Severity, Target

SENSITIVE_SERVICES = {
    "ftp": Severity.MEDIUM,
    "telnet": Severity.HIGH,
    "rlogin": Severity.HIGH,
    "rsh": Severity.HIGH,
    "vnc": Severity.MEDIUM,
    "rdp": Severity.MEDIUM,
    "smb": Severity.MEDIUM,
    "snmp": Severity.MEDIUM,
    "tftp": Severity.MEDIUM,
    "nfs": Severity.MEDIUM,
    "smtp": Severity.LOW,
    "pop3": Severity.LOW,
    "imap": Severity.LOW,
}

HOST_TIMEOUT = "90s"


@dataclass(slots=True)
class OpenPort:
    """A single open TCP port reported by Nmap."""

    number: int
    service: str
    product: str = ""
    version: str = ""


def run(target: Target, context: ScanContext) -> list[Finding]:
    """Scan open TCP ports with Nmap and report the results."""
    if context.options is not None and context.options.skip_ports:
        return []
    if shutil.which("nmap") is None:
        raise CheckError(
            "ports skipped: nmap not installed "
            "(pip install inspectra-cli[ports] and install the nmap binary)"
        )
    try:
        import nmap
    except ImportError as exc:
        raise CheckError(
            "ports skipped: python-nmap package not installed (pip install inspectra-cli[ports])"
        ) from exc

    return _scan(target, context, nmap.PortScanner())


def _scan(target: Target, context: ScanContext, scanner: object) -> list[Finding]:
    """Run the scan with the given scanner (injected so tests can pass a fake)."""
    try:
        scanner.scan(  # type: ignore[attr-defined]
            hosts=target.hostname,
            ports=_port_spec(context),
            arguments=_arguments(context),
        )
    except Exception as exc:  # python-nmap raises broad exceptions on scan failure
        raise CheckError(f"Nmap scan failed for {target.hostname}: {exc}") from exc

    open_ports = _collect_open_ports(scanner, target.hostname)
    if not open_ports:
        return [_no_open_ports(target, context)]
    findings = [_open_ports_summary(target, open_ports)]
    for port in open_ports:
        if port.service in SENSITIVE_SERVICES:
            findings.append(_sensitive_service(port))
    return findings


def _port_spec(context: ScanContext) -> str | None:
    if context.options is not None and context.options.ports:
        return context.options.ports
    return None


def _arguments(context: ScanContext) -> str:
    arguments = f"-sV --host-timeout {HOST_TIMEOUT}"
    if _port_spec(context) is None:
        top_ports = context.options.top_ports if context.options is not None else 1000
        arguments += f" --top-ports {top_ports}"
    return arguments


def _collect_open_ports(scanner: object, hostname: str) -> list[OpenPort]:
    """Extract open ports from a python-nmap scanner (duck-typed for tests)."""
    try:
        hosts = scanner.all_hosts()  # type: ignore[attr-defined]
    except Exception:
        return []
    if hostname not in hosts:
        return []
    ports: list[OpenPort] = []
    host_result = scanner[hostname]  # type: ignore[index]
    for proto in host_result.all_protocols():
        for number, info in host_result[proto].items():
            if info.get("state") == "open":
                ports.append(
                    OpenPort(
                        number=number,
                        service=info.get("name", "unknown"),
                        product=info.get("product", ""),
                        version=info.get("version", ""),
                    )
                )
    return sorted(ports, key=lambda port: port.number)


def _no_open_ports(target: Target, context: ScanContext) -> Finding:
    return Finding(
        rule_id="PRT-001",
        title="No open TCP ports detected",
        category="ports",
        severity=Severity.INFO,
        confidence=Confidence.MEDIUM,
        description=f"Nmap found no open TCP ports on {target.hostname} within the scanned range.",
        why_it_matters=(
            "A host with no open ports has a small attack surface, but firewalls "
            "may be hiding services from the scanner."
        ),
        recommendation=(
            "If services are expected, verify firewall rules and re-scan a wider port range."
        ),
        evidence=[f"nmap {target.hostname} {_arguments(context)}"],
    )


def _open_ports_summary(target: Target, open_ports: list[OpenPort]) -> Finding:
    return Finding(
        rule_id="PRT-002",
        title=f"{len(open_ports)} open TCP port(s) detected",
        category="ports",
        severity=Severity.INFO,
        confidence=Confidence.HIGH,
        description=f"Nmap identified {len(open_ports)} open TCP port(s) on {target.hostname}.",
        why_it_matters=(
            "Every open port is a potential entry point. Review each service for "
            "exposure and keep them patched."
        ),
        recommendation="Close ports that are not needed and restrict the rest with firewall rules.",
        evidence=[_format_port(port) for port in open_ports],
    )


def _sensitive_service(port: OpenPort) -> Finding:
    return Finding(
        rule_id="PRT-003",
        title=f"Sensitive service exposed: {port.service} (port {port.number})",
        category="ports",
        severity=SENSITIVE_SERVICES[port.service],
        confidence=Confidence.MEDIUM,
        description=(
            f"Port {port.number} runs {port.service}, a service that is frequently "
            "targeted when exposed."
        ),
        why_it_matters=(
            "Services like FTP, Telnet, RDP and SMB transmit credentials insecurely "
            "or are common attack targets when reachable from the internet."
        ),
        recommendation=restrict_service(port.service, port.number),
        evidence=[_format_port(port)],
    )


def _format_port(port: OpenPort) -> str:
    product = f" ({port.product} {port.version})".rstrip() if port.product else ""
    return f"{port.number}/tcp {port.service}{product}"
