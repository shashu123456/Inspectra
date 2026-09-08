"""Recommendation helpers used by checks to build actionable advice.

Keeping recommendation text in one place means the wording stays consistent
across reports and is easy to review.
"""

from __future__ import annotations


def remove_header(name: str) -> str:
    """Advice for a header that should not be present."""
    return (
        f"Remove the {name!r} response header (or disable the framework option "
        "that adds it) to reduce information disclosure."
    )


def renew_certificate(days: int) -> str:
    """Advice for an expiring TLS certificate."""
    return (
        f"Renew the TLS certificate within {days} day(s). Consider automating "
        "renewal with ACME (e.g. Let's Encrypt)."
    )


def review_exposed_path(path: str) -> str:
    """Advice for an accessible path found by the directory check."""
    return (
        f"Review {path!r}: remove it if it is not needed, or protect it with "
        "authentication and access controls."
    )


def restrict_service(service: str, port: int) -> str:
    """Advice for a sensitive service exposed on the network."""
    return (
        f"Restrict {service} (port {port}) to trusted networks via firewall or "
        "VPN rules, or replace it with a secure alternative (SFTP instead of "
        "FTP, SSH instead of Telnet)."
    )
