"""Health service — run health checks, investigations, and reconfigure."""

from __future__ import annotations

from ..diagnose import Diagnostic
from ..models import CheckResult, Settings
from ..opnsense import OPNsenseClient
from ..ssh import SSHClient


def run_health(opn: OPNsenseClient, settings: Settings, ssh: SSHClient) -> tuple[list[CheckResult], int | None]:
    """Run the standard health check suite.

    Returns (results, uptime_seconds) — uptime_seconds is None if fetch fails.
    """
    diag = Diagnostic(settings, opn, ssh)
    results = diag.run_health_checks()
    uptime = diag.fetch_uptime_seconds()
    return results, uptime


def run_investigate(
    opn: OPNsenseClient,
    settings: Settings,
    ssh: SSHClient,
    laptop_ip: str = "10.10.30.101",
) -> list[CheckResult]:
    """Run focused inter-VLAN routing investigation.

    Args:
        laptop_ip: Laptop IP on VLAN 30 to investigate.

    Returns:
        List of CheckResult objects from the investigation.
    """
    diag = Diagnostic(settings, opn, ssh)
    return diag.investigate_inter_vlan(laptop_ip)


def run_reconfigure(opn: OPNsenseClient, service: str) -> dict:
    """Reconfigure and reload a service (kea, unbound, all).

    Args:
        service: One of 'kea', 'unbound', or 'all'.

    Returns:
        Dict mapping service name to reconfigure status.

    Raises:
        ValueError: If service is not one of the valid choices.
    """
    valid = {"kea", "unbound", "all"}
    if service not in valid:
        raise ValueError(f"Invalid service '{service}'. Choose from: {', '.join(sorted(valid))}")

    targets = ["kea", "unbound"] if service == "all" else [service]
    results: dict[str, str] = {}
    for svc in targets:
        r = opn.kea_reconfigure() if svc == "kea" else opn.unbound_reconfigure()
        results[svc] = r.get("status", "?")
    return results
