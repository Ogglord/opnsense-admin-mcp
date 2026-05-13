"""MCP server for opnsense-mcp — AI-native interface.

Exposes OPNsense diagnostics and management as MCP tools.
Read-only tools are safe; write tools trigger audit and backup.

Config: set OPN_HOSTS, OPN_KEY, OPN_SECRET (and optionally OPN_SSH_KEY)
as environment variables, or keep a config.yaml file with named environments
selected via MCP_ENV.
"""

from __future__ import annotations

import os
import time
import traceback
from datetime import datetime, timezone
from typing import Any

from mcp.server import FastMCP

from .config import load_settings
from .db import HealthDB
from .diagnose import Diagnostic
from .models import Settings
from .opnsense import OPNsenseClient
from .services import dhcp as dhcp_svc
from .services import discovery as discovery_svc
from .services import dns as dns_svc
from .services import health as health_svc
from .services import status as status_svc
from .services import vlan as vlan_svc
from .ssh import SSHClient

MCP_VERSION = "0.3.0"
_SERVER_START = time.time()


def _ssh_mode() -> str:
    if os.environ.get("SSH_AUTH_SOCK"):
        return "agent"
    if os.environ.get("OPN_SSH_KEY"):
        return "key"
    return "none"


def _config_source() -> str:
    if os.environ.get("OPN_HOSTS"):
        return "env"
    if os.path.exists("config.yaml"):
        return "config.yaml"
    return "unknown"


def _ntopng_auth() -> tuple[str, str, int]:
    return (
        os.environ.get("NTOPNG_USER", "admin"),
        os.environ.get("NTOPNG_PASSWORD", "admin"),
        int(os.environ.get("NTOPNG_PORT", "3000")),
    )


def _ntopng_get(host: str, endpoint: str) -> Any:
    """Call ntopng REST API v2. Auth via NTOPNG_USER / NTOPNG_PASSWORD env vars."""
    import requests

    user, password, port = _ntopng_auth()
    url = f"http://{host}:{port}{endpoint}"
    r = requests.get(url, auth=(user, password), timeout=10, verify=False)
    r.raise_for_status()
    return r.json()


def _ntopng_import(host: str, modules: dict[str, Any]) -> Any:
    """POST to ntopng import endpoint using the required form encoding.

    ntopng import handlers read _POST["JSON"] — a form field containing
    a JSON string with envelope {"version":"1.0","modules":{...}}.
    """
    import json as _json
    import requests

    user, password, port = _ntopng_auth()
    envelope = {"version": "1.0", "modules": modules}
    r = requests.post(
        f"http://{host}:{port}/lua/rest/v2/import/active_monitoring/config.lua",
        auth=(user, password),
        data={"JSON": _json.dumps(envelope)},
        timeout=10,
    )
    if not r.ok:
        raise ValueError(f"ntopng {r.status_code}: {r.text[:500]}")
    result = r.json()
    if result.get("rc", -1) != 0:
        raise ValueError(f"ntopng import failed: {result}")
    return result


def _parse_pfctl_states(raw: str, limit: int) -> list[dict]:
    """Parse pfctl -ss output into structured dicts."""
    results = []
    for line in raw.splitlines():
        line = line.strip()
        if not line or line.startswith("No ALTQ") or line == "all":
            continue
        parts = line.split()
        if len(parts) < 4:
            continue
        results.append({"raw": line})
        if len(results) >= limit:
            break
    return results


def _make_context() -> dict[str, Any]:
    """Build shared infrastructure objects from environment."""
    settings = load_settings()
    opn = OPNsenseClient(settings)
    ssh = SSHClient(settings)
    diag = Diagnostic(settings, opn, ssh)
    instance_id = diag.fetch_hostuuid() or settings.opnsense_ts
    db = HealthDB(instance_id)
    return {
        "settings": settings,
        "opn": opn,
        "ssh": ssh,
        "db": db,
        "instance_id": instance_id,
    }


mcp = FastMCP("opnsense")


# ------------------------------------------------------------------
# Read-only tools
# ------------------------------------------------------------------


@mcp.tool()
async def server_info() -> dict[str, Any]:
    """Return MCP server version, process start time, config source, and SSH mode.

    Use this to verify the running code is current after deploying changes,
    and to confirm how the server is configured (env vars vs config.yaml,
    ssh-agent vs key file). Returns server metadata including the active
    OPNsense host and instance identifier.
    """
    uptime_s = int(time.time() - _SERVER_START)
    started_at = datetime.fromtimestamp(_SERVER_START, tz=timezone.utc).isoformat()
    ctx = _make_context()
    return {
        "version": MCP_VERSION,
        "started_at": started_at,
        "uptime_seconds": uptime_s,
        "pid": os.getpid(),
        "instance_id": ctx["instance_id"],
        "active_host": ctx["opn"].active_host,
        "ssh_mode": _ssh_mode(),
    }


@mcp.tool()
async def discover() -> dict[str, Any]:
    """Discover network topology: nodes, VLANs, interfaces, and gateways.

    Merges ARP table (SSH), DHCP leases, and static reservations. Each node
    includes ip, mac, hostname, manufacturer (OUI lookup), source
    (reservation/lease/arp), and description. Saves snapshot to SQLite and
    compares with previous snapshot to report topology drift (nodes appearing
    or disappearing, VLANs added or removed).

    Read-only — no side effects on the router. Safe to call frequently.
    """
    try:
        ctx = _make_context()
        topology = discovery_svc.discover(ctx["opn"], ctx["ssh"])

        previous = ctx["db"].latest_topology()
        drift = discovery_svc.detect_drift(topology, previous) if previous else []

        ctx["db"].save_topology(
            nodes=topology["nodes"],
            vlans=topology["vlans"],
            interfaces=topology["interfaces"],
            gateways=topology["gateways"],
        )

        return {
            "instance_id": ctx["instance_id"],
            "node_count": len(topology["nodes"]),
            "vlan_count": len(topology["vlans"]),
            "drift": drift,
            **topology,
        }
    except Exception as e:
        return {"error": type(e).__name__, "detail": str(e), "trace": traceback.format_exc()}


def _ntopng_monitor_check(opn_host: str, db: Any) -> list[dict[str, Any]]:
    """Return health check entries for each ntopng active monitor.

    Checks the window since the previous health run using hourly_stats
    (24-element array of downtime-event counts per hour-of-day).
    Reports PASS if no downtime events in window and last value >= threshold,
    WARN otherwise.
    """
    import requests
    from datetime import datetime, timezone

    user, password, port = _ntopng_auth()
    try:
        r = requests.get(
            f"http://{opn_host}:{port}/lua/rest/v2/get/active_monitoring/list.lua",
            auth=(user, password),
            timeout=10,
        )
        r.raise_for_status()
        am_list = r.json().get("rsp", [])
    except Exception as e:
        return [{"check": "ntopng monitors", "status": "WARN", "detail": f"unreachable: {e}"}]

    if not am_list:
        return []

    # Determine how many hours back to check
    prev_runs = db.recent_runs(limit=2)
    if len(prev_runs) >= 2:
        prev_ts = datetime.fromisoformat(prev_runs[1]["ts"])
        hours_back = max(1, int((datetime.now(timezone.utc) - prev_ts).total_seconds() / 3600) + 1)
    else:
        hours_back = 1

    now_hour = datetime.now(timezone.utc).hour
    check_hours = {(now_hour - i) % 24 for i in range(hours_back)}

    out = []
    for entry in am_list:
        key = entry.get("key", "?")
        measurement = entry.get("last_measurement", {}).get("measurement_type", "")
        last_val = entry.get("last_measurement", {}).get("measurement_value", "")
        is_alerted = entry.get("metadata", {}).get("is_alerted", False)
        hourly = entry.get("hourly_stats", [])
        downtime_events = sum(hourly[h] for h in check_hours if h < len(hourly))

        # Format last value with unit — cicmp/cicmpv6 = uptime %, icmp = RTT ms
        if not isinstance(last_val, (int, float)):
            val_str = "no data"
        elif measurement in ("cicmp", "cicmpv6", "http", "https"):
            val_str = f"{last_val}%"
        else:
            val_str = f"{last_val}ms"

        # Trust ntopng's own alerting + hourly downtime events; don't second-guess thresholds
        if is_alerted:
            status = "WARN"
            detail = f"last={val_str} alerted by ntopng"
        elif downtime_events > 0:
            status = "WARN"
            detail = f"last={val_str} {downtime_events} downtime events in last {hours_back}h"
        else:
            status = "PASS"
            detail = f"last={val_str} window={hours_back}h clean"

        out.append({"check": f"ntopng monitor: {key}", "status": status, "detail": detail})

    return out


@mcp.tool()
async def health_check() -> dict[str, Any]:
    """Run full health check suite across OPNsense and MT6000.

    Checks: API reachability, VLAN interfaces, routing table, ARP table,
    hardware flags, link speed, interface errors, internet ping,
    ntopng active monitor uptime since previous run, and
    (if MT6000 is configured) bridge VLAN, FDB, eth1 link, MT6000 ping.
    Saves the run to local SQLite history with router uptime for trend analysis.

    Any WARN or ERROR result is automatically enriched with trend data from
    SQLite history so you can distinguish persistent issues from transient spikes.
    Interface error trends include uptime_seconds for reboot correlation.

    Side effects: writes a row to the health check SQLite database.
    """
    try:
        ctx = _make_context()
        db = ctx["db"]
        results, uptime_seconds = health_svc.run_health(ctx["opn"], ctx["settings"], ctx["ssh"])
        checks = [{"check": r.name, "status": r.status.name, "detail": r.detail} for r in results]

        iface_errors: dict | None = None
        for r in results:
            if r.name == "Interface errors" and r.data:
                iface_errors = r.data
                break

        # ntopng active monitor check — window = since previous health run
        checks += _ntopng_monitor_check(ctx["opn"].active_host, db)

        run_id = db.save_run(checks, iface_errors, uptime_seconds)

        # Enrich WARN/ERROR checks with trend data where available
        enriched = []
        for r in results:
            entry: dict[str, Any] = {
                "check": r.name,
                "status": r.status.name,
                "detail": r.detail,
                "instance_id": ctx["instance_id"],
            }
            if r.status.name in ("WARN", "ERROR", "FAIL"):
                if r.name == "Interface errors" and r.data:
                    for iface in r.data:
                        trend = db.error_trend(interface=iface, limit=10)
                        entry.setdefault("trends", {})[iface] = trend
            enriched.append(entry)

        # Append ntopng monitor checks to enriched output
        for c in checks:
            if c["check"].startswith("ntopng monitor"):
                enriched.append({**c, "instance_id": ctx["instance_id"]})

        return {
            "run_id": run_id,
            "instance_id": ctx["instance_id"],
            "uptime_seconds": uptime_seconds,
            "checks": enriched,
        }
    except Exception as e:
        return {"error": type(e).__name__, "detail": str(e), "checks": []}


@mcp.tool()
async def get_status() -> dict[str, Any]:
    """Show status of key OPNsense services: Kea DHCP, Unbound DNS, BIND, and gateways.

    Returns a structured dict with service statuses, gateway health
    (loss/rtt), BIND zones and records. Read-only — no side effects.
    Call this for a quick overview of router health before digging into
    specific issues with leases, DNS records, or health checks.
    """
    try:
        ctx = _make_context()
        return status_svc.get_full_status(ctx["opn"])
    except Exception as e:
        return {"error": str(e), "detail": traceback.format_exc()}


@mcp.tool()
async def list_leases(vlan: int | None = None) -> list[dict[str, Any]]:
    """List active Kea DHCP leases, optionally filtered by VLAN ID.

    Returns each lease's IP, MAC, hostname, VLAN, reservation flag,
    and seconds until expiry. Read-only — no side effects.
    Use this to discover devices on the network, verify DHCP is working,
    or find a MAC address for adding a reservation.
    """
    try:
        ctx = _make_context()
        return status_svc.get_leases(ctx["opn"], vlan, ctx["settings"])
    except Exception as e:
        return [{"error": str(e), "detail": traceback.format_exc()}]


@mcp.tool()
async def list_reservations() -> list[dict[str, Any]]:
    """List all static Kea DHCP reservations.

    Returns IP, MAC, hostname, subnet, and description for each
    reservation. Read-only — no side effects.
    Use this to audit static assignments or check if a device already
    has a reservation before adding a new one.
    """
    try:
        ctx = _make_context()
        return status_svc.get_reservations(ctx["opn"])
    except Exception as e:
        return [{"error": str(e), "detail": traceback.format_exc()}]


@mcp.tool()
async def list_vlans() -> list[dict[str, Any]]:
    """List VLANs configured on OPNsense.

    Returns tag, interface, and description for each VLAN.
    Read-only — no side effects.
    Use this to verify VLAN configuration matches the intended
    network topology.
    """
    try:
        ctx = _make_context()
        return vlan_svc.list_vlans(ctx["opn"])
    except Exception as e:
        return [{"error": str(e), "detail": traceback.format_exc()}]


@mcp.tool()
async def list_unbound_forwards() -> list[dict[str, Any]]:
    """List Unbound DNS forward zones.

    Returns each zone's UUID, domain, server, port, and enabled flag.
    Read-only — no side effects.
    Use this to verify DNS forwarding is configured correctly, or to
    find a zone UUID for deletion.
    """
    try:
        ctx = _make_context()
        return dns_svc.list_unbound_forwards(ctx["opn"])
    except Exception as e:
        return [{"error": str(e), "detail": traceback.format_exc()}]


@mcp.tool()
async def list_bind_zones() -> list[dict[str, Any]]:
    """List BIND primary zones on OPNsense.

    Returns each zone's UUID, name, and enabled flag. Read-only.
    Use this to see which zones exist before adding or querying records.
    """
    try:
        ctx = _make_context()
        return dns_svc.list_bind_zones(ctx["opn"])
    except Exception as e:
        return [{"error": str(e), "detail": traceback.format_exc()}]


@mcp.tool()
async def list_bind_records(zone: str | None = None) -> list[dict[str, Any]]:
    """List BIND DNS records, optionally filtered by zone name.

    Returns each record's UUID, zone, name, type, and value.
    Read-only — no side effects.
    Use this to inspect DNS records in a zone, or find a record UUID
    for deletion. Omit the zone parameter to list all records.
    """
    try:
        ctx = _make_context()
        return dns_svc.list_bind_records(ctx["opn"], zone)
    except Exception as e:
        return [{"error": str(e), "detail": traceback.format_exc()}]


@mcp.tool()
async def health_runs(limit: int = 20) -> list[dict[str, Any]]:
    """Show recent health check run summaries from the local SQLite database.

    Returns run ID, timestamp, router uptime, and pass/fail/warn/error
    counts. Read-only — no side effects. Use this to see health trends
    over time or find a specific run for deeper investigation.
    """
    try:
        ctx = _make_context()
        return ctx["db"].recent_runs(limit=limit)
    except Exception as e:
        return [{"error": str(e), "detail": traceback.format_exc()}]


@mcp.tool()
async def health_errors(interface: str | None = None, limit: int = 50) -> list[dict[str, Any]]:
    """Show interface error trends over time from the health check database.

    Each row includes timestamp, interface name, ierrs/idrop/oerrs counts,
    and the router's uptime_seconds at the time of the check.

    Use uptime_seconds to correlate error spikes with reboots: if uptime
    resets (drops significantly) between two snapshots, error counters
    reset too — a jump in oerrs after a low uptime reading indicates
    errors accumulated since last boot, not a new deterioration.
    Stable uptime + rising errors = genuine degradation.

    Read-only — no side effects. Filter by interface name to narrow results.
    """
    try:
        ctx = _make_context()
        return ctx["db"].error_trend(interface=interface, limit=limit)
    except Exception as e:
        return [{"error": str(e), "detail": traceback.format_exc()}]


@mcp.tool()
async def dig(name: str, rtype: str = "A", server: str = "127.0.0.1", port: int = 53) -> str:
    """Run a DNS query via OPNsense using ``dig`` over SSH.

    Returns raw dig output. Read-only — no side effects.
    Use this to troubleshoot DNS resolution issues from the router's
    perspective, or verify that BIND/Unbound are serving expected records.
    """
    try:
        ctx = _make_context()
        return dns_svc.run_dig(ctx["ssh"], ctx["settings"], name, server, port, rtype)
    except Exception as e:
        return f"Error: {e}"


# ------------------------------------------------------------------
# Write tools (mutations — trigger reconfigure, backup, and audit)
# ------------------------------------------------------------------


@mcp.tool()
async def add_reservation(mac: str, ip: str, hostname: str = "", description: str = "") -> dict[str, Any]:
    """Add a static DHCP reservation to Kea on OPNsense.

    Finds the matching subnet automatically from the IP address.
    After saving, triggers a Kea reconfigure to activate the reservation.

    Side effects: modifies OPNsense DHCP config, triggers service reload.
    Use this to assign a fixed IP to a device by MAC address.
    """
    try:
        ctx = _make_context()
        return dhcp_svc.add_reservation(ctx["opn"], mac, ip, hostname, description)
    except Exception as e:
        return {"error": str(e), "detail": traceback.format_exc()}


@mcp.tool()
async def add_unbound_forward(domain: str, server: str, port: int = 53530) -> dict[str, Any]:
    """Add a DNS forward zone to Unbound on OPNsense.

    After saving, triggers an Unbound reconfigure.

    Side effects: modifies Unbound config, triggers service reload.
    Use this to forward queries for a domain to an upstream DNS server
    (e.g., forward home.arpa to BIND at 127.0.0.1:53530).
    """
    try:
        ctx = _make_context()
        return dns_svc.add_unbound_forward(ctx["opn"], domain, server, port)
    except Exception as e:
        return {"error": str(e), "detail": traceback.format_exc()}


@mcp.tool()
async def del_unbound_forward(uuid: str) -> dict[str, Any]:
    """Delete a Unbound DNS forward zone by UUID.

    Side effects: modifies Unbound config. Does NOT trigger reconfigure
    automatically — call reconfigure("unbound") after if needed.
    Use this to remove a stale forwarding rule.
    """
    try:
        ctx = _make_context()
        return dns_svc.del_unbound_forward(ctx["opn"], uuid)
    except Exception as e:
        return {"error": str(e), "detail": traceback.format_exc()}


@mcp.tool()
async def add_bind_record(zone: str, name: str, rtype: str, value: str) -> dict[str, Any]:
    """Add a DNS record to a BIND zone on OPNsense.

    Side effects: writes to BIND zone file. Does NOT trigger reconfigure
    automatically — call reconfigure("unbound") or reconfigure("all")
    after if needed.
    Use this to add A, AAAA, CNAME, or other record types to a zone.
    """
    try:
        ctx = _make_context()
        return dns_svc.add_bind_record(ctx["opn"], zone, name, rtype, value)
    except Exception as e:
        return {"error": str(e), "detail": traceback.format_exc()}


@mcp.tool()
async def del_bind_record(uuid: str) -> dict[str, Any]:
    """Delete a DNS record from BIND by UUID.

    Side effects: modifies BIND zone. Does NOT trigger reconfigure.
    Use this to remove an outdated or incorrect DNS record.
    """
    try:
        ctx = _make_context()
        return dns_svc.del_bind_record(ctx["opn"], uuid)
    except Exception as e:
        return {"error": str(e), "detail": traceback.format_exc()}


@mcp.tool()
async def reconfigure(service: str) -> dict[str, Any]:
    """Reconfigure and reload a service on OPNsense.

    Valid values: ``kea`` (DHCP), ``unbound`` (DNS), ``all`` (both).
    Returns the status of each reconfigured service.

    Side effects: triggers OPNsense service reload — may briefly
    interrupt DHCP or DNS. Use after adding reservations, forward zones,
    or DNS records to activate changes.
    """
    try:
        ctx = _make_context()
        return health_svc.run_reconfigure(ctx["opn"], service)
    except Exception as e:
        return {"error": str(e), "detail": traceback.format_exc()}


@mcp.tool()
async def ntopng_top_hosts(limit: int = 10) -> dict[str, Any]:
    """Top N local hosts by bandwidth from ntopng.

    Calls ntopng REST API v2 at port 3000 on the OPNsense host.
    Set NTOPNG_USER / NTOPNG_PASSWORD env vars for credentials (default: admin/admin).
    Set NTOPNG_PORT to override port (default: 3000).
    Fetches active hosts per interface, sorts by total bytes, returns top N.
    Read-only — no side effects.
    """
    try:
        ctx = _make_context()
        host = ctx["opn"].active_host
        ifaces = _ntopng_get(host, "/lua/rest/v2/get/ntopng/interfaces.lua")
        iface_list = ifaces.get("rsp", [])
        if not iface_list:
            return {"error": "ntopng returned no interfaces", "raw": ifaces}
        results = {}
        for iface in iface_list:
            ifid = iface.get("ifid", 0)
            ifname = iface.get("ifname", str(ifid))
            data = _ntopng_get(host, f"/lua/rest/v2/get/host/active.lua?ifid={ifid}")
            # paginated response: rsp.data[] holds the host list
            rsp = data.get("rsp", {})
            hosts = rsp.get("data", rsp) if isinstance(rsp, dict) else rsp
            if not isinstance(hosts, list):
                results[ifname] = {"error": "unexpected response", "raw": data}
                continue
            hosts.sort(
                key=lambda h: h.get("bytes", {}).get("total", 0),
                reverse=True,
            )
            results[ifname] = [
                {
                    "ip": h.get("ip"),
                    "name": h.get("name", h.get("ip")),
                    "bytes_sent": h.get("bytes", {}).get("sent", 0),
                    "bytes_rcvd": h.get("bytes", {}).get("rcvd", 0),
                    "total_bytes": h.get("bytes", {}).get("total", 0),
                    "num_flows": h.get("num_flows", {}).get("total", 0),
                    "score": h.get("score", {}).get("total", 0),
                    "is_local": h.get("is_localhost", False),
                }
                for h in hosts[:limit]
            ]
        return results
    except Exception as e:
        return {"error": str(e), "detail": traceback.format_exc()}


@mcp.tool()
async def ntopng_alerts(min_score: int = 1, limit: int = 20) -> dict[str, Any]:
    """Hosts with non-zero alert scores from ntopng (community-compatible).

    alert/list.lua is enterprise-only. This fetches all active hosts and
    returns those with score > 0, sorted by score descending. Score reflects
    ntopng's threat/anomaly detection heuristics.
    Set NTOPNG_USER / NTOPNG_PASSWORD env vars for credentials (default: admin/admin).
    Read-only — no side effects.
    """
    try:
        ctx = _make_context()
        host = ctx["opn"].active_host
        ifaces = _ntopng_get(host, "/lua/rest/v2/get/ntopng/interfaces.lua")
        iface_list = ifaces.get("rsp", [])
        results: dict[str, Any] = {}
        for iface in iface_list:
            ifid = iface.get("ifid", 0)
            ifname = iface.get("ifname", str(ifid))
            data = _ntopng_get(host, f"/lua/rest/v2/get/host/active.lua?ifid={ifid}")
            rsp = data.get("rsp", {})
            hosts = rsp.get("data", rsp) if isinstance(rsp, dict) else rsp
            if not isinstance(hosts, list):
                continue
            flagged = [
                {
                    "ip": h.get("ip"),
                    "name": h.get("name", h.get("ip")),
                    "score": h.get("score", {}).get("total", 0),
                    "score_as_client": h.get("score", {}).get("as_client", 0),
                    "score_as_server": h.get("score", {}).get("as_server", 0),
                    "total_bytes": h.get("bytes", {}).get("total", 0),
                    "num_flows": h.get("num_flows", {}).get("total", 0),
                    "is_local": h.get("is_localhost", False),
                    "is_blacklisted": h.get("is_blacklisted", False),
                }
                for h in hosts
                if h.get("score", {}).get("total", 0) >= min_score
            ]
            flagged.sort(key=lambda h: h["score"], reverse=True)
            results[ifname] = flagged[:limit]
        return results
    except Exception as e:
        return {"error": str(e), "detail": traceback.format_exc()}


@mcp.tool()
async def list_active_monitors() -> dict[str, Any]:
    """List all ntopng active monitoring entries (continuous ICMP/HTTP probes).

    Fetches the current active monitoring config via ntopng REST API v2.
    Returns all configured hosts with their measurement type, alias,
    threshold, and last known status.
    Set NTOPNG_USER / NTOPNG_PASSWORD env vars for credentials (default: admin/admin).
    Read-only — no side effects.
    """
    try:
        ctx = _make_context()
        host = ctx["opn"].active_host
        data = _ntopng_get(host, "/lua/rest/v2/export/active_monitoring/config.lua")
        return data.get("rsp", data)
    except Exception as e:
        return {"error": str(e), "detail": traceback.format_exc()}


_AM_IMPORT_FIELDS = {"threshold", "granularity", "ifname"}


def _am_strip_export_fields(res: dict) -> dict:
    """Keep only fields ntopng import endpoint accepts (whitelist)."""
    return {k: {fk: fv for fk, fv in v.items() if fk in _AM_IMPORT_FIELDS} for k, v in res.items()}


@mcp.tool()
async def add_active_monitor(
    target: str,
    measurement: str = "cicmp",
    threshold: int = 99,
    granularity: str = "min",
    ifname: str = "",
) -> dict[str, Any]:
    """Add a host to ntopng active monitoring.

    Fetches current config, adds the entry, and imports it back.
    ``target`` is an IP or hostname. ``measurement`` is ``cicmp`` (continuous
    ICMP, default), ``http``, or ``https``. ``threshold`` is minimum uptime
    percentage (default 99). ``granularity`` is ``min`` or ``5mins``.
    ``ifname`` optionally pins to a specific interface (e.g. ``vlan03``).

    Key format in ntopng config: ``{measurement}@{target}``.
    Side effects: modifies ntopng active monitoring configuration.
    """
    try:
        ctx = _make_context()
        host = ctx["opn"].active_host
        current = _ntopng_get(host, "/lua/rest/v2/export/active_monitoring/config.lua")
        config = current.get("rsp", current)
        am = config.get("modules", {}).get("active_monitoring", {})
        res: dict = am.get("res", {})
        key = f"{measurement}@{target}"
        if key in res:
            return {"error": f"Entry already exists: '{key}'", "existing": res[key]}
        entry: dict[str, Any] = {"threshold": threshold, "granularity": granularity}
        if ifname:
            entry["ifname"] = ifname
        res[key] = entry
        clean_res = _am_strip_export_fields(res)
        result = _ntopng_import(host, {"active_monitoring": {"res": clean_res}})
        return {"added": key, "entry": entry, "result": result}
    except Exception as e:
        return {"error": str(e), "detail": traceback.format_exc()}


@mcp.tool()
async def del_active_monitor(target: str) -> dict[str, Any]:
    """Remove a host from ntopng active monitoring.

    ``target`` can be the full key (``cicmp@host``), a bare hostname/IP
    (matched against the ``@host`` suffix of every key), or an exact key.
    Fetches current config, removes matching entry, and imports it back.

    Side effects: modifies ntopng active monitoring configuration.
    """
    try:
        ctx = _make_context()
        host = ctx["opn"].active_host
        current = _ntopng_get(host, "/lua/rest/v2/export/active_monitoring/config.lua")
        config = current.get("rsp", current)
        am = config.get("modules", {}).get("active_monitoring", {})
        res: dict = am.get("res", {})
        before = set(res.keys())
        # match exact key or suffix after @
        to_remove = {k for k in res if k == target or k.split("@", 1)[-1] == target}
        if not to_remove:
            return {"error": f"No entry matching '{target}'", "known_keys": list(res.keys())}
        for k in to_remove:
            del res[k]
        clean_res = _am_strip_export_fields(res)
        result = _ntopng_import(host, {"active_monitoring": {"res": clean_res}})
        return {"removed": list(to_remove), "remaining": list(res.keys()), "result": result}
    except Exception as e:
        return {"error": str(e), "detail": traceback.format_exc()}


@mcp.tool()
async def ntopng_monitor_timeseries(
    target: str,
    measurement: str = "cicmp",
    schema: str = "val_min",
    hours: int = 24,
) -> dict[str, Any]:
    """Fetch historical time series for an ntopng active monitoring probe.

    ``target`` is the hostname or IP (e.g. ``mt6000.home.arpa``).
    ``measurement`` is ``cicmp``, ``http``, or ``https``.
    ``schema`` selects the metric:
      - ``val_min`` — uptime percentage (default)
      - ``cicmp_stats_min`` — ICMP RTT min/max (ms)
      - ``jitter_stats_min`` — latency and jitter (ms)
    ``hours`` controls the look-back window (default 24, max 168).

    Returns series data and per-series statistics (min, max, average, p95).
    Read-only — no side effects.
    """
    import time

    try:
        ctx = _make_context()
        host = ctx["opn"].active_host
        user, password, port = _ntopng_auth()
        hours = min(max(1, hours), 168)
        now = int(time.time())
        epoch_begin = now - hours * 3600
        ts_query = f"ifid:-1,host:{target},metric:{measurement}"
        ts_schema = f"am_host:{schema}"
        url = (
            f"http://{host}:{port}/lua/rest/v2/get/timeseries/ts.lua"
            f"?ts_schema={ts_schema}&ts_query={ts_query}"
            f"&epoch_begin={epoch_begin}&epoch_end={now}"
        )
        import requests
        r = requests.get(url, auth=(user, password), timeout=15)
        r.raise_for_status()
        data = r.json()
        if data.get("rc", -1) != 0:
            return {"error": data.get("rc_str_hr", "unknown"), "raw": data}
        rsp = data.get("rsp", {})
        series = rsp.get("series", [])
        # Summarise: strip nulls, attach stats
        result = []
        for s in series:
            vals = [v for v in s.get("data", []) if v is not None]
            result.append({
                "id": s["id"],
                "samples": len(vals),
                "statistics": s.get("statistics", {}),
                "data": s.get("data", []),
            })
        return {
            "target": target,
            "measurement": measurement,
            "schema": ts_schema,
            "hours": hours,
            "step_seconds": rsp.get("step"),
            "series": result,
        }
    except Exception as e:
        return {"error": str(e), "detail": traceback.format_exc()}


@mcp.tool()
async def pf_states(limit: int = 50) -> dict[str, Any]:
    """Show active PF firewall state table entries.

    Runs ``pfctl -ss`` on OPNsense via SSH and returns the top N entries.
    Also returns total state count from ``pfctl -si``.
    Read-only — no side effects.
    """
    try:
        ctx = _make_context()
        ss = ctx["ssh"].opnsense(f"pfctl -ss | head -{limit + 5}")
        si = ctx["ssh"].opnsense("pfctl -si | grep 'current entries'")
        states = _parse_pfctl_states(ss.stdout, limit)
        return {
            "total_info": si.stdout.strip(),
            "entries": states,
            "truncated": len(states) >= limit,
        }
    except Exception as e:
        return {"error": str(e), "detail": traceback.format_exc()}


@mcp.tool()
async def read_log(log: str = "filter", lines: int = 100, date: str = "") -> dict[str, Any]:
    """Read recent lines from an OPNsense system log.

    Allowed log names: ``filter`` (PF firewall), ``configd``, ``system``,
    ``dhcpd``, ``dns``, ``ntopng``. Reads from /var/log/<name>/latest.log.
    Lines capped at 500.

    For ``system`` and ``configd`` logs, pass ``date`` as ``YYYY-MM-DD`` to read
    a specific day's archived log (e.g. ``date="2026-05-13"`` reads
    ``system_20260513.log``). Omit ``date`` to read latest.log as usual.
    Read-only — no side effects.
    """
    allowed = {
        "filter": "/var/log/filter/latest.log",
        "configd": "/var/log/configd/latest.log",
        "system": "/var/log/system/latest.log",
        "dhcpd": "/var/log/dhcpd/latest.log",
        "dns": "/var/log/dns/latest.log",
        "ntopng": "/var/log/ntopng/ntopng.log",
    }
    archived = {"system", "configd"}
    if log not in allowed:
        return {"error": f"Unknown log '{log}'. Allowed: {list(allowed)}"}
    lines = min(lines, 500)

    path = allowed[log]
    if date:
        if log not in archived:
            return {"error": f"date param only supported for: {sorted(archived)}"}
        import re
        if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", date):
            return {"error": "date must be YYYY-MM-DD"}
        datestamp = date.replace("-", "")
        path = f"/var/log/{log}/{log}_{datestamp}.log"

    try:
        ctx = _make_context()
        r = ctx["ssh"].opnsense(f"tail -n {lines} {path}")
        return {
            "log": log,
            "path": path,
            "lines_requested": lines,
            "stdout": r.stdout,
            "stderr": r.stderr,
            "exit_code": r.returncode,
        }
    except Exception as e:
        return {"error": str(e), "detail": traceback.format_exc()}


@mcp.tool()
async def dns_configs(service: str = "all") -> dict[str, Any]:
    """Return raw on-disk config files for DNS/DHCP services on OPNsense.

    Reads config files via SSH and returns their contents as strings.
    ``service`` selects which configs to fetch:
      - ``kea``      — Kea DHCPv4 + DDNS config files
      - ``bind``     — BIND named.conf + all zone files under /usr/local/etc/namedb/
      - ``unbound``  — Unbound unbound.conf
      - ``dnsmasq``  — dnsmasq.conf (if installed)
      - ``all``      — all of the above (default)

    Use this to inspect actual running config rather than API abstractions —
    useful for debugging DDNS, zone delegation, or resolver behaviour.
    Read-only — no side effects.
    """
    _KEA_FILES = [
        "/usr/local/etc/kea/kea-dhcp4.conf",
        "/usr/local/etc/kea/kea-dhcp-ddns.conf",
        "/usr/local/etc/kea/kea-ctrl-agent.conf",
    ]
    _BIND_CONF = "/usr/local/etc/namedb/named.conf"
    _BIND_DIR = "/usr/local/etc/namedb"
    _UNBOUND_FILES = [
        "/var/unbound/unbound.conf",
        "/usr/local/etc/unbound/unbound.conf",
    ]
    _DNSMASQ_FILES = [
        "/var/etc/dnsmasq.conf",
        "/usr/local/etc/dnsmasq.conf",
    ]

    def _read(ssh: SSHClient, path: str) -> dict[str, Any]:
        r = ssh.opnsense(f"cat {path}")
        if r.returncode == 0:
            return {"path": path, "content": r.stdout}
        return {"path": path, "error": r.stderr.strip() or f"exit {r.returncode}"}

    def _read_first(ssh: SSHClient, paths: list[str]) -> dict[str, Any]:
        for p in paths:
            r = ssh.opnsense(f"cat {p}")
            if r.returncode == 0:
                return {"path": p, "content": r.stdout}
        return {"paths_tried": paths, "error": "not found"}

    try:
        ctx = _make_context()
        ssh = ctx["ssh"]
        result: dict[str, Any] = {}
        want = service.lower()

        if want in ("kea", "all"):
            result["kea"] = [_read(ssh, p) for p in _KEA_FILES]

        if want in ("bind", "all"):
            named = _read(ssh, _BIND_CONF)
            result["bind"] = {"named_conf": named, "zones": {}}
            zone_list_r = ssh.opnsense(f"find {_BIND_DIR} -name '*.zone' -o -name '*.conf' -o -name '*.db' | sort")
            if zone_list_r.returncode == 0:
                for zpath in zone_list_r.stdout.splitlines():
                    zpath = zpath.strip()
                    if zpath and zpath != _BIND_CONF:
                        zr = ssh.opnsense(f"cat {zpath}")
                        result["bind"]["zones"][zpath] = zr.stdout if zr.returncode == 0 else f"error: {zr.stderr.strip()}"

        if want in ("unbound", "all"):
            result["unbound"] = _read_first(ssh, _UNBOUND_FILES)

        if want in ("dnsmasq", "all"):
            result["dnsmasq"] = _read_first(ssh, _DNSMASQ_FILES)

        return result
    except Exception as e:
        return {"error": str(e), "detail": traceback.format_exc()}


@mcp.tool()
async def hw_sensors() -> dict[str, Any]:
    """Read hardware sensor data from OPNsense via sysctl.

    Returns CPU temperatures (per-core if coretemp loaded), ACPI thermal zones,
    CPU time breakdown (idle/user/sys), and memory page stats.
    Read-only — no side effects.
    """
    syctls = [
        "dev.cpu",
        "hw.acpi.thermal",
        "kern.cp_time",
        "kern.cp_times",
        "vm.stats.vm.v_free_count",
        "vm.stats.vm.v_page_count",
        "hw.physmem",
    ]
    try:
        ctx = _make_context()
        out: dict[str, Any] = {}
        for key in syctls:
            r = ctx["ssh"].opnsense(f"sysctl {key}")
            if r.returncode == 0 and r.stdout.strip():
                for line in r.stdout.strip().splitlines():
                    if ": " in line:
                        k, v = line.split(": ", 1)
                        out[k.strip()] = v.strip()
        mem_free = int(out.get("vm.stats.vm.v_free_count", 0))
        mem_total = int(out.get("vm.stats.vm.v_page_count", 1))
        phys = int(out.get("hw.physmem", 0))
        out["_summary"] = {
            "ram_total_gb": round(phys / 1024**3, 1),
            "ram_free_pct": round(100 * mem_free / mem_total, 1) if mem_total else None,
        }
        return out
    except Exception as e:
        return {"error": str(e), "detail": traceback.format_exc()}


@mcp.tool()
async def list_packages(filter_type: str = "all") -> dict[str, Any]:
    """List installed packages and OPNsense plugins.

    Runs ``pkg info`` on OPNsense via SSH and parses the output into
    categorized groups. ``filter_type`` accepts: ``all``, ``plugins``
    (os-* only), ``opnsense`` (opnsense-* packages), ``base`` (everything else).
    Returns each package's name, version, and description.
    Read-only — no side effects.
    """
    try:
        ctx = _make_context()
        r = ctx["ssh"].opnsense("pkg info")
        if r.returncode != 0:
            return {"error": r.stderr or "pkg info failed"}

        plugins, opnsense_pkgs, base = [], [], []
        for line in r.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            parts = line.split(None, 1)
            full_name = parts[0]
            description = parts[1].strip() if len(parts) > 1 else ""
            # split name-version on last hyphen+digit boundary
            hyphen = full_name.rfind("-")
            name = full_name[:hyphen] if hyphen != -1 else full_name
            version = full_name[hyphen + 1:] if hyphen != -1 else ""
            entry = {"name": name, "version": version, "description": description}
            if name.startswith("os-"):
                plugins.append(entry)
            elif name.startswith("opnsense"):
                opnsense_pkgs.append(entry)
            else:
                base.append(entry)

        result: dict[str, Any] = {
            "counts": {
                "plugins": len(plugins),
                "opnsense": len(opnsense_pkgs),
                "base": len(base),
                "total": len(plugins) + len(opnsense_pkgs) + len(base),
            }
        }
        if filter_type in ("all", "plugins"):
            result["plugins"] = sorted(plugins, key=lambda x: x["name"])
        if filter_type in ("all", "opnsense"):
            result["opnsense"] = sorted(opnsense_pkgs, key=lambda x: x["name"])
        if filter_type in ("all", "base"):
            result["base"] = sorted(base, key=lambda x: x["name"])
        return result
    except Exception as e:
        return {"error": str(e), "detail": traceback.format_exc()}


@mcp.tool()
async def shell_run(command: str) -> dict[str, Any]:
    """Execute a read-only command on OPNsense via SSH (allowlisted).

    Allowed commands: ``hostname``, ``uptime``, ``uname -a``, ``df -h``,
    ``free -m``, ``netstat``, ``pkg info``, ``pkg version``,
    ``service -e``, ``sysctl``, ``pfctl -ss``, ``pfctl -si``, ``pfctl -sr``,
    ``pftop``, ``curl``, ``ls``, ``grep``, ``cat``, ``head``, ``tail``
    (and any command starting with one of these).
    Returns stdout, stderr, and exit code.

    Read-only — no side effects. For quick system checks without
    calling individual diagnostic tools.
    """
    try:
        ctx = _make_context()

        allowed = [
            "hostname", "uptime", "uname -a", "df -h", "free -m", "netstat",
            "pkg info", "pkg version", "service -e", "sysctl",
            "pfctl -ss", "pfctl -si", "pfctl -sr", "pftop",
            "curl", "ls", "grep", "cat", "head", "tail",
        ]
        if command not in allowed and not any(command.startswith(p) for p in allowed):
            raise ValueError(f"Command '{command}' is not allowlisted. Allowed: {allowed}")

        r = ctx["ssh"].opnsense(command)
        return {"stdout": r.stdout, "stderr": r.stderr, "exit_code": r.returncode}
    except Exception as e:
        return {"error": str(e), "detail": traceback.format_exc()}


# ------------------------------------------------------------------
# Resources
# ------------------------------------------------------------------


@mcp.resource("opnsense://config")
async def config_summary() -> str:
    """Sanitized config summary — VLANs defined, no secrets."""
    ctx = _make_context()
    settings: Settings = ctx["settings"]
    import json

    vlans = [{"id": v.id, "name": v.name, "iface": v.iface} for v in settings.network.vlans]
    return json.dumps(
        {
            "opnsense_host": settings.opnsense.host,
            "lan_iface": settings.network.lan_iface,
            "wan_iface": settings.network.wan_iface,
            "vlans": vlans,
            "is_test": settings.is_test,
            "has_mt6000": settings.has_mt6000(),
            "config_source": _config_source(),
            "ssh_mode": _ssh_mode(),
        },
        indent=2,
    )


@mcp.resource("opnsense://vlans")
async def vlan_definitions() -> str:
    """VLAN definitions from settings."""
    ctx = _make_context()
    settings: Settings = ctx["settings"]
    import json

    vlans = [{"id": v.id, "name": v.name, "iface": v.iface} for v in settings.network.vlans]
    return json.dumps(vlans, indent=2)


@mcp.resource("opnsense://health/last")
async def last_health_run() -> str:
    """Most recent health run results."""
    ctx = _make_context()
    import json

    runs = ctx["db"].recent_runs(limit=1)
    if runs:
        run_id = runs[0]["id"]
        checks = ctx["db"].checks_for_run(run_id)
        return json.dumps({"run_id": run_id, "ts": runs[0]["ts"], "checks": checks, "instance_id": ctx["instance_id"]}, indent=2)
    return json.dumps({"message": "No health runs found"}, indent=2)


# ------------------------------------------------------------------
# Entry point
# ------------------------------------------------------------------


def run() -> None:
    """Entry point for opn-mcp script."""
    mcp.run(transport="stdio")
