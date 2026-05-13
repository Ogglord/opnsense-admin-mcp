"""DNS service — Unbound forward zones, BIND zones/records, dig queries."""

from __future__ import annotations

from ..models import Settings
from ..opnsense import OPNsenseClient
from ..ssh import SSHClient
from .utils import reverse_zone_name

# ------------------------------------------------------------------
# Unbound
# ------------------------------------------------------------------


def list_unbound_forwards(opn: OPNsenseClient) -> list[dict]:
    """List Unbound forward zones."""
    rows = opn.unbound_forwards()
    return [
        {
            "uuid": r.uuid,
            "domain": r.domain,
            "server": r.server,
            "port": r.port,
            "enabled": r.enabled,
        }
        for r in rows
    ]


def add_unbound_forward(opn: OPNsenseClient, domain: str, server: str, port: int = 53530, reconfigure: bool = True) -> dict:
    """Add a forward zone to Unbound.

    Args:
        domain: Domain to forward.
        server: DNS server to forward to.
        port: DNS server port.
        reconfigure: Whether to reload Unbound after adding.

    Returns:
        Dict with saved status, domain, and reconfigure result.

    Raises:
        RuntimeError: If the API call fails to save.
    """
    r = opn.unbound_add_forward(domain, server, port)
    saved = bool(r.get("uuid")) or r.get("result") in ("saved", "created")
    if not saved:
        raise RuntimeError(f"Failed to add Unbound forward for {domain}")
    rc_ok = False
    if reconfigure:
        rc = opn.unbound_reconfigure()
        rc_ok = rc.get("status") == "ok"
    return {"saved": saved, "domain": domain, "reconfigure": rc_ok, "response": r}


def del_unbound_forward(opn: OPNsenseClient, uuid: str) -> dict:
    """Delete a forward zone by UUID.

    Args:
        uuid: UUID of the forward zone to delete.

    Returns:
        Dict with deleted status and API response.
    """
    r = opn.unbound_del_forward(uuid)
    return {"deleted": r.get("result") == "deleted", "response": r}


def setup_bind_forwarding(
    opn: OPNsenseClient,
    bind_server: str = "127.0.0.1",
    bind_port: int = 53530,
    forward_zone: str = "home.arpa",
) -> dict:
    """Add Unbound forward zones pointing to BIND for all internal zones.

    Args:
        bind_server: BIND server IP.
        bind_port: BIND server port.
        forward_zone: Primary forward zone name.

    Returns:
        Dict with zone results and reconfigure status.
    """
    zones = [forward_zone]
    for subnet in opn.kea_subnets():
        cidr = subnet.subnet
        if cidr:
            zones.append(reverse_zone_name(cidr))
    zones = sorted(set(zones))

    results = []
    for zone in zones:
        r = opn.unbound_add_forward(zone, bind_server, bind_port)
        saved = bool(r.get("uuid")) or r.get("result") in ("saved", "created")
        results.append({"zone": zone, "saved": saved})

    rc = opn.unbound_reconfigure()
    rc_ok = rc.get("status") == "ok"
    return {"zones": results, "reconfigure": rc_ok}


def disable_dhcp_registration(opn: OPNsenseClient) -> dict:
    """Disable Unbound's built-in DHCP hostname registration.

    Returns:
        Dict with saved status and reconfigure result.

    Raises:
        RuntimeError: If the API call fails.
    """
    r = opn.unbound_set_general(regdhcp="0", regdhcpstatic="0")
    saved = r.get("result") in ("saved", "updated", "ok") or bool(r.get("uuid"))
    rc = opn.unbound_reconfigure()
    rc_ok = rc.get("status") == "ok"
    return {"saved": saved, "reconfigure": rc_ok}


# ------------------------------------------------------------------
# BIND
# ------------------------------------------------------------------


def list_bind_zones(opn: OPNsenseClient) -> list[dict]:
    """List primary zones configured in BIND."""
    zones = opn.bind_zones()
    return [{"uuid": z.uuid, "name": z.domainname, "enabled": z.enabled} for z in zones]


def add_bind_zone(
    opn: OPNsenseClient,
    ssh: SSHClient,
    settings: Settings,
    name: str,
    ns_host: str | None = None,
) -> dict:
    """Add a primary zone to BIND with DDNS via rndc-key enabled and NS auto-added.

    Args:
        name: Zone name (or reverse zone if using --from-subnet equivalent).
        ns_host: NS record value (default: OPNsense FQDN from hostname).

    Returns:
        Dict with saved status, zone name, UUID, and NS record result.

    Raises:
        RuntimeError: If zone creation fails.
    """
    if not ns_host:
        ns_host = opn.system_fqdn(ssh)

    r = opn.bind_add_zone(name)
    saved = r.get("result") in ("saved", "created") or bool(r.get("uuid"))
    if not saved:
        raise RuntimeError(f"Failed to add BIND zone {name}")

    zone_uuid = r.get("uuid", "")
    ns_r = opn.bind_add_record(zone_uuid, "@", "NS", ns_host)
    ns_saved = ns_r.get("result") in ("saved", "created") or bool(ns_r.get("uuid"))
    return {"saved": saved, "name": name, "uuid": zone_uuid, "ns_added": ns_saved, "response": r}


def list_bind_records(opn: OPNsenseClient, zone: str | None = None) -> list[dict]:
    """List DNS records in BIND, optionally filtered by zone name.

    Args:
        zone: Optional zone name filter.

    Raises:
        ValueError: If zone name is provided but not found.
    """
    domain_uuid: str | None = None
    if zone:
        zones = opn.bind_zones()
        match = next((z for z in zones if z.domainname == zone), None)
        if not match:
            raise ValueError(f"Zone '{zone}' not found")
        domain_uuid = match.uuid

    records = opn.bind_records(domain_uuid)
    return [
        {
            "uuid": r.uuid,
            "zone": r.domain,
            "name": r.name,
            "type": r.type,
            "value": r.value,
        }
        for r in records
    ]


def add_bind_record(opn: OPNsenseClient, zone: str, name: str, rtype: str, value: str) -> dict:
    """Add a DNS record to a BIND zone.

    Args:
        zone: Zone name.
        name: Record name.
        rtype: Record type (A, AAAA, CNAME, etc.).
        value: Record value.

    Returns:
        Dict with saved status and API response.

    Raises:
        ValueError: If zone is not found.
    """
    zones = opn.bind_zones()
    match = next((z for z in zones if z.domainname == zone), None)
    if not match:
        raise ValueError(f"Zone '{zone}' not found")

    r = opn.bind_add_record(match.uuid, name, rtype.upper(), value)
    return {"saved": r.get("result") in ("saved", "created") or bool(r.get("uuid")), "response": r}


def del_bind_zone(opn: OPNsenseClient, name: str) -> dict:
    """Delete a primary zone and all its records by zone name.

    Args:
        name: Zone name.

    Returns:
        Dict with deleted status and API response.

    Raises:
        ValueError: If zone is not found.
    """
    zones = opn.bind_zones()
    match = next((z for z in zones if z.domainname == name), None)
    if not match:
        raise ValueError(f"Zone '{name}' not found")

    r = opn.bind_del_zone(match.uuid)
    return {"deleted": r.get("result") == "deleted", "response": r}


def del_bind_record(opn: OPNsenseClient, uuid: str) -> dict:
    """Delete a DNS record by UUID.

    Args:
        uuid: Record UUID.

    Returns:
        Dict with deleted status and API response.
    """
    r = opn.bind_del_record(uuid)
    return {"deleted": r.get("result") == "deleted", "response": r}


# ------------------------------------------------------------------
# dig
# ------------------------------------------------------------------


def run_dig(ssh: SSHClient, settings: Settings, name: str, server: str = "127.0.0.1", port: int = 53, rtype: str = "A") -> str:
    """Run a DNS query on OPNsense via SSH.

    Args:
        name: Name to query.
        server: DNS server to query.
        port: DNS server port.
        rtype: Record type (A, AAAA, MX, etc.).

    Returns:
        Raw dig output as a string.
    """
    r = ssh.opnsense(f"dig @{server} -p {port} {name} {rtype}")
    output = r.stdout
    if r.stderr:
        output += "\n" + r.stderr
    if not r.ok:
        raise RuntimeError(f"dig failed (exit {r.returncode}): {r.stderr[:200]}")
    return output
