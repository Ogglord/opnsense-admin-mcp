"""Status service — combined system status, leases, and reservations."""

from __future__ import annotations

import time

from ..models import Settings
from ..opnsense import OPNsenseClient


def get_full_status(opn: OPNsenseClient) -> dict:
    """Show status of key services (Kea, Unbound, BIND) and gateway.

    Returns:
        Dict with services, gateways, bind_zones, and bind_records.
    """
    data: dict = {"services": {}, "gateways": [], "bind_zones": [], "bind_records": []}

    for label, key, fn in [
        ("Kea DHCPv4", "kea", opn.kea_status),
        ("Unbound DNS", "unbound", opn.unbound_status),
        ("BIND", "bind", opn.bind_status),
    ]:
        try:
            resp = fn()
            st = resp.get("status", "unknown") if isinstance(resp, dict) else "unknown"
            data["services"][key] = {"label": label, "status": st}
        except Exception as e:
            data["services"][key] = {"label": label, "status": "error", "error": str(e)}

    try:
        for gw in opn.gateway_status():
            data["gateways"].append(
                {
                    "name": gw.name,
                    "status": gw.status_translated,
                    "loss": gw.loss,
                    "rtt": gw.delay,
                }
            )
    except Exception as e:
        data["gateways"] = [{"error": str(e)}]

    try:
        zones = opn.bind_zones()
        data["bind_zones"] = [{"uuid": z.uuid, "name": z.domainname, "enabled": z.enabled} for z in zones]
        for zone in zones:
            for rec in opn.bind_records(zone.uuid):
                data["bind_records"].append(
                    {
                        "zone": zone.domainname,
                        "name": rec.name,
                        "type": rec.type,
                        "value": rec.value,
                        "uuid": rec.uuid,
                    }
                )
    except Exception as e:
        data["bind_zones"] = [{"error": str(e)}]

    return data


def get_leases(opn: OPNsenseClient, vlan: int | None = None, settings: Settings | None = None) -> list[dict]:
    """Show all active Kea DHCP leases, optionally filtered by VLAN.

    Args:
        vlan: Optional VLAN ID to filter by.
        settings: Settings object needed for VLAN interface name lookup.

    Returns:
        List of lease dicts with ip, mac, hostname, vlan, reserved, expires_in_seconds.
    """
    rows = opn.kea_leases()
    if vlan and settings:
        vlan_if = settings.network.vlan_iface(vlan)
        rows = [r for r in rows if r.iface == vlan_if]

    now = int(time.time())
    return [
        {
            "ip": row.address,
            "mac": row.hwaddr,
            "hostname": row.hostname,
            "vlan": row.if_descr or row.iface,
            "reserved": row.is_reserved,
            "expires_in_seconds": max(0, row.expire - now),
        }
        for row in rows
    ]


def get_reservations(opn: OPNsenseClient) -> list[dict]:
    """Show all Kea DHCP host reservations.

    Returns:
        List of reservation dicts with ip, mac, hostname, subnet, description.
    """
    rows = opn.kea_reservations()
    return [
        {
            "ip": r.ip_address,
            "mac": r.hw_address,
            "hostname": r.hostname,
            "subnet": r.subnet,
            "description": r.description,
        }
        for r in rows
    ]
