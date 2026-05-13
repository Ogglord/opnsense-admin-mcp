"""Network topology discovery: nodes, VLANs, interfaces, gateways.

Merges ARP table (SSH) with DHCP leases and reservations (API).
Resolves OUI manufacturer for each MAC address via the bundled manuf database.
"""

from __future__ import annotations

import re
from typing import Any

from ..opnsense import OPNsenseClient
from ..ssh import SSHClient

_mac_parser: Any = None


def _get_mac_parser() -> Any:
    global _mac_parser
    if _mac_parser is None:
        from manuf import manuf as manuf_lib

        _mac_parser = manuf_lib.MacParser()
    return _mac_parser


def _lookup_manufacturer(mac: str) -> str:
    try:
        result = _get_mac_parser().get_manuf(mac)
        return result or ""
    except Exception:
        return ""


def _parse_arp(arp_output: str) -> list[dict[str, str]]:
    """Parse BSD `arp -an` output into list of {ip, mac} dicts."""
    nodes = []
    for line in arp_output.splitlines():
        m = re.search(r"\((\d+\.\d+\.\d+\.\d+)\) at ([0-9a-f:]{17})", line, re.IGNORECASE)
        if m:
            nodes.append({"ip": m.group(1), "mac": m.group(2).lower()})
    return nodes


def discover(opn: OPNsenseClient, ssh: SSHClient) -> dict[str, Any]:
    """Discover network topology. Returns nodes, vlans, interfaces, gateways.

    Node sources (priority high→low): reservation > lease > arp-only.
    Each node has: ip, mac, hostname, manufacturer, source, description.
    """
    errors: dict[str, str] = {}

    # -- ARP table --
    try:
        arp_result = ssh.opnsense("arp -an")
        if arp_result.ok:
            arp_nodes = _parse_arp(arp_result.stdout)
        else:
            errors["arp"] = arp_result.stderr or "command failed"
            arp_nodes = []
    except Exception as e:
        errors["arp"] = str(e)
        arp_nodes = []

    # -- DHCP leases --
    try:
        leases = [
            {"ip": l.address, "mac": l.hwaddr.lower(), "hostname": l.hostname, "iface": l.if_descr}
            for l in opn.kea_leases()
            if l.hwaddr
        ]
    except Exception as e:
        errors["leases"] = str(e)
        leases = []

    # -- DHCP reservations (static — authoritative) --
    try:
        reservations = [
            {"ip": r.ip_address, "mac": r.hw_address.lower(), "hostname": r.hostname, "description": r.description}
            for r in opn.kea_reservations()
            if r.hw_address
        ]
    except Exception as e:
        errors["reservations"] = str(e)
        reservations = []

    # -- Merge by MAC, priority: reservation > lease > arp --
    by_mac: dict[str, dict[str, Any]] = {}

    for n in arp_nodes:
        mac = n["mac"]
        by_mac[mac] = {"ip": n["ip"], "mac": mac, "hostname": "", "description": "", "source": "arp"}

    for l in leases:
        mac = l["mac"]
        existing = by_mac.get(mac, {})
        by_mac[mac] = {
            "ip": l["ip"] or existing.get("ip", ""),
            "mac": mac,
            "hostname": l["hostname"] or existing.get("hostname", ""),
            "description": existing.get("description", ""),
            "source": "lease",
        }

    for r in reservations:
        mac = r["mac"]
        existing = by_mac.get(mac, {})
        by_mac[mac] = {
            "ip": r["ip"] or existing.get("ip", ""),
            "mac": mac,
            "hostname": r["hostname"] or existing.get("hostname", ""),
            "description": r["description"] or "",
            "source": "reservation",
        }

    # -- OUI lookup --
    nodes = []
    for node in by_mac.values():
        node["manufacturer"] = _lookup_manufacturer(node["mac"])
        nodes.append(node)

    nodes.sort(key=lambda n: n["ip"])

    # -- VLANs --
    try:
        def _selected_iface(iface_field: Any) -> str:
            if isinstance(iface_field, dict):
                return next((k for k, v in iface_field.items() if isinstance(v, dict) and v.get("selected") == 1), "")
            return iface_field or ""

        vlans = [
            {"tag": v.get("tag", ""), "interface": _selected_iface(v.get("if", "")), "description": v.get("descr", "")}
            for v in opn.list_vlans()
        ]
    except Exception as e:
        errors["vlans"] = str(e)
        vlans = []

    # -- Interfaces --
    try:
        interfaces = [
            {"name": i.name, "identifier": i.identifier, "status": i.status, "ipv4": i.ipv4}
            for i in opn.interface_overview()
        ]
    except Exception as e:
        errors["interfaces"] = str(e)
        interfaces = []

    # -- Gateways --
    try:
        gateways = [
            {"name": g.name, "status": g.status_translated, "loss": g.loss, "delay": g.delay}
            for g in opn.gateway_status()
        ]
    except Exception as e:
        errors["gateways"] = str(e)
        gateways = []

    return {
        "nodes": nodes,
        "vlans": vlans,
        "interfaces": interfaces,
        "gateways": gateways,
        **({"errors": errors} if errors else {}),
    }


def detect_drift(current: dict[str, Any], previous: dict[str, Any]) -> list[dict[str, str]]:
    """Compare two topology snapshots. Returns list of drift events."""
    drift = []

    prev_macs = {n["mac"] for n in previous.get("nodes", [])}
    curr_macs = {n["mac"] for n in current.get("nodes", [])}

    for n in current["nodes"]:
        if n["mac"] not in prev_macs:
            label = n["hostname"] or n["manufacturer"] or n["mac"]
            drift.append({"event": "node_appeared", "detail": f"{label} ({n['ip']})"})

    for n in previous.get("nodes", []):
        if n["mac"] not in curr_macs:
            label = n["hostname"] or n["manufacturer"] or n["mac"]
            drift.append({"event": "node_disappeared", "detail": f"{label} ({n['ip']})"})

    prev_vlans = {v["tag"] for v in previous.get("vlans", [])}
    curr_vlans = {v["tag"] for v in current.get("vlans", [])}

    for tag in curr_vlans - prev_vlans:
        drift.append({"event": "vlan_appeared", "detail": f"VLAN {tag}"})
    for tag in prev_vlans - curr_vlans:
        drift.append({"event": "vlan_disappeared", "detail": f"VLAN {tag}"})

    return drift
