"""VLAN service — list and add VLANs."""

from __future__ import annotations

from ..opnsense import OPNsenseClient


def list_vlans(opn: OPNsenseClient) -> list[dict]:
    """List configured VLANs."""
    rows = opn.list_vlans()
    return [{"tag": v.get("tag"), "interface": v.get("vlanif"), "description": v.get("descr", "")} for v in rows]


def add_vlan(opn: OPNsenseClient, tag: int, interface: str = "igc0", description: str = "") -> dict:
    """Add a VLAN.

    Args:
        tag: 802.1Q VLAN ID (1-4094).
        interface: Parent interface.
        description: VLAN description.

    Returns:
        Dict with saved status, tag, interface, and API response.
    """
    r = opn.add_vlan(tag=tag, interface=interface, description=description)
    saved = r.get("result") in ("saved", "created") or bool(r.get("uuid"))
    return {"saved": saved, "tag": tag, "interface": interface, "response": r}
