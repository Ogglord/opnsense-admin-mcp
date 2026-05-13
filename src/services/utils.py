"""Shared helpers for service modules."""

from __future__ import annotations


def reverse_zone_name(subnet: str) -> str:
    """Compute correct in-addr.arpa zone name from a CIDR subnet.

    Args:
        subnet: A CIDR subnet string, e.g. ``10.10.10.0/24``.

    Returns:
        Reverse zone name, e.g. ``10.10.10.in-addr.arpa``.
    """
    import ipaddress

    net = ipaddress.ip_network(subnet, strict=False)
    octets = str(net.network_address).split(".")
    prefix = net.prefixlen
    if prefix <= 8:
        parts = octets[:1]
    elif prefix <= 16:
        parts = octets[:2]
    elif prefix <= 24:
        parts = octets[:3]
    else:
        parts = octets[:4]
    return ".".join(reversed(parts)) + ".in-addr.arpa"
