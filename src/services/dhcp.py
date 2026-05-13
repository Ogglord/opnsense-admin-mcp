"""DHCP service — reservations, subnets, Kea DDNS management."""

from __future__ import annotations

import ipaddress

from ..models import KeaSubnet, Settings
from ..opnsense import OPNsenseClient
from ..ssh import SSHClient
from .utils import reverse_zone_name


def add_reservation(
    opn: OPNsenseClient,
    mac: str,
    ip: str,
    hostname: str = "",
    description: str = "",
) -> dict:
    """Add a static DHCP reservation. Finds the subnet automatically from the IP.

    Args:
        mac: MAC address for the reservation.
        ip: IP address to reserve.
        hostname: Optional hostname.
        description: Optional description.

    Returns:
        Dict with saved status, API response, and reconfigure result.

    Raises:
        ValueError: If no Kea subnet contains the given IP.
    """
    addr = ipaddress.ip_address(ip)

    subnets = opn.kea_subnets()
    subnet = next(
        (s for s in subnets if addr in ipaddress.ip_network(s.subnet)),
        None,
    )
    if not subnet:
        raise ValueError(f"No Kea subnet found for {ip}")

    r = opn.kea_add_reservation(
        subnet_uuid=subnet.uuid,
        ip_address=ip,
        hw_address=mac,
        hostname=hostname,
        description=description,
    )

    reconfigure_result = None
    if r.get("result") == "saved":
        rc = opn.kea_reconfigure()
        reconfigure_result = rc.get("status")

    return {
        "saved": r.get("result") == "saved",
        "api_response": r,
        "reconfigure": reconfigure_result,
        "subnet": subnet.subnet,
        "subnet_uuid": subnet.uuid,
    }


def list_subnets(opn: OPNsenseClient) -> list[KeaSubnet]:
    """List configured Kea subnets."""
    return opn.kea_subnets()


def add_subnet(opn: OPNsenseClient, cidr: str, description: str = "") -> dict:
    """Add a Kea DHCP subnet.

    Args:
        cidr: Subnet in CIDR notation, e.g. 10.10.10.0/24.
        description: Optional description.

    Returns:
        API response dict.

    Raises:
        ValueError: If cidr is invalid.
    """
    try:
        ipaddress.ip_network(cidr, strict=False)
    except ValueError as e:
        raise ValueError(f"Invalid CIDR: {cidr}") from e
    return opn.kea_add_subnet(cidr, description=description)


def setup_ddns(
    opn: OPNsenseClient,
    ssh: SSHClient,
    settings: Settings,
    dns_server: str = "127.0.0.1",
    dns_port: int = 53530,
    forward_zone: str = "home.arpa",
) -> dict:
    """Configure Kea DDNS on all subnets and enable the kea-dhcp-ddns daemon.

    Args:
        dns_server: DNS server IP for DDNS updates.
        dns_port: DNS server port for DDNS updates.
        forward_zone: Forward zone name.

    Returns:
        Dict with subnet results, daemon status, and reconfigure status.

    Raises:
        RuntimeError: If TSIG key cannot be read from BIND.
    """
    tsig = opn.bind_tsig_key(ssh)
    if not tsig:
        raise RuntimeError("Could not read rndc-key from BIND named.conf")

    subnets = opn.kea_subnets()
    results = []

    for subnet in subnets:
        cidr = subnet.subnet
        uuid = subnet.uuid

        try:
            ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            continue

        reverse_zone = reverse_zone_name(cidr)

        r = opn.kea_set_subnet_ddns(
            uuid=uuid,
            forward_zone=forward_zone,
            reverse_zone=reverse_zone,
            dns_server=dns_server,
            dns_port=dns_port,
            key_name=tsig["name"],
            key_secret=tsig["secret"],
            key_algorithm=tsig["algorithm"],
            qualifying_suffix=forward_zone,
        )
        saved = r.get("result") == "saved"
        results.append({"subnet": cidr, "reverse_zone": reverse_zone, "saved": saved, "response": r})

    dr = opn.kea_enable_ddns(server_ip=dns_server)
    daemon_ok = dr.get("result") == "saved"
    rc = opn.kea_reconfigure()
    rc_ok = rc.get("status") == "ok"

    return {"subnets": results, "daemon_enabled": daemon_ok, "reconfigure": rc_ok}


def get_ddns_status(opn: OPNsenseClient) -> dict:
    """Show DDNS daemon status and per-subnet DDNS configuration."""
    subnets = opn.kea_subnets()
    ddns_cfg = opn.kea_ddns_get().get("ddns", {}).get("general", {})
    return {
        "daemon": ddns_cfg,
        "subnets": [
            {
                "subnet": s.subnet,
                "forward_zone": s.ddns_forward_zone,
                "reverse_zone": s.ddns_reverse_zone,
                "dns_server": s.ddns_dns_server,
                "dns_port": s.ddns_dns_port,
                "key_name": s.ddns_domain_key_name,
            }
            for s in subnets
        ],
    }
