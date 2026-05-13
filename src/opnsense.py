"""OPNsense REST API client.

Talks directly to the OPNsense REST API using requests + basic auth.
Covers DHCP (Kea), VLANs, interfaces, firewall, DNS (Unbound/BIND),
and system diagnostics.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

import urllib3

from .models import (
    BindRecord,
    BindZone,
    GatewayStatus,
    InterfaceInfo,
    KeaLease,
    KeaReservation,
    KeaSubnet,
    Settings,
    UnboundForward,
)

urllib3.disable_warnings()

import requests  # noqa: E402

if TYPE_CHECKING:
    from .ssh import SSHClient


class OPNsenseClient:
    """OPNsense API client for homelab automation."""

    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._auth = (settings.opnsense.key, settings.opnsense.secret)
        self._active_base: str | None = None

    # ------------------------------------------------------------------
    # Host resolution (tries configured hosts in order, caches winner)
    # ------------------------------------------------------------------

    def _resolve_base(self) -> str:
        if self._active_base:
            return self._active_base
        for host in self._settings.opnsense.hosts:
            base = host.rstrip("/")
            if not base.startswith(("http://", "https://")):
                base = "https://" + base
            try:
                r = requests.get(
                    f"{base}/api/core/system/status",
                    auth=self._auth,
                    verify=False,
                    timeout=5,
                )
                if r.status_code < 500:
                    self._active_base = base
                    return base
            except Exception:
                continue
        # fall back to primary
        base = self._settings.opnsense.host.rstrip("/")
        if not base.startswith(("http://", "https://")):
            base = "https://" + base
        self._active_base = base
        return self._active_base

    @property
    def active_host(self) -> str:
        """Return the currently resolved API host (strips scheme)."""
        return self._resolve_base().replace("http://", "").replace("https://", "")

    # ------------------------------------------------------------------
    # HTTP helpers (internal)
    # ------------------------------------------------------------------

    def _get(self, endpoint: str, params: dict | None = None) -> Any:
        r = requests.get(
            f"{self._resolve_base()}{endpoint}",
            auth=self._auth,
            verify=False,
            timeout=15,
            params=params or {},
        )
        r.raise_for_status()
        return r.json()

    def _post(self, endpoint: str, data: dict | None = None) -> Any:
        r = requests.post(
            f"{self._resolve_base()}{endpoint}",
            auth=self._auth,
            verify=False,
            timeout=15,
            json=data or {},
        )
        r.raise_for_status()
        return r.json()

    # ------------------------------------------------------------------
    # System
    # ------------------------------------------------------------------

    def system_status(self) -> dict:
        return self._get("/api/core/system/status")

    def is_alive(self) -> bool:
        try:
            data = self.system_status()
            meta = data.get("metadata", data)
            sys_info = meta.get("system", {})
            return isinstance(sys_info, dict) and "status" in sys_info
        except Exception:
            return False

    # ------------------------------------------------------------------
    # Interfaces
    # ------------------------------------------------------------------

    def interface_overview(self) -> list[InterfaceInfo]:
        data = self._get("/api/interfaces/overview/export")
        rows = data if isinstance(data, list) else data.get("rows", [])
        return [InterfaceInfo(**entry) for entry in rows]

    # ------------------------------------------------------------------
    # VLANs
    # ------------------------------------------------------------------

    def list_vlans(self) -> list[dict]:
        data = self._get("/api/interfaces/vlan_settings/get")
        inner = data.get("vlan", {}).get("vlan", {})
        items = list(inner.values()) if isinstance(inner, dict) else inner
        if not items and isinstance(inner, dict):
            item = inner.get("item")
            if item:
                items = item if isinstance(item, list) else [item]
        return items

    def add_vlan(self, tag: int, interface: str = "igc0", description: str = "") -> dict:
        return self._post(
            "/api/interfaces/vlan_settings/addItem",
            {
                "vlan": {
                    "if": interface,
                    "tag": str(tag),
                    "descr": description,
                    "pcp": "0",
                }
            },
        )

    # ------------------------------------------------------------------
    # Kea DHCP
    # ------------------------------------------------------------------

    def kea_status(self) -> dict:
        return self._get("/api/kea/service/status")

    def kea_leases(self) -> list[KeaLease]:
        data = self._get("/api/kea/leases4/search")
        raw = data.get("rows", [])
        return [KeaLease(**r) for r in raw]

    def kea_reservations(self) -> list[KeaReservation]:
        data = self._get("/api/kea/dhcpv4/searchReservation")
        raw = data.get("rows", [])
        return [KeaReservation(**r) for r in raw]

    def kea_subnets(self) -> list[KeaSubnet]:
        data = self._get("/api/kea/dhcpv4/searchSubnet")
        raw = data.get("rows", [])
        return [KeaSubnet(**r) for r in raw]

    def kea_add_subnet(self, cidr: str, description: str = "") -> dict:
        return self._post(
            "/api/kea/dhcpv4/addSubnet",
            {
                "subnet4": {
                    "subnet": cidr,
                    "description": description,
                }
            },
        )

    def kea_add_reservation(
        self,
        subnet_uuid: str,
        ip_address: str,
        hw_address: str,
        hostname: str = "",
        description: str = "",
    ) -> dict:
        return self._post(
            "/api/kea/dhcpv4/addReservation",
            {
                "reservation": {
                    "subnet": subnet_uuid,
                    "ip_address": ip_address,
                    "hw_address": hw_address,
                    "hostname": hostname,
                    "description": description,
                }
            },
        )

    def kea_reconfigure(self) -> dict:
        return self._post("/api/kea/service/reconfigure", {})

    def kea_ddns_get(self) -> dict:
        return self._get("/api/kea/ddns/get")

    def kea_set_subnet_ddns(
        self,
        uuid: str,
        forward_zone: str,
        reverse_zone: str,
        dns_server: str,
        dns_port: int,
        key_name: str,
        key_secret: str,
        key_algorithm: str,
        qualifying_suffix: str = "",
    ) -> dict:
        return self._post(
            f"/api/kea/dhcpv4/setSubnet/{uuid}",
            {
                "subnet4": {
                    "ddns_forward_zone": forward_zone,
                    "ddns_reverse_zone": reverse_zone,
                    "ddns_qualifying_suffix": qualifying_suffix or forward_zone,
                    "ddns_dns_server": dns_server,
                    "ddns_dns_port": str(dns_port),
                    "ddns_domain_key_name": key_name,
                    "ddns_domain_key_secret": key_secret,
                    "ddns_domain_key_algorithm": key_algorithm,
                    "ddns_update_on_renew": "1",
                    "ddns_override_no_update": "1",
                    "ddns_override_client_update": "0",
                }
            },
        )

    def kea_enable_ddns(self, server_ip: str = "127.0.0.1", server_port: int = 53001) -> dict:
        return self._post(
            "/api/kea/ddns/set",
            {
                "ddns": {
                    "general": {
                        "enabled": "1",
                        "server_ip": server_ip,
                        "server_port": str(server_port),
                    }
                }
            },
        )

    # ------------------------------------------------------------------
    # Unbound
    # ------------------------------------------------------------------

    def unbound_status(self) -> dict:
        return self._get("/api/unbound/service/status")

    def unbound_forwards(self) -> list[UnboundForward]:
        data = self._get("/api/unbound/settings/searchForward")
        return [UnboundForward(**r) for r in data.get("rows", [])]

    def unbound_add_forward(self, domain: str, server: str, port: int = 53530) -> dict:
        return self._post(
            "/api/unbound/settings/addForward",
            {
                "dot": {
                    "enabled": "1",
                    "type": "forward",
                    "domain": domain,
                    "server": server,
                    "port": str(port),
                    "forward_first": "0",
                    "forward_tcp_upstream": "0",
                }
            },
        )

    def unbound_del_forward(self, uuid: str) -> dict:
        return self._post(f"/api/unbound/settings/delForward/{uuid}", {})

    def unbound_reconfigure(self) -> dict:
        return self._post("/api/unbound/service/reconfigure", {})

    def unbound_get_general(self) -> dict:
        return self._get("/api/unbound/settings/get").get("unbound", {}).get("general", {})

    def unbound_set_general(self, **kwargs: str) -> dict:
        return self._post("/api/unbound/settings/set", {"unbound": {"general": kwargs}})

    # ------------------------------------------------------------------
    # Gateway
    # ------------------------------------------------------------------

    def gateway_status(self) -> list[GatewayStatus]:
        data = self._get("/api/routes/gateway/status")
        return [GatewayStatus(**r) for r in data.get("items", [])]

    # ------------------------------------------------------------------
    # BIND
    # ------------------------------------------------------------------

    def bind_status(self) -> dict:
        return self._get("/api/bind/service/status")

    def bind_zones(self) -> list[BindZone]:
        data = self._get("/api/bind/domain/searchPrimaryDomain")
        return [BindZone(**r) for r in data.get("rows", [])]

    def bind_records(self, domain_uuid: str | None = None) -> list[BindRecord]:
        params = {"domain": domain_uuid} if domain_uuid else {}
        data = self._get("/api/bind/record/searchRecord", params=params)
        return [BindRecord(**r) for r in data.get("rows", [])]

    def bind_add_zone(self, domainname: str) -> dict:
        return self._post(
            "/api/bind/domain/addPrimaryDomain",
            {
                "domain": {
                    "enabled": "1",
                    "domainname": domainname,
                    "ttl": "300",
                    "refresh": "21600",
                    "retry": "3600",
                    "expire": "3542400",
                    "negative": "300",
                    "allowrndcupdate": "1",
                    "mailadmin": "mail.opnsense.localdomain",
                    "dnsserver": "opnsense.localdomain",
                }
            },
        )

    def bind_add_record(self, domain_uuid: str, name: str, rtype: str, value: str) -> dict:
        return self._post(
            "/api/bind/record/addRecord",
            {
                "record": {
                    "enabled": "1",
                    "domain": domain_uuid,
                    "name": name,
                    "type": rtype,
                    "value": value,
                }
            },
        )

    def bind_del_record(self, uuid: str) -> dict:
        return self._post(f"/api/bind/record/delRecord/{uuid}", {})

    def bind_del_zone(self, uuid: str) -> dict:
        return self._post(f"/api/bind/domain/delDomain/{uuid}", {})

    def bind_reconfigure(self) -> dict:
        return self._post("/api/bind/service/reconfigure", {})

    def system_fqdn(self, ssh: SSHClient) -> str:
        """Return OPNsense FQDN with trailing dot."""
        fqdn = ssh.opnsense("hostname").stdout.strip().lower()
        return fqdn.rstrip(".") + "."

    def bind_tsig_key(self, ssh: SSHClient) -> dict | None:
        """Read rndc-key algo+secret from named.conf via SSH."""
        import re

        try:
            conf = ssh.opnsense("cat /usr/local/etc/namedb/named.conf").stdout
            algo = re.search(r'key "rndc-key".*?algorithm "([^"]+)"', conf, re.DOTALL)
            secret = re.search(r'key "rndc-key".*?secret "([^"]+)"', conf, re.DOTALL)
            if algo and secret:
                return {"name": "rndc-key", "algorithm": algo.group(1), "secret": secret.group(1)}
        except Exception:
            pass
        return None

    # ------------------------------------------------------------------
    # Config backup
    # ------------------------------------------------------------------

    def backup_config(self) -> bytes:
        r = requests.get(
            f"{self._resolve_base()}/api/core/backup/download/this",
            auth=self._auth,
            verify=False,
            timeout=30,
        )
        r.raise_for_status()
        return r.content  # returns XML bytes, not JSON — cannot use _get

    # ------------------------------------------------------------------
    # Firewall
    # ------------------------------------------------------------------

    def list_rules(self) -> list[dict]:
        return self._get("/api/firewall/filter/getRuleList").get("rows", [])

    def list_pf_states(self) -> list[dict]:
        return self._get("/api/firewall/filter/getStates").get("rows", [])

    def flush_pf_states(self) -> dict:
        return self._post("/api/firewall/filter/flushStates", {})
