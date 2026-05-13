"""Pydantic models for OPNsense API responses, settings, and diagnostics."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Generic, TypeVar

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

# ------------------------------------------------------------------
# Runtime config models (loaded from config.yaml or env vars)
# ------------------------------------------------------------------


class OPNsenseConfig(BaseModel):
    hosts: list[str] = Field(default_factory=list)
    host: str = ""  # backward compat — always mirrors hosts[0]
    key: str = ""
    secret: str = ""

    @model_validator(mode="after")
    def _normalize_hosts(self) -> OPNsenseConfig:
        if self.hosts and not self.host:
            self.host = self.hosts[0]
        elif self.host and not self.hosts:
            self.hosts = [self.host]
        elif self.host and self.hosts and self.host not in self.hosts:
            self.hosts = [self.host] + self.hosts
        return self


class NetworkConfig(BaseModel):
    lan_iface: str = "igc0"
    wan_iface: str = "em0"


class Settings(BaseModel):
    """Runtime configuration loaded from environment variables."""

    opnsense: OPNsenseConfig
    network: NetworkConfig = Field(default_factory=NetworkConfig)
    ssh_key: str = ""

    @property
    def opnsense_ts(self) -> str:
        """OPNsense host IP/address with scheme and trailing slash stripped."""
        h = self.opnsense.host.replace("http://", "").replace("https://", "").rstrip("/")
        return h

    @property
    def ssh_key_path(self) -> Path:
        p = Path(self.ssh_key)
        if not p.is_absolute():
            p = Path(__file__).resolve().parent.parent / p
        return p


# ------------------------------------------------------------------
# Generic API helpers
# ------------------------------------------------------------------

T = TypeVar("T")


class RowsResponse(BaseModel, Generic[T]):
    """Wrapper for OPNsense list endpoints: {"rows": [...]}."""

    rows: list[T] = Field(default_factory=list)


class StatusResponse(BaseModel):
    """OPNsense service status: {"status": "running", ...}."""

    status: str = "unknown"


class SaveResponse(BaseModel):
    """OPNsense save/CRUD response: {"result": "saved", "uuid": "..."}."""

    result: str = ""
    uuid: str = ""


class DeleteResponse(BaseModel):
    """OPNsense delete response: {"result": "deleted"}."""

    result: str = ""


class ReconfigureResponse(BaseModel):
    """OPNsense reconfigure response: {"status": "ok"}."""

    status: str = ""


# ------------------------------------------------------------------
# Interface
# ------------------------------------------------------------------


class InterfaceInfo(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    name: str = Field(default="", alias="description")
    identifier: str = ""
    status: str = "unknown"
    ipv4: str = Field(default="", alias="ipaddr")

    @field_validator("ipv4", mode="before")
    @classmethod
    def _coerce_ipv4(cls, v: Any) -> str:
        # API returns ipaddr as list[dict] e.g. [{'ipaddr': '192.168.0.1/24'}]
        if isinstance(v, list):
            if v and isinstance(v[0], dict):
                return v[0].get("ipaddr", "")
            return ""
        return v or ""


# ------------------------------------------------------------------
# Kea DHCP
# ------------------------------------------------------------------


class KeaLease(BaseModel):
    address: str = ""
    hwaddr: str = ""
    hostname: str = ""
    if_descr: str = ""
    iface: str = Field(default="", alias="if")
    is_reserved: bool = False
    expire: int = 0

    @model_validator(mode="before")
    @classmethod
    def _coerce_fields(cls, data: Any) -> Any:
        if isinstance(data, dict):
            if "expire" in data:
                try:
                    data["expire"] = int(data["expire"])
                except (ValueError, TypeError):
                    data["expire"] = 0
            if "is_reserved" in data and not isinstance(data["is_reserved"], bool):
                v = data["is_reserved"]
                data["is_reserved"] = v in (1, "1", "true", "True", True)
        return data


class KeaReservation(BaseModel):
    uuid: str = ""
    ip_address: str = ""
    hw_address: str = ""
    hostname: str = ""
    subnet: str = Field(default="", alias="%subnet")
    description: str = ""


class KeaSubnet(BaseModel):
    uuid: str = ""
    subnet: str = ""
    ddns_forward_zone: str = ""
    ddns_reverse_zone: str = ""
    ddns_dns_server: str = ""
    ddns_dns_port: str = ""
    ddns_domain_key_name: str = ""


class KeaDDNSConfig(BaseModel):
    enabled: str = "0"
    server_ip: str = "127.0.0.1"
    server_port: str = "53001"


# ------------------------------------------------------------------
# Unbound
# ------------------------------------------------------------------


class UnboundForward(BaseModel):
    uuid: str = ""
    domain: str = ""
    server: str = ""
    port: str = ""
    enabled: str = ""


class UnboundGeneral(BaseModel):
    regdhcp: str = ""
    regdhcpstatic: str = ""


# ------------------------------------------------------------------
# BIND
# ------------------------------------------------------------------


class BindZone(BaseModel):
    uuid: str = ""
    domainname: str = ""
    enabled: str = ""


class BindRecord(BaseModel):
    uuid: str = ""
    domain: str = ""
    name: str = ""
    type: str = ""
    value: str = ""


# ------------------------------------------------------------------
# Gateway / Routing
# ------------------------------------------------------------------


class GatewayStatus(BaseModel):
    name: str = ""
    status_translated: str = ""
    loss: str = ""
    delay: str = ""


# ------------------------------------------------------------------
# Diagnostics
# ------------------------------------------------------------------


class CheckStatus(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    WARN = "WARN"
    ERROR = "ERROR"


class CheckResult(BaseModel):
    name: str
    status: CheckStatus
    detail: str = ""
    data: Any = None


# ------------------------------------------------------------------
# SSH command result
# ------------------------------------------------------------------


@dataclass
class CommandResult:
    """Result of a remote command execution via fabric."""

    stdout: str
    stderr: str
    returncode: int
    ok: bool

    @property
    def failed(self) -> bool:
        return not self.ok
