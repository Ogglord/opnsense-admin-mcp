"""Diagnostic framework for OPNsense health checks."""

from __future__ import annotations

import re
import time
from collections.abc import Callable

from .models import CheckResult, CheckStatus, Settings
from .opnsense import OPNsenseClient
from .ssh import SSHClient

CheckFn = Callable[[], CheckResult]


class Diagnostic:
    """Container for all health and investigation checks."""

    def __init__(self, settings: Settings, opnsense: OPNsenseClient, ssh: SSHClient) -> None:
        self._settings = settings
        self._opn = opnsense
        self._ssh = ssh

    # ------------------------------------------------------------------
    # OPNsense checks
    # ------------------------------------------------------------------

    def fetch_hostuuid(self) -> str:
        """Return kern.hostuuid from OPNsense — stable unique ID per installation."""
        try:
            return self._ssh.opnsense("sysctl -n kern.hostuuid").stdout.strip()
        except Exception:
            return ""

    def fetch_uptime_seconds(self) -> int | None:
        """Return OPNsense uptime in seconds via sysctl kern.boottime, or None on failure."""
        try:
            r = self._ssh.opnsense("sysctl -n kern.boottime")
            if not r.ok:
                return None
            out = r.stdout
            m = re.search(r"sec\s*=\s*(\d+)", out)
            if m:
                return int(time.time()) - int(m.group(1))
        except Exception:
            pass
        return None

    def check_opnsense_api(self) -> CheckResult:
        alive = self._opn.is_alive()
        return CheckResult(
            name="OPNsense API",
            status=CheckStatus.PASS if alive else CheckStatus.FAIL,
            detail="API responded" if alive else "API unreachable",
        )

    def check_vlan_interfaces(self) -> CheckResult:
        """Check that all configured VLANs have an associated interface that is up."""
        try:
            vlans = self._opn.list_vlans()
            interfaces = self._opn.interface_overview()
        except Exception as e:
            return CheckResult(name="VLAN interfaces", status=CheckStatus.ERROR, detail=str(e))

        if not vlans:
            return CheckResult(name="VLAN interfaces", status=CheckStatus.PASS, detail="no VLANs configured")

        up_ifaces = {i.ipv4.split("/")[0] for i in interfaces if i.status == "up" and i.ipv4}
        iface_ids = {i.identifier for i in interfaces if i.status == "up"}
        vlan_tags = [v.get("tag", "") for v in vlans]
        down = []
        for iface in interfaces:
            if iface.identifier and iface.identifier not in ("wan", "lo0") and iface.status != "up":
                down.append(iface.identifier)

        if down:
            return CheckResult(name="VLAN interfaces", status=CheckStatus.WARN, detail=f"Down: {down}")
        return CheckResult(name="VLAN interfaces", status=CheckStatus.PASS, detail=f"VLANs: {vlan_tags}")

    def check_opnsense_routing(self) -> CheckResult:
        """Check routing table has a default route."""
        try:
            routing = self._ssh.check_output(self._ssh._resolve_opnsense_host(), "netstat -rn -f inet")
        except Exception as e:
            return CheckResult(name="Routing table", status=CheckStatus.ERROR, detail=str(e))

        has_default = any(line.startswith("default") or line.startswith("0.0.0.0") for line in routing.splitlines())
        if not has_default:
            return CheckResult(name="Routing table", status=CheckStatus.FAIL, detail="No default route")
        return CheckResult(name="Routing table", status=CheckStatus.PASS)

    def check_opnsense_arp(self) -> CheckResult:
        """Check that static DHCP reservations appear in ARP table (API-driven)."""
        try:
            arp = self._ssh.check_output(self._ssh._resolve_opnsense_host(), "arp -an")
        except Exception as e:
            return CheckResult(name="ARP table", status=CheckStatus.ERROR, detail=str(e))

        try:
            reservations = self._opn.kea_reservations()
        except Exception:
            reservations = []

        if not reservations:
            return CheckResult(name="ARP table", status=CheckStatus.PASS, detail="no static reservations to check")

        missing = [r.ip_address for r in reservations if r.ip_address and r.ip_address not in arp]
        if missing:
            labels = []
            for r in reservations:
                if r.ip_address in missing:
                    labels.append(r.hostname or r.ip_address)
            return CheckResult(name="ARP table", status=CheckStatus.WARN, detail=f"Not in ARP: {labels}")
        return CheckResult(name="ARP table", status=CheckStatus.PASS, detail=f"{len(reservations)} reservations reachable")

    def check_pf_states_for(self, src_ip: str, dst_ip: str) -> CheckResult:
        try:
            cmd = f"pfctl -ss | grep {src_ip}"
            states = self._ssh.check_output(self._ssh._resolve_opnsense_host(), cmd, timeout=15)
        except Exception as e:
            return CheckResult(name=f"PF states {src_ip}→{dst_ip}", status=CheckStatus.ERROR, detail=str(e))
        if dst_ip in states:
            return CheckResult(name=f"PF states {src_ip}→{dst_ip}", status=CheckStatus.PASS, detail="State exists")
        return CheckResult(name=f"PF states {src_ip}→{dst_ip}", status=CheckStatus.WARN, detail="No state (no traffic seen)")

    def check_ifconfig_hw(self) -> CheckResult:
        """Check LAN interface for hardware VLAN filtering flags."""
        iface = self._settings.network.lan_iface
        try:
            output = self._ssh.check_output(self._ssh._resolve_opnsense_host(), f"ifconfig {iface}")
        except Exception as e:
            return CheckResult(name=f"{iface} hardware flags", status=CheckStatus.ERROR, detail=str(e))
        flags_of_interest = ["vlanhwfilter", "vlanhwtag", "vlanhwtso", "vlanhwcsum"]
        found = [f for f in flags_of_interest if f in output.lower()]
        return CheckResult(name=f"{iface} hardware flags", status=CheckStatus.PASS, detail=f"Flags: {found}")

    def check_interface_errors(self) -> CheckResult:
        """Report RX/TX error counts on all physical and VLAN interfaces."""
        try:
            output = self._ssh.check_output(self._ssh._resolve_opnsense_host(), "netstat -i -b")
        except Exception as e:
            return CheckResult(name="Interface errors", status=CheckStatus.ERROR, detail=str(e))

        errors: dict[str, dict] = {}
        for line in output.splitlines()[1:]:  # skip header
            parts = line.split()
            if len(parts) < 9:
                continue
            name = parts[0].rstrip("*")
            network = parts[2] if len(parts) > 2 else ""
            if "<Link#" not in network:
                continue
            try:
                ierrs = int(parts[5])
                idrop = int(parts[6])
                oerrs = int(parts[9])
            except (ValueError, IndexError):
                continue
            if ierrs or idrop or oerrs:
                errors[name] = {"ierrs": ierrs, "idrop": idrop, "oerrs": oerrs}

        if errors:
            detail = "; ".join(
                f"{iface}: ierrs={v['ierrs']} idrop={v['idrop']} oerrs={v['oerrs']}" for iface, v in sorted(errors.items())
            )
            return CheckResult(name="Interface errors", status=CheckStatus.WARN, detail=detail, data=errors)
        return CheckResult(name="Interface errors", status=CheckStatus.PASS, detail="no errors")

    def check_igc0_link_speed(self) -> CheckResult:
        """Verify LAN interface negotiated 1Gbps full-duplex, not 2.5G."""
        iface = self._settings.network.lan_iface
        try:
            output = self._ssh.check_output(self._ssh._resolve_opnsense_host(), f"ifconfig {iface}")
        except Exception as e:
            return CheckResult(name=f"{iface} link speed", status=CheckStatus.ERROR, detail=str(e))
        m = re.search(r"media:.*?(\d+(?:\.\d+)?G?base[^\s]*)\s+<([^>]*)>", output, re.IGNORECASE)
        if not m:
            return CheckResult(name=f"{iface} link speed", status=CheckStatus.WARN, detail="Could not parse media line")
        media, options = m.group(1), m.group(2)
        detail = f"{media} <{options}>"
        if "2500" in media or "2.5G" in media.upper():
            return CheckResult(name=f"{iface} link speed", status=CheckStatus.FAIL, detail=f"2.5G detected — {detail}")
        if "full-duplex" not in options.lower():
            return CheckResult(name=f"{iface} link speed", status=CheckStatus.WARN, detail=f"Not full-duplex — {detail}")
        return CheckResult(name=f"{iface} link speed", status=CheckStatus.PASS, detail=detail)

    # ------------------------------------------------------------------
    # Connectivity checks
    # ------------------------------------------------------------------

    def check_ping(self, source_label: str, host: str, target: str) -> CheckResult:
        cmd = f"ping -c 2 -W 3 {target}"
        try:
            r = self._ssh.run(host, cmd, timeout=10)
        except Exception as e:
            return CheckResult(name=f"Ping {source_label}→{target}", status=CheckStatus.ERROR, detail=str(e))
        if r.ok:
            return CheckResult(name=f"Ping {source_label}→{target}", status=CheckStatus.PASS)
        return CheckResult(name=f"Ping {source_label}→{target}", status=CheckStatus.FAIL, detail=r.stderr[:200])

    def check_ping_opnsense_to(self, target: str) -> CheckResult:
        return self.check_ping("OPNsense", self._ssh._resolve_opnsense_host(), target)

    # ------------------------------------------------------------------
    # Run collections
    # ------------------------------------------------------------------

    def run_health_checks(self) -> list[CheckResult]:
        """Run the standard health check suite."""
        checks: list[CheckFn] = [
            self.check_opnsense_api,
            self.check_vlan_interfaces,
            self.check_opnsense_routing,
            self.check_opnsense_arp,
            self.check_ifconfig_hw,
            self.check_igc0_link_speed,
            self.check_interface_errors,
            lambda: self.check_ping_opnsense_to("1.1.1.1"),
        ]

        return [c() for c in checks]

