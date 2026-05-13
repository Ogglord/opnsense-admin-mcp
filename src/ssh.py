"""SSH client for running remote commands on OPNsense and other hosts.

Uses Fabric (paramiko under the hood) for connection reuse,
keep-alive, and simpler API. Tcpdump streaming uses subprocess
for reliability with long-running packet captures.

Supports ssh-agent via the SSH_AUTH_SOCK environment variable.
"""

from __future__ import annotations

import os
import subprocess
import tempfile
from contextlib import suppress

from fabric import Connection

from .models import CommandResult, Settings


class SSHClient:
    """Run commands on remote hosts via Fabric SSH connections.

    Authentication priority:
    1. ssh-agent (if SSH_AUTH_SOCK is set) — used by default.
    2. Explicit SSH key file (if settings.ssh_key is non-empty).
    3. If neither is available, raises ValueError.
    """

    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._key_path: str | None = str(settings.ssh_key_path.resolve()) if settings.ssh_key else None
        self._use_agent: bool = bool(os.environ.get("SSH_AUTH_SOCK"))
        self._conns: dict[str, Connection] = {}
        self._captures: list[tuple[subprocess.Popen[bytes], str, str, str]] = []
        self._active_opnsense: str | None = None

    # ------------------------------------------------------------------
    # Connection management
    # ------------------------------------------------------------------

    def _connect(self, host: str) -> Connection:
        """Create or return a cached Fabric Connection for *host*.

        Uses ssh-agent when available, falling back to an explicit
        key file.  Raises ValueError when neither is configured.
        """
        if host not in self._conns:
            connect_kwargs: dict = {"timeout": 10}

            if self._use_agent:
                connect_kwargs["allow_agent"] = True
                if self._key_path is not None:
                    connect_kwargs["key_filename"] = self._key_path
            elif self._key_path is not None:
                connect_kwargs["key_filename"] = self._key_path
            else:
                raise ValueError(
                    "No SSH authentication method available: set SSH_AUTH_SOCK for ssh-agent or configure ssh_key in settings."
                )

            self._conns[host] = Connection(
                host=host,
                user="root",
                connect_kwargs=connect_kwargs,
            )
        return self._conns[host]

    def close(self) -> None:
        for conn in self._conns.values():
            with suppress(Exception):
                conn.close()
        self._conns.clear()

    # ------------------------------------------------------------------
    # Core
    # ------------------------------------------------------------------

    def run(self, host: str, command: str, timeout: int = 30) -> CommandResult:
        """Run a command and return a CommandResult."""
        conn = self._connect(host)
        try:
            r = conn.run(command, hide=True, warn=True, timeout=timeout)
            return CommandResult(
                stdout=r.stdout or "",
                stderr=r.stderr or "",
                returncode=r.return_code,
                ok=r.ok,
            )
        except Exception as e:
            return CommandResult(
                stdout="",
                stderr=str(e),
                returncode=255,
                ok=False,
            )

    def run_ok(self, host: str, command: str, timeout: int = 30) -> bool:
        return self.run(host, command, timeout).ok

    def check_output(self, host: str, command: str, timeout: int = 30) -> str:
        r = self.run(host, command, timeout)
        if not r.ok:
            raise RuntimeError(f"Command failed (exit {r.returncode}): {r.stderr[:200]}")
        return r.stdout.strip()

    # ------------------------------------------------------------------
    # OPNsense shortcut (tries all configured hosts, caches winner)
    # ------------------------------------------------------------------

    def _resolve_opnsense_host(self) -> str:
        if self._active_opnsense:
            return self._active_opnsense
        for host in self._settings.opnsense.hosts:
            h = host.replace("https://", "").replace("http://", "").rstrip("/")
            try:
                conn = self._connect(h)
                r = conn.run("true", hide=True, warn=True, timeout=5)
                if r.ok:
                    self._active_opnsense = h
                    return h
            except Exception:
                pass
        self._active_opnsense = self._settings.opnsense_ts
        return self._active_opnsense

    def opnsense(self, command: str, timeout: int = 30) -> CommandResult:
        return self.run(self._resolve_opnsense_host(), command, timeout)

    # ------------------------------------------------------------------
    # Tcpdump (subprocess — Fabric channels don't handle streaming well)
    # ------------------------------------------------------------------

    def _build_ssh_args(self, host: str, remote_cmd: str) -> list[str]:
        """Build ssh subprocess argument list, omitting -i when using agent.

        When ssh-agent is active, native ssh uses it automatically,
        so we skip the explicit -i flag.
        """
        args = [
            "ssh",
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "ConnectTimeout=10",
        ]
        if not self._use_agent and self._key_path is not None:
            args.extend(["-i", self._key_path])
        args.append(f"root@{host}")
        args.append(remote_cmd)
        return args

    def tcpdump_start(
        self,
        host: str,
        interface: str,
        filter_expr: str = "icmp",
        packet_count: int = 20,
    ) -> str:
        """Start background tcpdump via SSH subprocess, return path to output file."""
        f = tempfile.NamedTemporaryFile(prefix=f"tcpdump_{host}_", suffix=".pcap", delete=False)  # noqa: SIM115
        f.close()
        cmd = f"tcpdump -i {interface} -c {packet_count} -U -w - {filter_expr} 2>/dev/null"
        ssh_args = self._build_ssh_args(host, cmd)
        proc = subprocess.Popen(
            ssh_args,
            stdout=open(f.name, "wb"),  # noqa: SIM115
            stderr=subprocess.DEVNULL,
        )
        self._captures.append((proc, f.name, host, interface))
        return f.name

    def tcpdump_stop_all(self) -> list[str]:
        paths: list[str] = []
        for proc, path, *_ in self._captures:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
            paths.append(path)
        self._captures.clear()
        return paths

    def capture_pings(
        self,
        host: str,
        interface: str,
        source_ip: str,
        target_ip: str,
        duration: int = 15,
    ) -> bytes:
        """Run tcpdump for N seconds returning raw pcap."""
        filter_expr = f"icmp and host {source_ip} and host {target_ip}"
        cmd = f"tcpdump -i {interface} -U -w - {filter_expr} 2>/dev/null"
        ssh_args = self._build_ssh_args(host, cmd)
        try:
            r = subprocess.run(ssh_args, capture_output=True, timeout=duration)
            return r.stdout
        except subprocess.TimeoutExpired as e:
            return e.stdout if e.stdout is not None else b""
