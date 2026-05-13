"""Load settings from environment variables.

Required env vars:
  OPN_HOSTS   Comma-separated list of OPNsense IPs/URLs (ordered, first reachable wins)
  OPN_KEY     OPNsense API key
  OPN_SECRET  OPNsense API secret

Optional:
  OPN_SSH_KEY Path to SSH private key (omit to use ssh-agent via SSH_AUTH_SOCK)
"""

from __future__ import annotations

import os

from .models import OPNsenseConfig, Settings


def load_settings(env: str = "prod") -> Settings:
    """Build Settings from environment variables.

    Raises:
        RuntimeError: If OPN_HOSTS, OPN_KEY, or OPN_SECRET are not set.
    """
    hosts_env = os.environ.get("OPN_HOSTS", "")
    key = os.environ.get("OPN_KEY", "")
    secret = os.environ.get("OPN_SECRET", "")

    missing = [v for v, val in [("OPN_HOSTS", hosts_env), ("OPN_KEY", key), ("OPN_SECRET", secret)] if not val]
    if missing:
        raise RuntimeError(f"Required env vars not set: {', '.join(missing)}")

    hosts = [h.strip() for h in hosts_env.split(",") if h.strip()]
    ssh_key = os.environ.get("OPN_SSH_KEY", "")

    return Settings(
        opnsense=OPNsenseConfig(hosts=hosts, key=key, secret=secret),
        ssh_key=ssh_key,
    )
