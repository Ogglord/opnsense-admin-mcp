# OPNsense MCP Server

MCP interface for OPNsense, for doing network automation and basic diagnostics.

Exposes OPNsense (DHCP, DNS, firewall, health checks) and network topology discovery as MCP tools for Claude Code and other AI assistants.

---

## MCP Capabilities

### Read-only tools

- **discover** — Network topology (nodes, VLANs, interfaces, gateways). Detects topology drift (nodes appearing/disappearing).
- **get_status** — Service status (Kea DHCP, Unbound DNS, BIND authoritative). Gateway health (loss/RTT).
- **health_check** — Full suite: API reachability, VLAN interfaces, routing table, ARP table, interface errors, internet ping. Includes trend data from SQLite history.
- **health_runs** — Recent health check summaries (run ID, timestamp, uptime, pass/fail counts).
- **health_errors** — Interface error trends over time, correlated with uptime (detect reboots).
- **list_leases** — Active DHCP leases, optionally filtered by VLAN (IP, MAC, hostname, expiry).
- **list_reservations** — Static DHCP reservations.
- **list_vlans** — Configured VLANs (tag, interface, description).
- **list_bind_zones** — BIND primary zones.
- **list_bind_records** — BIND DNS records, optionally filtered by zone.
- **list_unbound_forwards** — Unbound DNS forward zones.
- **dig** — DNS query via OPNsense (specify server, port, record type).
- **ntopng_top_hosts** — Top N hosts by bandwidth per interface (bytes sent/rcvd, flow count, threat score).
- **ntopng_alerts** — Hosts with threat scores >= threshold (community-compatible score filter).
- **pf_states** — Active PF firewall state table entries + total state count.
- **read_log** — Tail system logs (filter/PF, configd, system, dhcpd, DNS, ntopng). Capped at 500 lines.
- **hw_sensors** — CPU temperatures (per-core), ACPI thermal zones, CPU time breakdown, RAM stats (total/free/percent).
- **list_packages** — Installed packages and OPNsense plugins, grouped (plugins/opnsense-core/base). Sortable by type.
- **shell_run** — Allowlisted SSH commands (hostname, uptime, uname, df, free, netstat, pkg, service, sysctl, pfctl, pftop).

### Write tools (mutations)

- **add_reservation** — Add static DHCP reservation (auto-finds subnet from IP). Triggers Kea reconfigure.
- **add_bind_record** — Add DNS record to BIND zone (A, AAAA, CNAME, etc.).
- **del_bind_record** — Delete BIND record by UUID.
- **add_unbound_forward** — Add Unbound DNS forward zone.
- **del_unbound_forward** — Delete Unbound forward zone.
- **reconfigure** — Reload service (kea, unbound, all).

### Resources

- **opnsense://config** — Sanitized config summary (VLANs, interfaces, no secrets).
- **opnsense://vlans** — VLAN definitions.
- **opnsense://health/last** — Most recent health check run.

---

## Installation

### Prerequisites

- [uv](https://docs.astral.sh/uv/getting-started/installation/) — Python package manager
- OPNsense API credentials (System → Access → Users → create user with API enabled) with proper access rights
- SSH key on OPNsense (optional, for `read_log`, `shell_run`, `hw_sensors`)

### One-liner

Run from the directory where you want to open Claude Code or OpenCode:

```sh
sh -c "$(curl -fsSL https://raw.githubusercontent.com/Ogglord/opn-mcp/main/install.sh)"
```

The script will:
1. Clone the repo into `./opn-mcp` in the current directory
2. Install dependencies via `uv`
3. Prompt for OPNsense credentials
4. Write `.mcp.json` (Claude Code) and `opencode.json` (OpenCode) into the cloned directory
5. Smoke-test the MCP server

Then open Claude Code or OpenCode from the `opn-mcp` directory.

### Manual setup

```sh
git clone https://github.com/Ogglord/opn-mcp.git
cd opn-mcp
./install.sh
```

### SSH (optional)

Required for `read_log`, `shell_run`, `hw_sensors`. Choose one:

1. **SSH agent** (recommended): add your public key to OPNsense `~root/.ssh/authorized_keys`, ensure `SSH_AUTH_SOCK` is set.
2. **Key file**: set `OPN_SSH_KEY` to the absolute path of an unencrypted private key.

### Running the MCP server manually

```sh
uv run opn-mcp
```

Runs on stdio, ready for Claude Code, OpenCode, or any MCP client.

---

## Project structure

```
src/
  mcp_server.py         # MCP tool definitions
  opnsense.py           # REST API client
  ssh.py                # SSH client for remote commands
  models.py             # Data models (Settings, Lease, etc.)
  db.py                 # SQLite health check history
  services/
    discovery.py        # Network topology discovery
    health.py           # Health check suite
    status.py           # Service status
    dhcp.py             # Kea DHCP operations
    dns.py              # Unbound + BIND operations
```

---

## Example: MCP usage in Claude Code

Ask Claude Code to query your network:

```
Show me the top 10 hosts by bandwidth on each VLAN
```

Claude calls `ntopng_top_hosts` → see which devices are active, who's consuming bandwidth.

```
List all DNS zones and records
```

Claude calls `list_bind_zones` + `list_bind_records` → review your DNS setup.

```
Run a full health check and show me any errors
```

Claude calls `health_check` → highlights misconfigurations, interface errors, connectivity issues.

```
Add a static DHCP reservation for MAC 00:11:22:33:44:55 at 192.168.1.100
```

Claude calls `add_reservation` → OPNsense config updated, Kea reloaded.

---

## Known limitations

- **ntopng_alerts** uses community-compatible score filter (enterprise-only `alert/list.lua` unavailable).
- **read_log** is SSH-only; requires SSH key or agent configured.
- **shell_run** is allowlisted for safety; new commands require code changes.
- All write tools require valid OPNsense API credentials.

---

## License

MIT
