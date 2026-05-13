"""Lightweight SQLite store for health check history and topology snapshots.

Single database file; instance_id (kern.hostuuid) partitions rows per router.
"""

from __future__ import annotations

import json
import os
import sqlite3
from collections.abc import Generator
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path


def _xdg_data_home() -> Path:
    xdg = os.environ.get("XDG_DATA_HOME")
    return Path(xdg) if xdg else Path.home() / ".local" / "share"


def _db_path() -> Path:
    """Resolve DB path: $OPNSENSE_DB_PATH override > XDG default."""
    override = os.environ.get("OPNSENSE_DB_PATH")
    if override:
        return Path(override)
    return _xdg_data_home() / "opnsense" / "health.db"


DB_PATH = _db_path()

BASE_SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (
    id           INTEGER PRIMARY KEY,
    ts           TEXT    NOT NULL
);

CREATE TABLE IF NOT EXISTS checks (
    id      INTEGER PRIMARY KEY,
    run_id  INTEGER NOT NULL REFERENCES runs(id),
    name    TEXT    NOT NULL,
    status  TEXT    NOT NULL,
    detail  TEXT
);

CREATE TABLE IF NOT EXISTS interface_errors (
    id          INTEGER PRIMARY KEY,
    run_id      INTEGER NOT NULL REFERENCES runs(id),
    ts          TEXT    NOT NULL,
    interface   TEXT    NOT NULL,
    ierrs       INTEGER NOT NULL DEFAULT 0,
    idrop       INTEGER NOT NULL DEFAULT 0,
    oerrs       INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_iface_errors_ts  ON interface_errors(interface, ts);
"""

# Each entry is one forward migration. Index+1 == user_version after applying.
MIGRATIONS: list[str] = [
    # v1: router uptime per run for error correlation
    "ALTER TABLE runs ADD COLUMN uptime_seconds INTEGER",
    # v2: instance_id partition key — old rows get empty string default
    "ALTER TABLE runs ADD COLUMN instance_id TEXT NOT NULL DEFAULT ''",
    # v3: index on instance_id (must follow v2 — column must exist first)
    "CREATE INDEX IF NOT EXISTS idx_runs_instance ON runs(instance_id)",
    # v4: topology snapshots — nodes/vlans/interfaces/gateways per discovery run
    """CREATE TABLE IF NOT EXISTS topology (
        id          INTEGER PRIMARY KEY,
        instance_id TEXT NOT NULL,
        ts          TEXT NOT NULL,
        nodes       TEXT,
        vlans       TEXT,
        interfaces  TEXT,
        gateways    TEXT
    )""",
    # v5: index for fast latest-snapshot lookup
    "CREATE INDEX IF NOT EXISTS idx_topology_instance ON topology(instance_id, ts DESC)",
]


def _migrate(con: sqlite3.Connection) -> None:
    """Apply pending migrations using PRAGMA user_version as schema version counter."""
    current: int = con.execute("PRAGMA user_version").fetchone()[0]
    pending = MIGRATIONS[current:]
    for i, sql in enumerate(pending, start=current + 1):
        con.execute(sql)
        con.execute(f"PRAGMA user_version = {i}")
    if pending:
        con.commit()


@contextmanager
def _conn(path: Path) -> Generator[sqlite3.Connection, None, None]:
    path.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(path)
    con.row_factory = sqlite3.Row
    try:
        con.executescript(BASE_SCHEMA)
        _migrate(con)
        yield con
        con.commit()
    finally:
        con.close()


def save_run(
    instance_id: str,
    results: list,
    iface_errors: dict[str, dict] | None = None,
    uptime_seconds: int | None = None,
    path: Path | None = None,
) -> int:
    """Persist one health run. Returns run_id."""
    ts = datetime.now(timezone.utc).isoformat()
    with _conn(path or DB_PATH) as con:
        cur = con.execute(
            "INSERT INTO runs (instance_id, ts, uptime_seconds) VALUES (?, ?, ?)",
            (instance_id, ts, uptime_seconds),
        )
        run_id = cur.lastrowid
        assert run_id is not None

        con.executemany(
            "INSERT INTO checks (run_id, name, status, detail) VALUES (?, ?, ?, ?)",
            [(run_id, r["check"], r["status"], r.get("detail", "")) for r in results],
        )

        if iface_errors:
            con.executemany(
                "INSERT INTO interface_errors (run_id, ts, interface, ierrs, idrop, oerrs) VALUES (?, ?, ?, ?, ?, ?)",
                [(run_id, ts, iface, v["ierrs"], v["idrop"], v["oerrs"]) for iface, v in iface_errors.items()],
            )
    return run_id


def recent_runs(instance_id: str, limit: int = 20, path: Path | None = None) -> list[dict]:
    """Return recent runs for this instance with pass/fail/warn summary and uptime."""
    with _conn(path or DB_PATH) as con:
        rows = con.execute(
            """
            SELECT r.id, r.ts, r.uptime_seconds,
                   SUM(CASE WHEN c.status = 'PASS'  THEN 1 ELSE 0 END) AS passed,
                   SUM(CASE WHEN c.status = 'FAIL'  THEN 1 ELSE 0 END) AS failed,
                   SUM(CASE WHEN c.status = 'WARN'  THEN 1 ELSE 0 END) AS warned,
                   SUM(CASE WHEN c.status = 'ERROR' THEN 1 ELSE 0 END) AS errors
            FROM runs r
            LEFT JOIN checks c ON c.run_id = r.id
            WHERE r.instance_id = ?
            GROUP BY r.id
            ORDER BY r.id DESC
            LIMIT ?
            """,
            (instance_id, limit),
        ).fetchall()
    return [dict(r) for r in rows]


def error_trend(
    instance_id: str,
    interface: str | None = None,
    limit: int = 50,
    path: Path | None = None,
) -> list[dict]:
    """Return interface error counts over time with uptime for correlation.

    Use uptime_seconds to detect reboots: counter reset after low uptime = expected,
    not degradation. Stable uptime + rising errors = genuine issue.
    """
    with _conn(path or DB_PATH) as con:
        if interface:
            rows = con.execute(
                """
                SELECT ie.ts, ie.interface, ie.ierrs, ie.idrop, ie.oerrs, r.uptime_seconds
                FROM interface_errors ie
                JOIN runs r ON r.id = ie.run_id
                WHERE r.instance_id = ? AND ie.interface = ?
                ORDER BY ie.ts DESC LIMIT ?
                """,
                (instance_id, interface, limit),
            ).fetchall()
        else:
            rows = con.execute(
                """
                SELECT ie.ts, ie.interface, ie.ierrs, ie.idrop, ie.oerrs, r.uptime_seconds
                FROM interface_errors ie
                JOIN runs r ON r.id = ie.run_id
                WHERE r.instance_id = ?
                ORDER BY ie.ts DESC LIMIT ?
                """,
                (instance_id, limit),
            ).fetchall()
    return [dict(r) for r in rows]


def save_topology(
    instance_id: str,
    nodes: list[dict],
    vlans: list[dict],
    interfaces: list[dict],
    gateways: list[dict],
    path: Path | None = None,
) -> int:
    """Persist one topology snapshot. Returns row id."""
    ts = datetime.now(timezone.utc).isoformat()
    with _conn(path or DB_PATH) as con:
        cur = con.execute(
            "INSERT INTO topology (instance_id, ts, nodes, vlans, interfaces, gateways) VALUES (?, ?, ?, ?, ?, ?)",
            (
                instance_id,
                ts,
                json.dumps(nodes),
                json.dumps(vlans),
                json.dumps(interfaces),
                json.dumps(gateways),
            ),
        )
        return cur.lastrowid  # type: ignore[return-value]


def latest_topology(instance_id: str, path: Path | None = None) -> dict | None:
    """Return most recent topology snapshot for this instance, or None."""
    with _conn(path or DB_PATH) as con:
        row = con.execute(
            "SELECT id, ts, nodes, vlans, interfaces, gateways FROM topology WHERE instance_id = ? ORDER BY ts DESC LIMIT 1",
            (instance_id,),
        ).fetchone()
    if not row:
        return None
    return {
        "id": row["id"],
        "ts": row["ts"],
        "nodes": json.loads(row["nodes"] or "[]"),
        "vlans": json.loads(row["vlans"] or "[]"),
        "interfaces": json.loads(row["interfaces"] or "[]"),
        "gateways": json.loads(row["gateways"] or "[]"),
    }


def checks_for_run(run_id: int, path: Path | None = None) -> list[dict]:
    """Return all check results for a specific run."""
    with _conn(path or DB_PATH) as con:
        rows = con.execute(
            "SELECT name, status, detail FROM checks WHERE run_id = ? ORDER BY id",
            (run_id,),
        ).fetchall()
    return [dict(r) for r in rows]


class HealthDB:
    """Per-instance view into the shared SQLite health database."""

    def __init__(self, instance_id: str, path: Path | None = None) -> None:
        self._instance_id = instance_id
        self._path = path or DB_PATH

    def save_run(
        self,
        results: list,
        iface_errors: dict[str, dict] | None = None,
        uptime_seconds: int | None = None,
    ) -> int:
        return save_run(self._instance_id, results, iface_errors, uptime_seconds, self._path)

    def recent_runs(self, limit: int = 20) -> list[dict]:
        return recent_runs(self._instance_id, limit=limit, path=self._path)

    def error_trend(self, interface: str | None = None, limit: int = 50) -> list[dict]:
        return error_trend(self._instance_id, interface=interface, limit=limit, path=self._path)

    def checks_for_run(self, run_id: int) -> list[dict]:
        return checks_for_run(run_id, path=self._path)

    def save_topology(
        self,
        nodes: list[dict],
        vlans: list[dict],
        interfaces: list[dict],
        gateways: list[dict],
    ) -> int:
        return save_topology(self._instance_id, nodes, vlans, interfaces, gateways, self._path)

    def latest_topology(self) -> dict | None:
        return latest_topology(self._instance_id, self._path)
