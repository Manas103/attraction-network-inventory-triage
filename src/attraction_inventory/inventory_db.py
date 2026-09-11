"""SQLite inventory store: snapshots, the last issued diagram, and drift.

Schema
------
snapshots(snapshot_id, created_at, capture_file, issued)
    One row per inventory run. `issued` marks a snapshot as the one that was
    actually handed out as the network diagram / Theory of Operations at
    some point; only issued snapshots are compared against for drift.
snapshot_assets(snapshot_id, mac, ip, vendor, model, role, zone, protocol,
                 vendor_locked, cpe23)
    The assets present in that snapshot.

Drift is defined as: any asset in the current (latest) snapshot whose MAC
address does not appear in the most recently issued snapshot.
"""
from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path


SCHEMA = """
CREATE TABLE IF NOT EXISTS snapshots (
    snapshot_id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at TEXT NOT NULL,
    capture_file TEXT NOT NULL,
    issued INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS snapshot_assets (
    snapshot_id INTEGER NOT NULL REFERENCES snapshots(snapshot_id),
    mac TEXT NOT NULL,
    ip TEXT,
    vendor TEXT,
    model TEXT,
    role TEXT,
    zone INTEGER,
    protocol TEXT,
    vendor_locked INTEGER NOT NULL DEFAULT 0,
    cpe23 TEXT,
    PRIMARY KEY (snapshot_id, mac)
);
"""


@dataclass
class SnapshotAssetRow:
    mac: str
    ip: str | None
    vendor: str | None
    model: str | None
    role: str | None
    zone: int | None
    protocol: str | None
    vendor_locked: bool
    cpe23: str | None


def connect(db_path: str | Path) -> sqlite3.Connection:
    conn = sqlite3.connect(str(db_path))
    conn.executescript(SCHEMA)
    return conn


def ingest_snapshot(conn: sqlite3.Connection, capture_file: str, rows: list[SnapshotAssetRow],
                     issued: bool = False) -> int:
    cur = conn.execute(
        "INSERT INTO snapshots (created_at, capture_file, issued) VALUES (?, ?, ?)",
        (datetime.now(timezone.utc).isoformat(), capture_file, int(issued)),
    )
    snapshot_id = cur.lastrowid
    conn.executemany(
        "INSERT INTO snapshot_assets "
        "(snapshot_id, mac, ip, vendor, model, role, zone, protocol, vendor_locked, cpe23) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        [(snapshot_id, r.mac, r.ip, r.vendor, r.model, r.role, r.zone, r.protocol,
          int(r.vendor_locked), r.cpe23) for r in rows],
    )
    conn.commit()
    return snapshot_id


def mark_issued(conn: sqlite3.Connection, snapshot_id: int) -> None:
    conn.execute("UPDATE snapshots SET issued = 1 WHERE snapshot_id = ?", (snapshot_id,))
    conn.commit()


def latest_issued_snapshot_id(conn: sqlite3.Connection) -> int | None:
    row = conn.execute(
        "SELECT snapshot_id FROM snapshots WHERE issued = 1 ORDER BY snapshot_id DESC LIMIT 1"
    ).fetchone()
    return row[0] if row else None


def latest_snapshot_id(conn: sqlite3.Connection) -> int | None:
    row = conn.execute("SELECT snapshot_id FROM snapshots ORDER BY snapshot_id DESC LIMIT 1").fetchone()
    return row[0] if row else None


def snapshot_macs(conn: sqlite3.Connection, snapshot_id: int) -> set[str]:
    rows = conn.execute("SELECT mac FROM snapshot_assets WHERE snapshot_id = ?", (snapshot_id,)).fetchall()
    return {r[0] for r in rows}


def snapshot_asset_rows(conn: sqlite3.Connection, snapshot_id: int) -> list[SnapshotAssetRow]:
    rows = conn.execute(
        "SELECT mac, ip, vendor, model, role, zone, protocol, vendor_locked, cpe23 "
        "FROM snapshot_assets WHERE snapshot_id = ?", (snapshot_id,),
    ).fetchall()
    return [SnapshotAssetRow(mac=r[0], ip=r[1], vendor=r[2], model=r[3], role=r[4], zone=r[5],
                              protocol=r[6], vendor_locked=bool(r[7]), cpe23=r[8]) for r in rows]


def compute_drift(conn: sqlite3.Connection, current_snapshot_id: int) -> list[str]:
    """Return the MACs present in `current_snapshot_id` but absent from the
    most recently issued diagram's snapshot. Returns [] (and the caller
    should treat that as "no issued diagram yet") if none has been issued.
    """
    issued_id = latest_issued_snapshot_id(conn)
    current = snapshot_macs(conn, current_snapshot_id)
    if issued_id is None:
        return sorted(current)
    issued = snapshot_macs(conn, issued_id)
    return sorted(current - issued)
