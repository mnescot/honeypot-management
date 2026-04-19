"""
SQLite data layer for remote node management.

Uses aiosqlite with WAL mode. One shared connection on app.state.db;
SQLite serialises writers, WAL keeps readers non-blocking.
"""
from __future__ import annotations

import hashlib
import logging
from datetime import datetime, timezone
from pathlib import Path

import aiosqlite

log = logging.getLogger("honeypot-mgmt.db")

DB_PATH = Path("/var/lib/honeypot-mgmt/state.db")

MIGRATIONS = [
    # v1: initial schema
    """
    CREATE TABLE IF NOT EXISTS nodes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        label TEXT UNIQUE NOT NULL,
        hostname TEXT,
        os_id TEXT,
        os_version TEXT,
        agent_version TEXT,
        token_sha256 TEXT UNIQUE,
        public_ip TEXT,
        enrolled_at TEXT,
        last_seen TEXT,
        last_status TEXT,
        revoked_at TEXT,
        created_at TEXT NOT NULL,
        created_by TEXT
    );
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_nodes_last_seen ON nodes(last_seen);
    """,
    """
    CREATE TABLE IF NOT EXISTS enrolment_tokens (
        token_sha256 TEXT PRIMARY KEY,
        label TEXT NOT NULL,
        expires_at TEXT NOT NULL,
        used_at TEXT,
        created_at TEXT NOT NULL,
        created_by TEXT
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS commands (
        id TEXT PRIMARY KEY,
        node_id INTEGER NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
        type TEXT NOT NULL,
        payload_json TEXT NOT NULL,
        created_at TEXT NOT NULL,
        created_by TEXT,
        delivered_at TEXT,
        ack_at TEXT,
        ack_status TEXT,
        ack_output TEXT
    );
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_commands_pending
        ON commands(node_id, ack_at);
    """,
    """
    CREATE TABLE IF NOT EXISTS honeypots (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        node_id INTEGER NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
        kind TEXT NOT NULL,
        container_name TEXT,
        config_yaml TEXT,
        state TEXT,
        updated_at TEXT NOT NULL
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS events_ingest (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        node_id INTEGER NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
        received_at TEXT NOT NULL,
        count INTEGER NOT NULL,
        indexed INTEGER NOT NULL DEFAULT 0
    );
    """,
]


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def sha256(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()


async def connect(path: Path = DB_PATH) -> aiosqlite.Connection:
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = await aiosqlite.connect(str(path))
    conn.row_factory = aiosqlite.Row
    await conn.execute("PRAGMA journal_mode=WAL")
    await conn.execute("PRAGMA synchronous=NORMAL")
    await conn.execute("PRAGMA busy_timeout=5000")
    await conn.execute("PRAGMA foreign_keys=ON")
    for migration in MIGRATIONS:
        await conn.executescript(migration)
    await conn.commit()
    log.info("SQLite ready at %s", path)
    return conn
