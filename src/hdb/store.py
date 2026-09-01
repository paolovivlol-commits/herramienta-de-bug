"""Almacenamiento local en SQLite.

Todo vive en HDB_HOME (por defecto ~/.hdb). Un solo fichero, sin dependencias.
"""

from __future__ import annotations

import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator

SCHEMA = """
CREATE TABLE IF NOT EXISTS programs (
    slug           TEXT PRIMARY KEY,
    name           TEXT NOT NULL,
    url            TEXT,
    platform       TEXT NOT NULL DEFAULT 'bugcrowd',
    max_payout     INTEGER,
    safe_harbor    TEXT,
    managed        INTEGER,
    disclosure     INTEGER,
    synced_at      TEXT
);

CREATE TABLE IF NOT EXISTS targets (
    id           INTEGER PRIMARY KEY,
    program_slug TEXT NOT NULL REFERENCES programs(slug) ON DELETE CASCADE,
    category     TEXT NOT NULL,
    target       TEXT NOT NULL,
    target_type  TEXT,
    name         TEXT,
    UNIQUE (program_slug, category, target, target_type)
);
CREATE INDEX IF NOT EXISTS idx_targets_program ON targets(program_slug);

CREATE TABLE IF NOT EXISTS assets (
    id           INTEGER PRIMARY KEY,
    program_slug TEXT NOT NULL,
    host         TEXT NOT NULL,
    source       TEXT,
    scope_status TEXT,
    first_seen   TEXT NOT NULL,
    last_seen    TEXT NOT NULL,
    UNIQUE (program_slug, host)
);
CREATE INDEX IF NOT EXISTS idx_assets_program ON assets(program_slug);

CREATE TABLE IF NOT EXISTS findings (
    id           INTEGER PRIMARY KEY,
    program_slug TEXT NOT NULL,
    title        TEXT NOT NULL,
    vrt_id       TEXT,
    priority     INTEGER,
    target       TEXT,
    status       TEXT NOT NULL DEFAULT 'draft',
    notes        TEXT,
    created_at   TEXT NOT NULL,
    updated_at   TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT
);
"""

FINDING_STATUSES = ("draft", "submitted", "triaged", "accepted", "duplicate", "not_applicable", "resolved")


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def home() -> Path:
    path = Path(os.environ.get("HDB_HOME", Path.home() / ".hdb"))
    path.mkdir(parents=True, exist_ok=True)
    return path


def db_path() -> Path:
    return home() / "hdb.db"


def connect() -> sqlite3.Connection:
    conn = sqlite3.connect(db_path())
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.executescript(SCHEMA)
    return conn


@contextmanager
def session() -> Iterator[sqlite3.Connection]:
    conn = connect()
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def set_meta(conn: sqlite3.Connection, key: str, value: str) -> None:
    conn.execute(
        "INSERT INTO meta(key, value) VALUES(?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        (key, value),
    )


def get_meta(conn: sqlite3.Connection, key: str, default: str = "") -> str:
    row = conn.execute("SELECT value FROM meta WHERE key = ?", (key,)).fetchone()
    return row["value"] if row else default
