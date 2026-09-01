"""Seguimiento de hallazgos: del borrador al pago."""

from __future__ import annotations

import sqlite3
from typing import List, Optional, Sequence

from . import store

STATUSES = store.FINDING_STATUSES


def create(
    conn: sqlite3.Connection,
    program_slug: str,
    title: str,
    vrt_id: str = "",
    priority: Optional[int] = None,
    target: str = "",
    notes: str = "",
) -> int:
    stamp = store.now()
    cur = conn.execute(
        """INSERT INTO findings(program_slug, title, vrt_id, priority, target, status, notes, created_at, updated_at)
           VALUES(?,?,?,?,?,'draft',?,?,?)""",
        (program_slug, title, vrt_id, priority, target, notes, stamp, stamp),
    )
    return int(cur.lastrowid)


def update(conn: sqlite3.Connection, finding_id: int, **fields) -> bool:
    allowed = {"title", "vrt_id", "priority", "target", "status", "notes"}
    sets = {k: v for k, v in fields.items() if k in allowed and v is not None}
    if not sets:
        return False
    clause = ", ".join(f"{k} = ?" for k in sets)
    args: List[object] = list(sets.values()) + [store.now(), finding_id]
    cur = conn.execute(f"UPDATE findings SET {clause}, updated_at = ? WHERE id = ?", args)
    return cur.rowcount > 0


def get(conn: sqlite3.Connection, finding_id: int) -> Optional[sqlite3.Row]:
    return conn.execute("SELECT * FROM findings WHERE id = ?", (finding_id,)).fetchone()


def listing(conn: sqlite3.Connection, program: str = "", status: str = "") -> Sequence[sqlite3.Row]:
    sql = "SELECT * FROM findings WHERE 1=1"
    args: List[object] = []
    if program:
        sql += " AND program_slug = ?"
        args.append(program)
    if status:
        sql += " AND status = ?"
        args.append(status)
    sql += " ORDER BY COALESCE(priority, 9), updated_at DESC"
    return conn.execute(sql, args).fetchall()
