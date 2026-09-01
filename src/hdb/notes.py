"""Memoria de la sesion de caza.

BOB apunta que estas probando en cada punto y en que estado esta, para que no
pierdas el hilo ni repitas trabajo. Es un cuaderno, no un escaner.

Estados: todo (pendiente), testing (probandolo), confirmed (bug!), clear (probado,
nada), skip (fuera de interes/scope).
"""

from __future__ import annotations

import sqlite3
from typing import List, Optional, Sequence

from . import store

STATUSES = store.NOTE_STATUSES


def add(
    conn: sqlite3.Connection,
    program_slug: str,
    text: str,
    target: str = "",
    playbook: str = "",
    status: str = "todo",
) -> int:
    stamp = store.now()
    cur = conn.execute(
        """INSERT INTO notes(program_slug, target, playbook, status, text, created_at, updated_at)
           VALUES(?,?,?,?,?,?,?)""",
        (program_slug, target, playbook, status, text, stamp, stamp),
    )
    return int(cur.lastrowid)


def set_status(conn: sqlite3.Connection, note_id: int, status: str, text: str = "") -> bool:
    fields = "status = ?, updated_at = ?"
    args: List[object] = [status, store.now()]
    if text:
        fields = "status = ?, text = ?, updated_at = ?"
        args = [status, text, store.now()]
    args.append(note_id)
    cur = conn.execute(f"UPDATE notes SET {fields} WHERE id = ?", args)
    return cur.rowcount > 0


def listing(conn: sqlite3.Connection, program: str = "", status: str = "") -> Sequence[sqlite3.Row]:
    sql = "SELECT * FROM notes WHERE 1=1"
    args: List[object] = []
    if program:
        sql += " AND program_slug = ?"
        args.append(program)
    if status:
        sql += " AND status = ?"
        args.append(status)
    # primero lo que sigue abierto (todo, testing), luego confirmados, al final el resto
    sql += """ ORDER BY CASE status
                 WHEN 'testing' THEN 0 WHEN 'todo' THEN 1 WHEN 'confirmed' THEN 2
                 WHEN 'clear' THEN 3 ELSE 4 END, updated_at DESC"""
    return conn.execute(sql, args).fetchall()


def seed_from_points(conn: sqlite3.Connection, program_slug: str, points) -> int:
    """Crea notas 'todo' a partir de los puntos criticos de BOB, sin duplicar."""
    created = 0
    for cp in points:
        exists = conn.execute(
            "SELECT 1 FROM notes WHERE program_slug = ? AND target = ? AND playbook = ?",
            (program_slug, cp.where, cp.playbook_id),
        ).fetchone()
        if exists:
            continue
        add(conn, program_slug, cp.why, cp.where, cp.playbook_id, "todo")
        created += 1
    return created
