"""Programas de Bugcrowd y sus scopes.

Los scopes publicos se toman del dataset de bounty-targets-data, que rastrea
las paginas publicas de Bugcrowd a diario. Para programas privados (los que no
son publicos) se importa el scope a mano con `hdb program import`.
"""

from __future__ import annotations

import re
import sqlite3
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

from . import fetch, store
from .scope import IN_SCOPE, OUT_OF_SCOPE, Rule, parse_target

BUGCROWD_DATA_URL = "https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/main/data/bugcrowd_data.json"


def slug_from_url(url: str, name: str) -> str:
    match = re.search(r"bugcrowd\.com/(?:engagements/)?([A-Za-z0-9_.-]+)", url or "")
    if match:
        return match.group(1).lower()
    return re.sub(r"[^a-z0-9]+", "-", (name or "programa").lower()).strip("-") or "programa"


def sync(conn: sqlite3.Connection, url: str = BUGCROWD_DATA_URL) -> Tuple[int, int]:
    """Descarga todos los programas publicos. Devuelve (programas, targets)."""
    payload = fetch.get_json(url)
    stamp = store.now()
    n_programs = 0
    n_targets = 0
    for item in payload:
        slug = slug_from_url(item.get("url", ""), item.get("name", ""))
        conn.execute(
            """INSERT INTO programs(slug, name, url, platform, max_payout, safe_harbor, managed, disclosure, synced_at)
               VALUES(?,?,?,'bugcrowd',?,?,?,?,?)
               ON CONFLICT(slug) DO UPDATE SET
                 name=excluded.name, url=excluded.url, max_payout=excluded.max_payout,
                 safe_harbor=excluded.safe_harbor, managed=excluded.managed,
                 disclosure=excluded.disclosure, synced_at=excluded.synced_at""",
            (
                slug,
                (item.get("name") or "").strip(),
                item.get("url"),
                item.get("max_payout"),
                item.get("safe_harbor"),
                1 if item.get("managed_by_bugcrowd") else 0,
                1 if item.get("allows_disclosure") else 0,
                stamp,
            ),
        )
        n_programs += 1
        conn.execute("DELETE FROM targets WHERE program_slug = ?", (slug,))
        targets = item.get("targets") or {}
        for category, key in ((IN_SCOPE, "in_scope"), (OUT_OF_SCOPE, "out_of_scope")):
            for entry in targets.get(key) or []:
                target = (entry.get("target") or entry.get("uri") or "").strip()
                if not target:
                    continue
                conn.execute(
                    """INSERT OR IGNORE INTO targets(program_slug, category, target, target_type, name)
                       VALUES(?,?,?,?,?)""",
                    (slug, category, target, (entry.get("type") or "").strip(), (entry.get("name") or "").strip()),
                )
                n_targets += 1
    store.set_meta(conn, "programs_synced_at", stamp)
    return n_programs, n_targets


def upsert_manual(
    conn: sqlite3.Connection,
    slug: str,
    name: str,
    in_scope: Iterable[str],
    out_of_scope: Iterable[str],
    url: str = "",
    replace: bool = True,
) -> int:
    """Crea o actualiza un programa a mano (util para programas privados)."""
    conn.execute(
        """INSERT INTO programs(slug, name, url, platform, synced_at)
           VALUES(?,?,?,'bugcrowd',?)
           ON CONFLICT(slug) DO UPDATE SET name=excluded.name, url=excluded.url, synced_at=excluded.synced_at""",
        (slug, name or slug, url, store.now()),
    )
    if replace:
        conn.execute("DELETE FROM targets WHERE program_slug = ?", (slug,))
    count = 0
    for category, values in ((IN_SCOPE, in_scope), (OUT_OF_SCOPE, out_of_scope)):
        for raw in values:
            raw = raw.strip()
            if not raw or raw.startswith("#"):
                continue
            conn.execute(
                "INSERT OR IGNORE INTO targets(program_slug, category, target, target_type, name) VALUES(?,?,?,'','')",
                (slug, category, raw),
            )
            count += 1
    return count


def get_program(conn: sqlite3.Connection, slug: str) -> Optional[sqlite3.Row]:
    return conn.execute("SELECT * FROM programs WHERE slug = ?", (slug,)).fetchone()


def resolve_slug(conn: sqlite3.Connection, needle: str) -> List[str]:
    """Acepta el slug exacto o un fragmento del nombre."""
    needle = needle.strip().lower()
    if get_program(conn, needle):
        return [needle]
    rows = conn.execute(
        "SELECT slug FROM programs WHERE lower(slug) LIKE ? OR lower(name) LIKE ? ORDER BY slug",
        (f"%{needle}%", f"%{needle}%"),
    ).fetchall()
    return [r["slug"] for r in rows]


def rules_for(conn: sqlite3.Connection, slug: str) -> List[Rule]:
    rows = conn.execute(
        "SELECT category, target, target_type, name FROM targets WHERE program_slug = ?", (slug,)
    ).fetchall()
    return [parse_target(r["target"], r["category"], r["target_type"], r["name"]) for r in rows]


def all_rules(conn: sqlite3.Connection) -> Dict[str, List[Rule]]:
    out: Dict[str, List[Rule]] = {}
    rows = conn.execute(
        "SELECT program_slug, category, target, target_type, name FROM targets ORDER BY program_slug"
    ).fetchall()
    for r in rows:
        out.setdefault(r["program_slug"], []).append(
            parse_target(r["target"], r["category"], r["target_type"], r["name"])
        )
    return out


def search(
    conn: sqlite3.Connection,
    needle: str = "",
    min_payout: int = 0,
    safe_harbor: str = "",
    limit: int = 40,
) -> Sequence[sqlite3.Row]:
    sql = "SELECT * FROM programs WHERE 1=1"
    args: List[object] = []
    if needle:
        sql += " AND (lower(name) LIKE ? OR lower(slug) LIKE ?)"
        args += [f"%{needle.lower()}%", f"%{needle.lower()}%"]
    if min_payout:
        sql += " AND COALESCE(max_payout, 0) >= ?"
        args.append(min_payout)
    if safe_harbor:
        sql += " AND lower(COALESCE(safe_harbor,'')) = ?"
        args.append(safe_harbor.lower())
    sql += " ORDER BY COALESCE(max_payout,0) DESC, name LIMIT ?"
    args.append(limit)
    return conn.execute(sql, args).fetchall()
