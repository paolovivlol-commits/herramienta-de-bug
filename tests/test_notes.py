import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))


def fresh_conn():
    d = tempfile.mkdtemp()
    os.environ["HDB_HOME"] = d
    from hdb import store
    import importlib
    importlib.reload(store)
    return store.connect()


def test_add_and_list_notes():
    from hdb import notes
    conn = fresh_conn()
    notes.add(conn, "acme", "probar idor en /orders", target="https://acme/orders/1", playbook="idor")
    rows = notes.listing(conn, "acme")
    assert len(rows) == 1
    assert rows[0]["status"] == "todo"


def test_mark_status_and_ordering():
    from hdb import notes
    conn = fresh_conn()
    a = notes.add(conn, "acme", "a", status="clear")
    b = notes.add(conn, "acme", "b", status="testing")
    notes.add(conn, "acme", "c", status="todo")
    assert notes.set_status(conn, a, "confirmed")
    rows = notes.listing(conn, "acme")
    # testing primero, luego todo, luego confirmed, luego clear
    assert rows[0]["id"] == b
    assert [r["status"] for r in rows][:2] == ["testing", "todo"]


def test_seed_from_points_dedups():
    from hdb import notes
    from hdb.bob import CriticalPoint
    conn = fresh_conn()
    pts = [CriticalPoint("https://acme/api/x", "idor", "por que", 90)]
    assert notes.seed_from_points(conn, "acme", pts) == 1
    assert notes.seed_from_points(conn, "acme", pts) == 0  # no duplica
    assert len(notes.listing(conn, "acme")) == 1
