import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))


def run(args, home):
    os.environ["HDB_HOME"] = home
    import importlib
    from hdb import store, cli
    importlib.reload(store)
    importlib.reload(cli)
    return cli.main(args)


def test_capture_and_status_flow(capsys):
    home = tempfile.mkdtemp()
    ev = Path(tempfile.mkdtemp()) / "ev.txt"
    ev.write_text("GET /api/orders/124\n\n200 OK\n{\"owner\":\"otro\"}", encoding="utf-8")

    # importar programa
    ins = Path(tempfile.mkdtemp()) / "in.txt"
    ins.write_text("*.example.com\n", encoding="utf-8")
    assert run(["program", "import", "demo", "--in-scope", str(ins)], home) == 0

    # capturar evidencia (sin juez)
    rc = run(["bob", "capture", "-p", "demo", "-f", str(ev),
              "--target", "https://api.example.com/orders/124", "--playbook", "idor"], home)
    assert rc == 0
    out = capsys.readouterr().out
    assert "evidencia guardada" in out
    # el fichero de evidencia existe
    saved = list((Path(home) / "evidence" / "demo").glob("*.txt"))
    assert saved and "owner" in saved[0].read_text(encoding="utf-8")

    # status refleja la nota en 'testing'
    assert run(["bob", "status", "-p", "demo"], home) == 0
    out = capsys.readouterr().out
    assert "demo" in out and "en curso" in out


def test_scope_check_exit_codes(capsys):
    home = tempfile.mkdtemp()
    ins = Path(tempfile.mkdtemp()) / "in.txt"
    ins.write_text("*.example.com\n", encoding="utf-8")
    run(["program", "import", "demo", "--in-scope", str(ins)], home)
    assert run(["scope", "check", "app.example.com", "-p", "demo"], home) == 0
    assert run(["scope", "check", "otro.com", "-p", "demo"], home) == 2
