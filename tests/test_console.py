"""El programa no debe crashear en consolas no-UTF8 (Windows cmd.exe / cp1252)."""

import io
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from hdb import cli  # noqa: E402


def test_setup_console_survives_cp1252_and_prints_emoji():
    old = sys.stdout
    stream = io.TextIOWrapper(io.BytesIO(), encoding="cp1252")
    sys.stdout = stream
    try:
        cli.setup_console()
        # emoji + acentos + guion largo: lo que tumbaba a Windows
        print("\U0001F916 BOB: señal ¿crítico? — café")  # no debe lanzar
    finally:
        sys.stdout = old


def test_no_color_env_disables_ansi(monkeypatch):
    monkeypatch.setenv("HDB_NO_COLOR", "1")
    monkeypatch.setattr(cli, "_COLOR_ENABLED", True)
    cli.setup_console()
    assert cli._COLOR_ENABLED is False


def test_paint_returns_plain_when_color_disabled(monkeypatch):
    monkeypatch.setattr(cli, "_COLOR_ENABLED", False)
    assert cli.paint("hola", "red") == "hola"
