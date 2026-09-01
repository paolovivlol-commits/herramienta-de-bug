import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from hdb import report  # noqa: E402


def test_render_fills_vrt_details():
    body = report.render(
        "IDOR en /api/users", program="Acme", program_slug="acme", target="https://api.acme.com/users/1",
        vrt_id="broken_access_control.idor.modify_view_sensitive_information_iterable_object_identifiers",
    )
    assert "IDOR en /api/users" in body
    assert "Pasos para reproducir" in body
    assert "hdb scope check" in body
    assert "acme" in body
    assert "P1" in body


def test_render_without_vrt_still_works():
    body = report.render("Algo raro")
    assert "hdb vrt search" in body
