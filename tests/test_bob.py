import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from hdb import bob  # noqa: E402
from hdb.scan import Issue, ScanResult  # noqa: E402
from hdb.surface import Endpoint, SurfaceMap  # noqa: E402


def test_review_ranks_auth_over_redirect():
    sm = SurfaceMap(base="https://t.example")
    sm.endpoints = [
        Endpoint(url="https://t.example/go?next=/x", hints={"redirect"}, params=["next"]),
        Endpoint(url="https://t.example/login", hints={"auth"}),
    ]
    rv = bob.review("https://t.example", sm, None)
    assert rv.critical_points[0].playbook_id == "auth"
    assert rv.critical_points[-1].playbook_id == "redirect"


def test_review_surfaces_js_as_secrets_point():
    sm = SurfaceMap(base="https://t.example")
    sm.js_files = ["https://t.example/app.js"]
    rv = bob.review("https://t.example", sm, None)
    assert any(cp.playbook_id == "secrets" for cp in rv.critical_points)


def test_review_collects_scan_issues_as_quick_wins():
    scan_result = ScanResult(url="https://t.example", reachable=True)
    scan_result.issues = [
        Issue("Falta CSP", "server_security_misconfiguration.lack_of_security_headers.content_security_policy",
              5, "no CSP", "añadir CSP", url="https://t.example")
    ]
    rv = bob.review("https://t.example", None, scan_result)
    assert rv.quick_wins and "CSP" in rv.quick_wins[0]


def test_every_critical_point_maps_to_a_real_playbook():
    sm = SurfaceMap(base="https://t.example")
    sm.endpoints = [
        Endpoint(url="https://t.example/api/orders/1", hints={"idor"}),
        Endpoint(url="https://t.example/import?url=x", hints={"ssrf"}, params=["url"]),
    ]
    rv = bob.review("https://t.example", sm, None)
    for cp in rv.critical_points:
        assert cp.playbook is not None  # no lanza KeyError


def test_dedup_keeps_highest_weight():
    sm = SurfaceMap(base="https://t.example")
    sm.endpoints = [
        Endpoint(url="https://t.example/a", hints={"idor"}),
        Endpoint(url="https://t.example/a", hints={"idor"}, params=["id"]),
    ]
    rv = bob.review("https://t.example", sm, None)
    same = [c for c in rv.critical_points if c.where == "https://t.example/a"]
    assert len(same) == 1
    assert same[0].params == ["id"]


def test_review_folds_js_secrets_as_critical_points():
    from hdb.jsanalyze import JsHit, JsReport
    rep = JsReport(url="https://t.example/app.js", fetched=True, size=10)
    rep.hits = [
        JsHit("secret", "AWS Access Key", "AKIA...aaaa", "critico"),
        JsHit("secret", "Stripe Publishable", "pk_live...", "no suele ser bug"),
    ]
    rv = bob.review("https://t.example", None, None, [rep])
    ids = [cp.playbook_id for cp in rv.critical_points]
    assert ids and all(i == "secrets" for i in ids)
    # el AWS (alto riesgo) va antes que el publishable (bajo riesgo)
    assert "AWS Access Key" in rv.critical_points[0].where
    assert rv.critical_points[0].weight > rv.critical_points[-1].weight


def test_review_without_js_reports_still_works():
    from hdb.surface import Endpoint, SurfaceMap
    sm = SurfaceMap(base="https://t.example")
    sm.endpoints = [Endpoint(url="https://t.example/login", hints={"auth"})]
    rv = bob.review("https://t.example", sm, None)
    assert rv.critical_points[0].playbook_id == "auth"
