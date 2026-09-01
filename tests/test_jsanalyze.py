import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from hdb import jsanalyze as js  # noqa: E402


def test_detects_aws_key():
    rep = js.analyze_text("x.js", 'var k = "AKIAIOSFODNN7EXAMPLE";')
    labels = [h.label for h in rep.secrets]
    assert "AWS Access Key" in labels


def test_masks_secret_value():
    rep = js.analyze_text("x.js", 'const t = "ghp_' + "a" * 36 + '";')
    hit = rep.secrets[0]
    assert "..." in hit.value and "ghp_" in hit.value


def test_extracts_internal_endpoints():
    body = 'fetch("/api/v1/users"); get("/admin/panel"); x("/public/img.png")'
    rep = js.analyze_text("x.js", body)
    eps = {h.value for h in rep.hits if h.kind == "endpoint"}
    assert "/api/v1/users" in eps
    assert "/admin/panel" in eps
    assert "/public/img.png" not in eps  # no es ruta de api/admin


def test_ignores_noise_urls():
    body = '"http://www.w3.org/2000/svg" "https://api.realtarget.com/v2/orders"'
    rep = js.analyze_text("x.js", body)
    urls = {h.value for h in rep.hits if h.kind == "url"}
    assert "https://api.realtarget.com/v2/orders" in urls
    assert not any("w3.org" in u for u in urls)


def test_stripe_secret_vs_publishable():
    rep = js.analyze_text("x.js", 'a="sk_live_' + "a" * 30 + '"; b="pk_live_' + "b" * 30 + '"')
    labels = [h.label for h in rep.secrets]
    assert "Stripe Secret Key" in labels
    assert "Stripe Publishable" in labels
