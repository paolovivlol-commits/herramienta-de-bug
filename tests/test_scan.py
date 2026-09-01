import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from hdb import scan  # noqa: E402


def resp(headers=None, cookies=None, body="", scheme="https", status=200):
    return scan.Response(
        url=f"{scheme}://t.example/",
        final_url=f"{scheme}://t.example/",
        status=status,
        headers={k.lower(): v for k, v in (headers or {}).items()},
        set_cookie=cookies or [],
        body=body,
        scheme=scheme,
    )


def test_only_read_only_methods_allowed():
    import pytest

    with pytest.raises(ValueError):
        scan.fetch("https://t.example", method="POST")


def test_missing_headers_are_reported():
    issues = scan.check_security_headers(resp(headers={}))
    ids = {i.vrt_id for i in issues}
    assert "server_security_misconfiguration.lack_of_security_headers.content_security_policy" in ids
    assert "server_security_misconfiguration.lack_of_security_headers.strict_transport_security" in ids


def test_present_headers_are_not_reported():
    full = {
        "strict-transport-security": "max-age=63072000",
        "content-security-policy": "default-src 'self'",
        "x-content-type-options": "nosniff",
        "x-frame-options": "DENY",
    }
    assert scan.check_security_headers(resp(headers=full)) == []


def test_hsts_not_expected_over_http():
    issues = scan.check_security_headers(resp(headers={}, scheme="http"))
    ids = {i.vrt_id for i in issues}
    assert "server_security_misconfiguration.lack_of_security_headers.strict_transport_security" not in ids


def test_clickjacking_only_without_protection():
    assert scan.check_clickjacking(resp(headers={}))
    assert not scan.check_clickjacking(resp(headers={"x-frame-options": "DENY"}))
    assert not scan.check_clickjacking(resp(headers={"content-security-policy": "frame-ancestors 'none'"}))


def test_session_cookie_without_flags_is_higher_priority():
    issues = scan.check_cookies(resp(cookies=["sessionid=abc; Path=/"]))
    assert issues
    assert issues[0].priority == 4
    assert "session_token" in issues[0].vrt_id


def test_secure_httponly_cookie_is_clean():
    assert scan.check_cookies(resp(cookies=["sessionid=abc; Secure; HttpOnly"])) == []


def test_cors_wildcard_without_credentials_is_ignored():
    r = resp(headers={"access-control-allow-origin": "*"})
    assert scan.check_cors(r) == []


def test_cors_reflected_origin_with_credentials_is_flagged():
    r = resp(headers={
        "access-control-allow-origin": scan.PROBE_ORIGIN,
        "access-control-allow-credentials": "true",
    })
    issues = scan.check_cors(r)
    assert issues and issues[0].priority == 3


def test_mixed_content_detected_on_https():
    r = resp(body='<img src="http://cdn.evil/x.png">', scheme="https")
    assert scan.check_mixed_content(r)
    assert scan.check_mixed_content(resp(body='<img src="https://cdn/x.png">')) == []


def test_server_version_disclosure():
    assert scan.check_server_disclosure(resp(headers={"server": "nginx/1.18.0"}))
    assert scan.check_server_disclosure(resp(headers={"server": "nginx"})) == []


def test_http_without_redirect_is_cleartext():
    http = resp(scheme="http", status=200)
    issues = scan.check_https_downgrade(http)
    assert issues and "cleartext" in issues[0].vrt_id


def test_http_redirecting_to_https_is_clean():
    http = scan.Response("http://t.example/", "http://t.example/", 301,
                         {"location": "https://t.example/"}, [], "", "http")
    assert scan.check_https_downgrade(http) == []
