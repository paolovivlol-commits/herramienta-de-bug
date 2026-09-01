import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from hdb.scope import IN_SCOPE, NOT_LISTED, OUT_OF_SCOPE, Query, check, parse_target  # noqa: E402


def rules(in_scope=(), out_of_scope=(), types=None):
    types = types or {}
    out = [parse_target(t, IN_SCOPE, types.get(t, "")) for t in in_scope]
    out += [parse_target(t, OUT_OF_SCOPE, types.get(t, "")) for t in out_of_scope]
    return out


def test_query_parsing_strips_port_and_scheme():
    q = Query.parse("https://Api.Example.com:8443/v1/users?id=1")
    assert q.host == "api.example.com"
    assert q.path == "/v1/users"


def test_bare_host_without_scheme():
    q = Query.parse("api.example.com/v1")
    assert q.host == "api.example.com"
    assert q.path == "/v1"


def test_wildcard_covers_subdomains_and_apex():
    rule = parse_target("*.example.com", IN_SCOPE)
    assert rule.kind == "wildcard"
    assert rule.matches(Query.parse("https://a.b.example.com"))
    assert rule.matches(Query.parse("example.com"))
    assert not rule.matches(Query.parse("notexample.com"))
    assert not rule.matches(Query.parse("example.com.evil.net"))


def test_bare_domain_does_not_cover_subdomains():
    rule = parse_target("https://example.com/", IN_SCOPE)
    assert rule.kind == "domain"
    assert rule.matches(Query.parse("https://example.com/anything"))
    assert not rule.matches(Query.parse("https://sub.example.com"))


def test_url_target_requires_path_prefix():
    rule = parse_target("https://example.com/api/v2", IN_SCOPE)
    assert rule.kind == "url"
    assert rule.matches(Query.parse("https://example.com/api/v2/users"))
    assert not rule.matches(Query.parse("https://example.com/admin"))


def test_cidr_matches_ip():
    rule = parse_target("10.0.0.0/24", IN_SCOPE)
    assert rule.kind == "cidr"
    assert rule.matches(Query.parse("10.0.0.9"))
    assert not rule.matches(Query.parse("10.0.1.9"))


def test_out_of_scope_beats_in_scope():
    rs = rules(in_scope=["*.example.com"], out_of_scope=["https://blog.example.com"])
    assert check("https://blog.example.com/post", rs).status == OUT_OF_SCOPE
    assert check("https://app.example.com", rs).status == IN_SCOPE


def test_unknown_host_is_never_allowed():
    rs = rules(in_scope=["*.example.com"])
    verdict = check("https://otro.com", rs)
    assert verdict.status == NOT_LISTED
    assert verdict.allowed is False
    assert verdict.exit_code == 2


def test_mobile_target_is_flagged_for_manual_review():
    rule = parse_target("com.example.android.app", IN_SCOPE, "android")
    assert rule.kind == "non_network"
    assert rule.automatable is False


def test_free_text_target_is_not_matchable():
    rule = parse_target("Cualquier host de produccion de la empresa", IN_SCOPE)
    assert rule.automatable is False
    assert not rule.matches(Query.parse("https://example.com"))


def test_glob_in_the_middle_is_not_guessed():
    rule = parse_target("api-*.example.com", IN_SCOPE)
    assert rule.kind == "unparsed"
    assert not rule.matches(Query.parse("api-prod.example.com"))


def test_wildcard_with_path_scopes_the_path_too():
    rule = parse_target("*.example.com/api", IN_SCOPE)
    assert rule.kind == "wildcard"
    assert rule.matches(Query.parse("https://a.example.com/anything"))


def test_exit_codes_are_scriptable():
    rs = rules(in_scope=["*.example.com"], out_of_scope=["dev.example.com"])
    assert check("app.example.com", rs).exit_code == 0
    assert check("dev.example.com", rs).exit_code == 1
    assert check("otro.net", rs).exit_code == 2
