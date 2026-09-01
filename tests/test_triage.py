import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from hdb import triage  # noqa: E402


def test_idor_max_impact_is_p1():
    v = triage.assess("idor", {"crossuser": True, "sensitive": True, "modify": True, "iterable": True})
    assert v.priority == 1
    assert v.headline == "SI, importante"
    assert "iterable" in v.vrt_id


def test_idor_view_only_sensitive_is_p3():
    v = triage.assess("idor", {"crossuser": True, "sensitive": True, "modify": False, "iterable": True})
    assert v.priority == 3


def test_idor_without_crossuser_is_unconfirmed():
    v = triage.assess("idor", {"crossuser": False, "sensitive": True, "modify": True, "iterable": True})
    assert v.priority is None
    assert v.headline == "Sin confirmar"


def test_idor_guid_lowers_priority():
    v = triage.assess("idor", {"crossuser": True, "sensitive": True, "modify": True, "iterable": False})
    assert v.priority == 4
    assert "guid" in v.vrt_id


def test_cors_reflect_without_creds_is_low():
    v = triage.assess("cors", {"reflect": True, "creds": False, "sensitive": True})
    assert v.priority == 5


def test_cors_no_reflect_is_ineligible():
    v = triage.assess("cors", {"reflect": False})
    assert v.eligible is False
    assert v.priority is None


def test_secrets_public_key_is_ineligible():
    v = triage.assess("secrets", {"public": True})
    assert v.eligible is False


def test_secrets_valid_with_scope_is_p1():
    v = triage.assess("secrets", {"public": False, "valid": True, "scope": True})
    assert v.priority == 1


def test_redirect_chained_reports_as_ato():
    v = triage.assess("redirect", {"external": True, "chain": True})
    assert v.priority == 2
    assert "account_takeover" in v.vrt_id


def test_redirect_isolated_is_low():
    v = triage.assess("redirect", {"external": True, "chain": False})
    assert v.priority == 4


def test_auth_full_bypass_is_p1():
    v = triage.assess("auth", {"full": True})
    assert v.priority == 1


def test_ssrf_secrets_is_p2():
    v = triage.assess("ssrf", {"secrets": True})
    assert v.priority == 2


def test_universal_warnings_always_present():
    v = triage.assess("idor", {"crossuser": True, "sensitive": True, "modify": True, "iterable": True})
    assert any("duplicados" in w for w in v.warnings)
    assert any("no ha visto el target" in w for w in v.warnings)


def test_unknown_playbook_raises():
    import pytest
    with pytest.raises(KeyError):
        triage.assess("xxe", {})
