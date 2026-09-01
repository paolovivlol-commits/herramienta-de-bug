import json
import sys
import types
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from hdb import judge  # noqa: E402


def test_build_prompt_includes_all_parts():
    p = judge.build_prompt("EVIDENCIA_HTTP", context="sospecho IDOR", target="https://t/x")
    assert "EVIDENCIA_HTTP" in p
    assert "sospecho IDOR" in p
    assert "https://t/x" in p


def test_empty_evidence_raises():
    import pytest
    with pytest.raises(ValueError):
        judge.analyze("   ")


def test_judgment_from_dict_roundtrip():
    d = {
        "is_vulnerability": "si", "confidence": 90, "vuln_class": "IDOR",
        "vrt_id": "broken_access_control.idor.x", "priority_estimate": "P1",
        "reasoning": "la respuesta trae datos de otro usuario",
        "what_is_missing": [], "next_tests": ["probar modificar"], "false_positive_risks": ["podrian ser datos propios"],
    }
    j = judge.Judgment.from_dict(d, model="claude-opus-5")
    assert j.is_vulnerability == "si" and j.confidence == 90
    assert j.priority_estimate == "P1"
    assert j.model == "claude-opus-5"


def _install_fake_anthropic(monkeypatch, payload: dict, capture: dict):
    """Inyecta un modulo anthropic falso que devuelve `payload` como JSON."""
    fake = types.ModuleType("anthropic")

    class _Msg:
        def __init__(self, text):
            self.content = [types.SimpleNamespace(type="text", text=text)]

    class _Stream:
        def __init__(self, text):
            self._text = text
        def __enter__(self):
            return self
        def __exit__(self, *a):
            return False
        def get_final_message(self):
            return _Msg(self._text)

    class _Messages:
        def stream(self, **kwargs):
            capture.update(kwargs)
            return _Stream(json.dumps(payload))

    class Anthropic:
        def __init__(self, *a, **k):
            self.messages = _Messages()

    fake.Anthropic = Anthropic
    monkeypatch.setitem(sys.modules, "anthropic", fake)


def test_analyze_parses_model_json(monkeypatch):
    payload = {
        "is_vulnerability": "probable", "confidence": 70, "vuln_class": "CORS",
        "vrt_id": "server_security_misconfiguration.unsafe_cross_origin_resource_sharing",
        "priority_estimate": "P3", "reasoning": "refleja el origin con credenciales",
        "what_is_missing": ["confirmar datos sensibles"], "next_tests": ["repetir con Origin atacante"],
        "false_positive_risks": ["endpoint sin datos sensibles"],
    }
    capture = {}
    _install_fake_anthropic(monkeypatch, payload, capture)
    j = judge.analyze("REQ/RESP", context="cors?", target="https://t/api", model="claude-opus-5")
    assert j.is_vulnerability == "probable"
    assert j.priority_estimate == "P3"
    # se envio el modelo correcto y el esquema estructurado
    assert capture["model"] == "claude-opus-5"
    assert capture["output_config"]["format"]["type"] == "json_schema"
    assert capture["thinking"] == {"type": "adaptive"}


def test_analyze_auth_error_becomes_unavailable(monkeypatch):
    fake = types.ModuleType("anthropic")

    class Anthropic:
        def __init__(self, *a, **k):
            pass
        @property
        def messages(self):
            raise RuntimeError("Could not resolve authentication method. Expected api_key")

    fake.Anthropic = Anthropic
    monkeypatch.setitem(sys.modules, "anthropic", fake)
    import pytest
    with pytest.raises(judge.JudgeUnavailable):
        judge.analyze("evidencia")
