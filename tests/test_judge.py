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


def test_estimate_cost_opus():
    # 1M entrada + 1M salida en opus-5 = 5 + 25 = 30 USD
    assert abs(judge.estimate_cost("claude-opus-5", 1_000_000, 1_000_000) - 30.0) < 1e-6


def test_estimate_cost_haiku_is_cheaper():
    opus = judge.estimate_cost("claude-opus-5", 3000, 1500)
    haiku = judge.estimate_cost("claude-haiku-4-5", 3000, 1500)
    assert haiku < opus


def test_analyze_reports_usage_and_cost(monkeypatch):
    import json as _json, sys as _sys, types as _types
    payload = {
        "is_vulnerability": "no", "confidence": 10, "vuln_class": "", "vrt_id": "",
        "priority_estimate": "N/A", "reasoning": "config esperada",
        "what_is_missing": [], "next_tests": [], "false_positive_risks": [],
    }
    fake = _types.ModuleType("anthropic")

    class _Msg:
        def __init__(self, text):
            self.content = [_types.SimpleNamespace(type="text", text=text)]
            self.usage = _types.SimpleNamespace(input_tokens=2000, output_tokens=1000)

    class _Stream:
        def __init__(self, text): self._t = text
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def get_final_message(self): return _Msg(self._t)

    class _Messages:
        def stream(self, **k): return _Stream(_json.dumps(payload))

    class Anthropic:
        def __init__(self, *a, **k): self.messages = _Messages()

    fake.Anthropic = Anthropic
    monkeypatch.setitem(_sys.modules, "anthropic", fake)
    j = judge.analyze("evidencia", model="claude-opus-5")
    assert j.input_tokens == 2000 and j.output_tokens == 1000
    assert j.cost_usd > 0


def test_ollama_backend_is_free(monkeypatch):
    import io, json as _json
    from hdb import judge as _judge
    payload = {
        "is_vulnerability": "probable", "confidence": 60, "vuln_class": "IDOR",
        "vrt_id": "broken_access_control.idor.x", "priority_estimate": "P3",
        "reasoning": "posible acceso cruzado", "what_is_missing": [], "next_tests": [],
        "false_positive_risks": [],
    }
    server_resp = _json.dumps({"message": {"content": _json.dumps(payload)}}).encode()

    captured = {}
    def fake_urlopen(req, timeout=0):
        captured["url"] = req.full_url
        captured["body"] = _json.loads(req.data.decode())
        class R:
            def __enter__(self): return self
            def __exit__(self, *a): return False
            def read(self): return server_resp
        return R()
    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)

    j = _judge.analyze("REQ/RESP", backend="ollama", model="llama3.1")
    assert j.cost_usd == 0.0
    assert j.model == "ollama:llama3.1"
    assert j.is_vulnerability == "probable"
    assert captured["url"].endswith("/api/chat")
    assert captured["body"]["model"] == "llama3.1"


def test_ollama_connection_error_is_friendly(monkeypatch):
    import urllib.error
    from hdb import judge as _judge
    def boom(req, timeout=0):
        raise urllib.error.URLError("connection refused")
    monkeypatch.setattr("urllib.request.urlopen", boom)
    import pytest
    with pytest.raises(_judge.JudgeUnavailable):
        _judge.analyze("evidencia", backend="ollama")
