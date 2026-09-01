"""Analisis de ficheros JavaScript (solo lectura).

Descarga un .js y busca, mediante patrones, cosas que las apps filtran sin
querer: claves de API, endpoints internos, tokens y URLs. NO ejecuta el JS ni
prueba las claves; solo las señala para que TU las verifiques a mano.

Un match es una PISTA, no una vulnerabilidad. Muchas claves publicas (Google
Maps, Stripe publishable, etc.) son inofensivas por diseño: verifica alcance y
validez antes de reportar.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import List, Pattern, Tuple

from . import scan

# (etiqueta, patron, nota). Patrones conservadores para no ahogar en ruido.
SECRET_PATTERNS: List[Tuple[str, Pattern, str]] = [
    ("AWS Access Key", re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "Clave de acceso AWS: alto impacto si es valida."),
    ("Google API Key", re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b"), "Verifica el alcance; muchas son publicas e inofensivas."),
    ("Slack Token", re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,48}\b"), "Token de Slack: revisa permisos."),
    ("GitHub Token", re.compile(r"\bghp_[0-9A-Za-z]{36}\b"), "Token de GitHub: alto impacto."),
    ("Stripe Secret Key", re.compile(r"\bsk_live_[0-9A-Za-z]{24,}\b"), "Clave SECRETA de Stripe: critico."),
    ("Stripe Publishable", re.compile(r"\bpk_live_[0-9A-Za-z]{24,}\b"), "Publishable: normalmente NO es un bug."),
    ("JWT", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{6,}\b"), "Decodificalo; ¿lleva datos o sigue activo?"),
    ("Private Key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"), "Clave privada embebida: critico."),
    ("Generic Secret", re.compile(r"""(?i)(?:api[_-]?key|secret|passwd|password|token)['"\s]*[:=]['"\s]*([0-9A-Za-z\-_]{16,})"""),
     "Asignacion tipo secreto: revisa el valor a mano."),
]

# Endpoints internos referenciados desde el JS.
ENDPOINT_RE = re.compile(r"""['"`](/(?:api|v\d|internal|admin|graphql|rest)[/A-Za-z0-9_\-.{}:]*)['"`]""")
FULLURL_RE = re.compile(r"""['"`](https?://[A-Za-z0-9.\-]+(?:/[A-Za-z0-9_\-./]*)?)['"`]""")


@dataclass
class JsHit:
    kind: str  # secret | endpoint | url
    label: str
    value: str
    note: str = ""


@dataclass
class JsReport:
    url: str
    fetched: bool = False
    size: int = 0
    hits: List[JsHit] = field(default_factory=list)
    error: str = ""

    @property
    def secrets(self) -> List[JsHit]:
        return [h for h in self.hits if h.kind == "secret"]


def _mask(value: str) -> str:
    v = value.strip()
    if len(v) <= 12:
        return v
    return f"{v[:6]}...{v[-4:]} (len {len(v)})"


def analyze_text(url: str, body: str) -> JsReport:
    rep = JsReport(url=url, fetched=True, size=len(body))
    seen = set()

    for label, pattern, note in SECRET_PATTERNS:
        for m in pattern.finditer(body):
            value = m.group(1) if m.groups() else m.group(0)
            key = ("secret", label, value)
            if key in seen:
                continue
            seen.add(key)
            rep.hits.append(JsHit("secret", label, _mask(value), note))

    endpoints = set()
    for m in ENDPOINT_RE.finditer(body):
        endpoints.add(m.group(1))
    for ep in sorted(endpoints)[:60]:
        rep.hits.append(JsHit("endpoint", "endpoint interno", ep))

    hosts = set()
    for m in FULLURL_RE.finditer(body):
        u = m.group(1)
        if any(s in u for s in ("w3.org", "schema.org", "googleapis.com/ajax", "example.")):
            continue
        hosts.add(u)
    for u in sorted(hosts)[:40]:
        rep.hits.append(JsHit("url", "url referenciada", u))
    return rep


def analyze_url(url: str, timeout: int = 20, max_body: int = 2_000_000) -> JsReport:
    resp = scan.fetch(url, "GET", timeout=timeout, max_body=max_body)
    if resp.error or resp.status == 0:
        return JsReport(url=url, error=resp.error or "sin respuesta")
    if resp.status != 200 or not resp.body:
        return JsReport(url=url, error=f"status {resp.status}")
    return analyze_text(url, resp.body)
