"""Juez de IA: analiza la evidencia que TU capturaste.

Le pasas el request y la respuesta HTTP que obtuviste durante tu testing
autorizado, y un modelo de Claude razona sobre esa evidencia concreta para
decirte si el impacto es real, con que confianza, y que probar despues.

Limite importante: el juez NO hace peticiones al target. Solo analiza texto que
tu ya obtuviste legitimamente. No sustituye tu criterio ni las reglas del
programa; es un segundo par de ojos experto.

Requiere el paquete `anthropic` y credenciales (ANTHROPIC_API_KEY o un perfil de
`ant auth login`). Es la unica parte de hdb que usa red hacia un LLM; todo lo
demas funciona offline.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import List, Optional

DEFAULT_MODEL = "claude-opus-5"

SYSTEM_PROMPT = """\
Eres un triager senior de Bugcrowd que evalua hallazgos de bug bounty. Un \
investigador te trae EVIDENCIA que ya capturo durante su testing autorizado \
(peticiones y respuestas HTTP, fragmentos de codigo, notas). Tu trabajo es \
evaluar esa evidencia con rigor y escepticismo.

Reglas:
- Analizas SOLO la evidencia proporcionada. No pides ni simulas nuevas \
peticiones al objetivo.
- Eres esceptico: si el impacto no esta demostrado en la evidencia, dilo \
claramente en vez de asumirlo. Muchos "hallazgos" son falsos positivos \
(claves publicas, comportamiento esperado, datos propios del usuario).
- Distingues correlacion de vulnerabilidad. Una cabecera ausente no es un bug \
si no hay impacto.
- Piensas en terminos de la taxonomia VRT de Bugcrowd y su prioridad P1-P5.
- Señalas riesgos de duplicado y de elegibilidad (cosas que el programa suele \
excluir).
- Nunca animas a acciones destructivas, fuera de scope, o contra datos de \
terceros.

Devuelve tu analisis en el formato JSON solicitado, en español."""

RESULT_SCHEMA = {
    "type": "object",
    "properties": {
        "is_vulnerability": {
            "type": "string",
            "enum": ["si", "probable", "no_demostrado", "no", "falso_positivo"],
            "description": "Veredicto sobre si la evidencia demuestra una vulnerabilidad real.",
        },
        "confidence": {"type": "integer", "minimum": 0, "maximum": 100},
        "vuln_class": {"type": "string", "description": "Clase de bug, p.ej. IDOR, SSRF, XSS almacenado."},
        "vrt_id": {"type": "string", "description": "Ruta VRT sugerida, o cadena vacia si no aplica."},
        "priority_estimate": {
            "type": "string",
            "enum": ["P1", "P2", "P3", "P4", "P5", "N/A"],
        },
        "reasoning": {"type": "string", "description": "Por que, citando la evidencia concreta."},
        "what_is_missing": {
            "type": "array",
            "items": {"type": "string"},
            "description": "Que falta demostrar para confirmar o subir la severidad.",
        },
        "next_tests": {
            "type": "array",
            "items": {"type": "string"},
            "description": "Pruebas manuales concretas y no destructivas a realizar despues.",
        },
        "false_positive_risks": {
            "type": "array",
            "items": {"type": "string"},
            "description": "Razones por las que esto podria NO ser un bug.",
        },
    },
    "required": [
        "is_vulnerability", "confidence", "vuln_class", "vrt_id",
        "priority_estimate", "reasoning", "what_is_missing", "next_tests",
        "false_positive_risks",
    ],
    "additionalProperties": False,
}


@dataclass
class Judgment:
    is_vulnerability: str
    confidence: int
    vuln_class: str
    vrt_id: str
    priority_estimate: str
    reasoning: str
    what_is_missing: List[str] = field(default_factory=list)
    next_tests: List[str] = field(default_factory=list)
    false_positive_risks: List[str] = field(default_factory=list)
    model: str = ""

    @classmethod
    def from_dict(cls, d: dict, model: str = "") -> "Judgment":
        return cls(
            is_vulnerability=d.get("is_vulnerability", "no_demostrado"),
            confidence=int(d.get("confidence", 0)),
            vuln_class=d.get("vuln_class", ""),
            vrt_id=d.get("vrt_id", ""),
            priority_estimate=d.get("priority_estimate", "N/A"),
            reasoning=d.get("reasoning", ""),
            what_is_missing=list(d.get("what_is_missing", [])),
            next_tests=list(d.get("next_tests", [])),
            false_positive_risks=list(d.get("false_positive_risks", [])),
            model=model,
        )


class JudgeUnavailable(RuntimeError):
    """El juez no puede correr (falta el paquete o las credenciales)."""


def _client():
    try:
        import anthropic  # noqa: F401
    except ImportError as exc:
        raise JudgeUnavailable(
            "el juez de IA necesita el paquete 'anthropic'. Instalalo con:\n"
            "  pip install anthropic"
        ) from exc
    import anthropic

    return anthropic.Anthropic()


_AUTH_HINT = (
    "no encuentro credenciales de Anthropic. Configura una con:\n"
    "  export ANTHROPIC_API_KEY=sk-ant-...   (o: ant auth login)"
)


def _is_auth_error(exc: Exception) -> bool:
    msg = str(exc).lower()
    return "authentication" in msg or "api_key" in msg or "credentials" in msg or "x-api-key" in msg


def build_prompt(evidence: str, context: str = "", target: str = "") -> str:
    parts = []
    if target:
        parts.append(f"Target: {target}")
    if context:
        parts.append(f"Lo que el investigador sospecha / observo:\n{context}")
    parts.append("Evidencia capturada (request/response u otra):\n" + evidence)
    parts.append(
        "Evalua si esto demuestra una vulnerabilidad real. Se esceptico y "
        "concreto; cita la evidencia. Rellena el JSON solicitado."
    )
    return "\n\n".join(parts)


def analyze(
    evidence: str,
    context: str = "",
    target: str = "",
    model: str = DEFAULT_MODEL,
    effort: str = "high",
    max_tokens: int = 8000,
) -> Judgment:
    """Envia la evidencia al modelo y devuelve el veredicto estructurado."""
    if not evidence.strip():
        raise ValueError("no hay evidencia que analizar")
    client = _client()
    prompt = build_prompt(evidence, context, target)

    try:
        with client.messages.stream(
            model=model,
            max_tokens=max_tokens,
            system=SYSTEM_PROMPT,
            thinking={"type": "adaptive"},
            output_config={"effort": effort, "format": {"type": "json_schema", "schema": RESULT_SCHEMA}},
            messages=[{"role": "user", "content": prompt}],
        ) as stream:
            message = stream.get_final_message()
    except Exception as exc:  # noqa: BLE001
        if _is_auth_error(exc):
            raise JudgeUnavailable(_AUTH_HINT) from exc
        raise

    text = next((b.text for b in message.content if b.type == "text"), "")
    if not text:
        raise JudgeUnavailable("el modelo no devolvio un analisis legible; reintenta.")
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise JudgeUnavailable(f"respuesta del modelo no es JSON valido: {exc}") from exc
    return Judgment.from_dict(data, model=model)
