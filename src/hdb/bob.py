"""BOB — el copiloto de bug bounty.

BOB no ataca nada. Hace dos cosas:

1. REVISAR: mira la superficie in-scope (solo lectura) y te AVISA de los puntos
   que valen la pena probar a mano, ordenados por impacto potencial. Tu haces
   el testing.
2. REPORTAR: cuando le dices "lo encontre", BOB convierte el hallazgo en un
   reporte listo para enviar por la plataforma.

La logica de ranking (`review`) vive separada de la red para poder probarla.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional

from . import playbooks as pb_mod
from .scan import ScanResult
from .surface import SurfaceMap
from .jsanalyze import JsReport

# Cuanto "vale la pena" cada clase de bug (mayor = mas critico). Guia el orden
# en el que BOB te presenta los puntos a revisar.
# Etiquetas de secreto que casi nunca son un bug (publicas por diseño).
LOW_RISK_SECRETS = {"Stripe Publishable", "Google API Key"}


PRIORITY_WEIGHT = {
    "auth": 100, "pwreset": 95, "idor": 90, "ssrf": 85, "logic": 80,
    "upload": 70, "secrets": 65, "redirect": 40, "cors": 45,
}


@dataclass
class CriticalPoint:
    where: str  # url o descripcion
    playbook_id: str
    why: str
    weight: int
    params: List[str] = field(default_factory=list)

    @property
    def playbook(self) -> pb_mod.Playbook:
        return pb_mod.by_id(self.playbook_id)


@dataclass
class Review:
    target: str
    critical_points: List[CriticalPoint] = field(default_factory=list)
    quick_wins: List[str] = field(default_factory=list)  # hallazgos pasivos ya visibles
    notes: List[str] = field(default_factory=list)


def review(
    target: str,
    surface: Optional[SurfaceMap],
    scan_result: Optional[ScanResult],
    js_reports: Optional[List[JsReport]] = None,
) -> Review:
    """Combina el mapa de superficie y el escaneo pasivo en una lista priorizada."""
    rv = Review(target=target)
    points: List[CriticalPoint] = []

    if surface:
        rv.notes.extend(surface.notes)
        for ep in surface.endpoints:
            for hint in ep.hints:
                weight = PRIORITY_WEIGHT.get(hint, 30)
                if ep.params:
                    weight += 5
                points.append(
                    CriticalPoint(
                        where=ep.url,
                        playbook_id=hint if hint in {pb.id for pb in pb_mod.PLAYBOOKS} else "idor",
                        why=_reason(hint, ep.params),
                        weight=weight,
                        params=ep.params,
                    )
                )
        if surface.js_files:
            points.append(
                CriticalPoint(
                    where=f"{len(surface.js_files)} fichero(s) JS",
                    playbook_id="secrets",
                    why="Los JS suelen filtrar claves, endpoints internos y tokens.",
                    weight=PRIORITY_WEIGHT["secrets"],
                )
            )

    for rep in js_reports or []:
        for hit in rep.secrets:
            weight = 60 if hit.label in LOW_RISK_SECRETS else 98
            points.append(
                CriticalPoint(
                    where=f"{hit.label} en {rep.url}",
                    playbook_id="secrets",
                    why=f"{hit.value} — {hit.note}",
                    weight=weight,
                )
            )

    if scan_result:
        for issue in scan_result.issues:
            tag = "P{} ".format(issue.priority) if issue.priority else ""
            rv.quick_wins.append(f"{tag}{issue.title} ({issue.url})")

    # dedup por (url, playbook) quedandonos con el de mas peso
    best = {}
    for cp in points:
        key = (cp.where, cp.playbook_id)
        if key not in best or cp.weight > best[key].weight:
            best[key] = cp
    rv.critical_points = sorted(best.values(), key=lambda c: -c.weight)
    return rv


def _reason(hint: str, params: List[str]) -> str:
    base = {
        "idor": "Identificador manipulable: candidato a IDOR/control de acceso.",
        "auth": "Flujo de autenticacion: revisa sesion, JWT y bypass.",
        "pwreset": "Flujo de reset: ruta corta a account takeover.",
        "ssrf": "Parametro que recibe una URL: posible SSRF.",
        "upload": "Punto de subida de ficheros: revisa filtros y ruta.",
        "redirect": "Parametro de redireccion: posible open redirect (encadenable).",
        "secrets": "Puede exponer informacion sensible.",
        "cors": "Revisa la politica CORS con credenciales.",
    }.get(hint, "Merece una revision manual.")
    if params:
        base += f" Parametros: {', '.join(params)}."
    return base
