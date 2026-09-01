"""Tasacion de un hallazgo: '¿esto es importante?'.

BOB no ha visto tu target. Lo que hace aqui es tasar TU hallazgo a partir de lo
que TU observaste: te pregunta hechos de si/no y mapea las respuestas a la
taxonomia de Bugcrowd (VRT), devolviendo la prioridad fundamentada y las alertas
de elegibilidad. El veredicto vale lo que valgan tus respuestas: si mientes o
te equivocas, el veredicto se equivoca. No sustituye leer las reglas del
programa ni buscar duplicados.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Tuple

from . import vrt


@dataclass
class Question:
    key: str
    text: str


@dataclass
class Verdict:
    headline: str  # "SI, importante" / "Menor" / "Probablemente no elegible" / ...
    priority: Optional[int]
    vrt_id: str
    reasons: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    eligible: bool = True

    @property
    def priority_label(self) -> str:
        # El veredicto manda: si BOB no fija prioridad (sin confirmar / no
        # elegible), no mostramos la del VRT para no dar una falsa señal.
        if self.priority is None:
            return "no aplica todavia (sin confirmar o no elegible)"
        return vrt.PRIORITY_LABEL.get(self.priority, f"P{self.priority}")


@dataclass
class Assessor:
    playbook_id: str
    questions: List[Question]
    evaluate: Callable[[Dict[str, bool]], Verdict]


def _headline(priority: Optional[int], eligible: bool = True) -> str:
    if not eligible:
        return "Probablemente NO elegible"
    if priority in (1, 2):
        return "SI, importante"
    if priority == 3:
        return "Moderado (vale la pena)"
    if priority in (4, 5):
        return "Menor (revisa si el programa lo premia)"
    return "Necesita tu criterio"


# --------------------------------------------------------------------------- IDOR


def _idor(a: Dict[str, bool]) -> Verdict:
    if not a.get("crossuser"):
        return Verdict(
            "Sin confirmar", None, "broken_access_control.idor",
            reasons=["No has probado acceso a datos de OTRA cuenta: aun no es un IDOR demostrado."],
            warnings=["Demuestralo con dos cuentas propias antes de seguir."],
        )
    sensitive = a.get("sensitive", False)
    modify = a.get("modify", False)
    iterable = a.get("iterable", False)
    if not sensitive:
        v = Verdict(_headline(5), 5, "broken_access_control.idor.view_non_sensitive_information")
        v.reasons.append("Datos no sensibles: impacto bajo.")
        return v
    if not iterable:
        v = Verdict(_headline(4), 4, "broken_access_control.idor.modify_view_sensitive_information_guid")
        v.reasons.append("Identificador no adivinable (GUID/UUID): baja la prioridad; documenta como lo obtuviste.")
        return v
    if modify:
        vid = "broken_access_control.idor.modify_view_sensitive_information_iterable_object_identifiers"
        v = Verdict(_headline(1), 1, vid)
        v.reasons.append("Datos sensibles + id iterable + puedes MODIFICAR: maximo impacto.")
    else:
        vid = "broken_access_control.idor.view_sensitive_information_iterable_object_identifiers"
        v = Verdict(_headline(3), 3, vid)
        v.reasons.append("Datos sensibles + id iterable, solo lectura.")
    return v


# --------------------------------------------------------------------------- CORS


def _cors(a: Dict[str, bool]) -> Verdict:
    if not a.get("reflect"):
        return Verdict("Probablemente NO elegible", None,
                       "server_security_misconfiguration.unsafe_cross_origin_resource_sharing",
                       reasons=["Si no refleja un Origin arbitrario, no es explotable."], eligible=False)
    if not a.get("creds"):
        return Verdict("Menor (revisa si el programa lo premia)", 5,
                       "server_security_misconfiguration.unsafe_cross_origin_resource_sharing",
                       reasons=["Refleja el Origin pero SIN credenciales: impacto limitado; muchos programas no lo premian."])
    if not a.get("sensitive"):
        return Verdict("Moderado (vale la pena)", 4,
                       "server_security_misconfiguration.unsafe_cross_origin_resource_sharing",
                       reasons=["Origin reflejado + credenciales, pero sin datos sensibles claros."])
    return Verdict("SI, importante", 3,
                   "server_security_misconfiguration.unsafe_cross_origin_resource_sharing",
                   reasons=["Origin reflejado + credenciales + datos sensibles: otro sitio puede leerlos."])


# --------------------------------------------------------------------------- Open redirect


def _redirect(a: Dict[str, bool]) -> Verdict:
    if not a.get("external"):
        return Verdict("Probablemente NO elegible", None,
                       "unvalidated_redirects_and_forwards.open_redirect.get_based",
                       reasons=["Si no rediriges a un dominio externo, no hay open redirect."], eligible=False)
    if a.get("chain"):
        return Verdict("SI, importante", 2,
                       "server_security_misconfiguration.oauth_misconfiguration.account_takeover",
                       reasons=["Encadenado a robo de token (OAuth/SSO): el impacto real esta aqui, no en el redirect."],
                       warnings=["Repórtalo como el ATO/robo de token, no como 'open redirect' a secas."])
    return Verdict("Menor (revisa si el programa lo premia)", 4,
                   "unvalidated_redirects_and_forwards.open_redirect.get_based",
                   reasons=["Open redirect aislado: muchos programas lo consideran P4-P5 o fuera de recompensa."],
                   warnings=["Busca como encadenarlo (robo de token) para que valga la pena."])


# --------------------------------------------------------------------------- Secrets


def _secrets(a: Dict[str, bool]) -> Verdict:
    if a.get("public"):
        return Verdict("Probablemente NO elegible", None,
                       "sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset",
                       reasons=["Clave publica por diseño (Stripe publishable, Google Maps...): normalmente NO es un bug."],
                       eligible=False)
    if not a.get("valid"):
        return Verdict("Menor (revisa si el programa lo premia)", 5,
                       "sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset",
                       reasons=["La clave no esta activa o no la validaste: impacto sin demostrar."],
                       warnings=["Confirma que sigue viva (sin abusar de ella) antes de reportar."])
    if not a.get("scope"):
        return Verdict("Moderado (vale la pena)", 3,
                       "sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset",
                       reasons=["Clave valida pero de alcance limitado."])
    return Verdict("SI, importante", 1,
                   "sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset",
                   reasons=["Clave valida con acceso a datos o acciones reales: alto impacto."],
                   warnings=["No la uses mas alla de confirmar el acceso; no toques datos de terceros."])


# --------------------------------------------------------------------------- Auth bypass


def _auth(a: Dict[str, bool]) -> Verdict:
    if a.get("full"):
        return Verdict("SI, importante", 1,
                       "broken_authentication_and_session_management.authentication_bypass",
                       reasons=["Bypass total de autenticacion: critico."])
    if a.get("other"):
        return Verdict("SI, importante", 2,
                       "server_security_misconfiguration.oauth_misconfiguration.account_takeover",
                       reasons=["Acceso a la cuenta de otro usuario (account takeover)."])
    if a.get("twofa"):
        return Verdict("Moderado (vale la pena)", 3,
                       "broken_authentication_and_session_management.two_fa_bypass",
                       reasons=["Bypass de 2FA."])
    return Verdict("Necesita tu criterio", None,
                   "broken_authentication_and_session_management.authentication_bypass",
                   reasons=["No encaja en un patron claro: describe exactamente que control saltaste."])


# --------------------------------------------------------------------------- SSRF


def _ssrf(a: Dict[str, bool]) -> Verdict:
    if a.get("secrets"):
        return Verdict("SI, importante", 2,
                       "server_security_misconfiguration.server_side_request_forgery_ssrf.internal_secrets_exposure",
                       reasons=["Expusiste secretos internos (p.ej. credenciales de metadata cloud)."],
                       warnings=["No exfiltres datos de terceros; documenta lo minimo para probarlo."])
    if a.get("internal"):
        return Verdict("Moderado (vale la pena)", 3,
                       "server_security_misconfiguration.server_side_request_forgery_ssrf.internal_data_exposure",
                       reasons=["Alcanzaste datos/recursos internos."])
    if a.get("blind"):
        return Verdict("Menor (revisa si el programa lo premia)", 4,
                       "server_security_misconfiguration.server_side_request_forgery_ssrf.internal_data_exposure",
                       reasons=["SSRF a ciegas (solo confirmaste la peticion saliente): impacto por demostrar."])
    return Verdict("Sin confirmar", None,
                   "server_security_misconfiguration.server_side_request_forgery_ssrf.internal_data_exposure",
                   reasons=["Aun no demostraste que el servidor pida una URL que tu controlas."])


ASSESSORS: Dict[str, Assessor] = {
    "idor": Assessor("idor", [
        Question("crossuser", "¿Accediste a datos/objetos de OTRA cuenta (no la tuya)?"),
        Question("sensitive", "¿Esos datos son sensibles (PII, financieros, privados)?"),
        Question("modify", "¿Puedes MODIFICARLOS (no solo verlos)?"),
        Question("iterable", "¿El identificador es predecible/iterable (numerico secuencial, etc.)?"),
    ], _idor),
    "cors": Assessor("cors", [
        Question("reflect", "¿Refleja tu Origin arbitrario en Access-Control-Allow-Origin?"),
        Question("creds", "¿Devuelve Access-Control-Allow-Credentials: true?"),
        Question("sensitive", "¿El endpoint devuelve datos sensibles del usuario autenticado?"),
    ], _cors),
    "redirect": Assessor("redirect", [
        Question("external", "¿Redirige a un dominio externo que tu controlas?"),
        Question("chain", "¿Puedes encadenarlo para robar un token (OAuth/SSO)?"),
    ], _redirect),
    "secrets": Assessor("secrets", [
        Question("public", "¿Es una clave PUBLICA por diseño (Stripe publishable, Google Maps...)?"),
        Question("valid", "¿Confirmaste que la clave sigue ACTIVA (sin abusar de ella)?"),
        Question("scope", "¿Da acceso a datos o acciones reales?"),
    ], _secrets),
    "auth": Assessor("auth", [
        Question("full", "¿Es un bypass TOTAL de autenticacion (entras sin credenciales)?"),
        Question("other", "¿Accedes a la cuenta de OTRO usuario?"),
        Question("twofa", "¿Es un bypass de 2FA?"),
    ], _auth),
    "ssrf": Assessor("ssrf", [
        Question("secrets", "¿Expusiste secretos internos (credenciales de metadata cloud)?"),
        Question("internal", "¿Alcanzaste datos/recursos internos?"),
        Question("blind", "¿Solo confirmaste la peticion saliente (a ciegas)?"),
    ], _ssrf),
}

UNIVERSAL_WARNINGS = [
    "Busca duplicados en la actividad publica del programa antes de reportar.",
    "Relee las reglas: algunos P4-P5 estan fuera de recompensa segun el programa.",
    "Este veredicto se basa en TUS respuestas; BOB no ha visto el target.",
]


def assess(playbook_id: str, answers: Dict[str, bool]) -> Verdict:
    assessor = ASSESSORS.get(playbook_id)
    if not assessor:
        entry = None
        raise KeyError(playbook_id)
    v = assessor.evaluate(answers)
    v.warnings.extend(UNIVERSAL_WARNINGS)
    return v


def available() -> List[str]:
    return sorted(ASSESSORS.keys())
