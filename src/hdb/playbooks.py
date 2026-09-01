"""Playbooks de testing manual: el 'cerebro' del copiloto.

La idea no es automatizar el ataque, sino asistir a la persona que caza. Cada
playbook cubre una clase de bug que se prueba a mano (IDOR, auth, SSRF, logica
de negocio...) y trae:

- señales (`triggers`): palabras que, si aparecen en lo que describes o en una
  URL, sugieren probar esta clase.
- pasos (`steps`): checklist concreto de que intentar, en orden.
- que sube la prioridad (`escalation`): como convertir un P3 en P1.
- el VRT con el que se reporta.

Todo es conocimiento curado, offline y determinista. No envia trafico.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List


@dataclass(frozen=True)
class Playbook:
    id: str
    name: str
    vrt: str
    triggers: List[str]
    idea: str
    steps: List[str]
    escalation: List[str] = field(default_factory=list)
    manual_only: bool = True  # recordatorio: esto se prueba a mano, no con script

    def score(self, text: str) -> int:
        text = text.lower()
        return sum(1 for t in self.triggers if t in text)


PLAYBOOKS: List[Playbook] = [
    Playbook(
        id="idor",
        name="IDOR / control de acceso a objetos",
        vrt="broken_access_control.idor.modify_view_sensitive_information_iterable_object_identifiers",
        triggers=["id", "/api/", "user", "order", "account", "uuid", "?id=", "profile", "invoice", "document"],
        idea="Un identificador en la URL o el cuerpo que apunta a un objeto. Si puedes "
        "cambiarlo por el de otro usuario y el servidor no comprueba que sea tuyo, es IDOR.",
        steps=[
            "Crea DOS cuentas (atacante y victima). Trabaja siempre con datos propios.",
            "Con la cuenta atacante, localiza un request que lea o modifique un objeto por id.",
            "Anota el id y su formato: numerico secuencial, uuid, hash, base64...",
            "Repite el request cambiando el id por el de un objeto de la cuenta victima.",
            "Comprueba la respuesta: ¿te devuelve/modifica datos que no son tuyos?",
            "Prueba tambien: quitar el id, ponerlo en 0/negativo, cambiar el metodo (GET->POST).",
        ],
        escalation=[
            "Datos sensibles (PII, financieros) + id iterable = P1.",
            "Poder MODIFICAR (no solo ver) sube la severidad.",
            "Si el id es un UUID no adivinable, baja a P4: documenta como lo obtuviste.",
        ],
    ),
    Playbook(
        id="auth",
        name="Autenticacion y sesion",
        vrt="broken_authentication_and_session_management.authentication_bypass",
        triggers=["login", "signin", "session", "cookie", "token", "jwt", "2fa", "otp", "logout", "remember"],
        idea="Fallos en como el servidor decide quien eres y mantiene la sesion.",
        steps=[
            "¿La sesion se invalida al cerrar sesion y al cambiar la contraseña? Prueba reusar la cookie vieja.",
            "Decodifica el JWT (jwt.io): ¿algoritmo 'none'? ¿acepta firmas debiles? ¿datos sensibles dentro?",
            "¿Se puede saltar el 2FA yendo directo a la URL post-login, o reenviando el request sin el paso OTP?",
            "Prueba fijacion de sesion: ¿el id de sesion cambia tras autenticarte?",
            "Mira el 'remember me' y los tokens de larga duracion.",
        ],
        escalation=[
            "Bypass total de autenticacion = P1.",
            "Bypass de 2FA = P3, sube si da acceso a cuentas ajenas.",
        ],
    ),
    Playbook(
        id="pwreset",
        name="Recuperacion de contraseña",
        vrt="sensitive_data_exposure.weak_password_reset_implementation.token_leakage_via_host_header_poisoning",
        triggers=["reset", "forgot", "recover", "password", "email link", "magic link"],
        idea="El flujo de reset suele ser la ruta mas corta al account takeover.",
        steps=[
            "Pide un reset y examina el correo: ¿el token es predecible, corto o no expira?",
            "Prueba Host header poisoning: cambia el header Host y mira si el enlace del correo apunta a tu dominio.",
            "¿El token se reutiliza? ¿funciona tras usarlo una vez?",
            "¿Puedes cambiar el email de destino manipulando un parametro del request?",
            "Comprueba si el reset invalida las sesiones activas.",
        ],
        escalation=[
            "Token filtrado via Host header -> account takeover = P2.",
            "Si consigues resetear la cuenta de otro = P1.",
        ],
    ),
    Playbook(
        id="ssrf",
        name="SSRF (Server-Side Request Forgery)",
        vrt="server_security_misconfiguration.server_side_request_forgery_ssrf.internal_data_exposure",
        triggers=["url=", "webhook", "callback", "fetch", "proxy", "import", "avatar", "pdf", "render", "image url"],
        idea="Un parametro donde metes una URL y el servidor la pide por ti. Si alcanza "
        "recursos internos, es SSRF.",
        steps=[
            "Localiza parametros que reciben URLs (webhooks, import por URL, previsualizadores, avatares).",
            "Apunta a un servidor tuyo (Burp Collaborator o similar) y confirma que el servidor te llama.",
            "Prueba llegar a metadata cloud: http://169.254.169.254/ (AWS/GCP). SOLO si esta permitido.",
            "Prueba esquemas alternativos y bypasses de allowlist: redirecciones, DNS rebinding, IPs en decimal.",
            "Documenta que recurso interno alcanzaste, sin exfiltrar datos de terceros.",
        ],
        escalation=[
            "Exposicion de secretos internos (credenciales de metadata) = P2.",
            "Solo confirmar la peticion saliente (blind) = P3-P4.",
        ],
    ),
    Playbook(
        id="upload",
        name="Subida de ficheros",
        vrt="server_security_misconfiguration.unsafe_file_upload.file_extension_filter_bypass",
        triggers=["upload", "file", "attachment", "avatar", "import", "document", "multipart"],
        idea="Todo punto de subida es un candidato: tipo, extension, ruta y contenido.",
        steps=[
            "Sube un fichero legitimo y observa la ruta/nombre resultante.",
            "Prueba saltar el filtro de extension: doble extension, mayusculas, bytes nulos, content-type falso.",
            "¿Puedes controlar el nombre y provocar path traversal (../)?",
            "Si permite SVG/HTML, prueba XSS almacenado en el visor.",
            "Comprueba si el fichero queda accesible publicamente sin autorizacion.",
        ],
        escalation=[
            "Subir contenido ejecutable en el servidor = critico (P1), pero confirma impacto real.",
            "XSS almacenado via SVG = P2-P3.",
        ],
    ),
    Playbook(
        id="redirect",
        name="Open redirect",
        vrt="unvalidated_redirects_and_forwards.open_redirect.get_based",
        triggers=["redirect", "return", "next", "url=", "continue", "returnto", "callback", "goto", "dest"],
        idea="Parametros que controlan a donde te manda la app tras una accion.",
        steps=[
            "Busca parametros tipo ?next=, ?redirect=, ?returnUrl=.",
            "Cambia el valor por https://ejemplo-atacante.com y mira si te redirige fuera del dominio.",
            "Prueba bypasses: //evil.com, https:evil.com, /\\evil.com, @evil.com.",
            "Encadenalo con OAuth/login para robar tokens si el redirect_uri es debil.",
        ],
        escalation=[
            "Open redirect solo = P4-P5 en muchos programas.",
            "Encadenado a robo de token OAuth = P2. Ahi esta el valor.",
        ],
    ),
    Playbook(
        id="cors",
        name="CORS mal configurado",
        vrt="server_security_misconfiguration.unsafe_cross_origin_resource_sharing",
        triggers=["cors", "access-control", "api", "origin", "cross-origin"],
        idea="Si un endpoint con datos sensibles refleja tu Origin y permite credenciales, "
        "otro sitio puede leer la respuesta del usuario.",
        steps=[
            "Manda un request con Origin: https://ejemplo-atacante.com a un endpoint autenticado.",
            "Mira la respuesta: ¿Access-Control-Allow-Origin refleja tu Origin?",
            "¿Access-Control-Allow-Credentials: true a la vez? Eso es lo explotable.",
            "Confirma que el endpoint devuelve datos sensibles del usuario.",
            "(`hdb scan` ya detecta el reflejo basico; aqui confirmas el impacto.)",
        ],
        escalation=["Reflejo de Origin + credenciales + datos sensibles = P3, sube segun el dato."],
    ),
    Playbook(
        id="logic",
        name="Logica de negocio",
        vrt="broken_access_control.idor.modify_view_sensitive_information_iterable_object_identifiers",
        triggers=["price", "cart", "checkout", "coupon", "quantity", "balance", "transfer", "workflow", "role", "invite"],
        idea="Los bugs que ninguna herramienta encuentra: reglas del negocio que se pueden romper.",
        steps=[
            "Manipula cantidades y precios: negativos, decimales, cero, overflow.",
            "Reordena o repite pasos de un flujo (paga, luego cancela y quedate el producto).",
            "Race conditions: envia el mismo request en paralelo (canjear un cupon dos veces).",
            "Salta pasos de validacion yendo directo a la URL final.",
            "Prueba escalada horizontal/vertical de roles: invita, cambia tu rol, accede a paneles.",
        ],
        escalation=[
            "Impacto economico directo o acceso a funciones de admin = alta prioridad.",
            "Explica el impacto en dinero/usuarios: es lo que decide el pago.",
        ],
    ),
    Playbook(
        id="secrets",
        name="Secretos e informacion expuesta",
        vrt="sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset",
        triggers=["js", "javascript", "api key", "config", "backup", ".git", "env", "swagger", "source map", "debug"],
        idea="Cosas que la app filtra sin querer y estan accesibles sin explotar nada.",
        steps=[
            "Lee los ficheros JS (y sus source maps .map): busca claves, endpoints internos, tokens.",
            "Prueba rutas comunes de solo lectura: /robots.txt, /.well-known/, /swagger.json, /api-docs.",
            "Busca claves en respuestas, comentarios HTML y cabeceras.",
            "Si encuentras una clave, comprueba si sigue activa y su alcance (sin abusar de ella).",
        ],
        escalation=[
            "Clave/credencial valida y con alcance real = P1-P2.",
            "Una clave revocada o de bajo impacto es P4-P5: verifica antes de reportar.",
        ],
    ),
]


def by_id(pid: str) -> Playbook:
    for pb in PLAYBOOKS:
        if pb.id == pid:
            return pb
    raise KeyError(pid)


def recommend(context: str, limit: int = 4) -> List[Playbook]:
    """Ordena los playbooks por relevancia para lo que describe la persona."""
    scored = [(pb.score(context), pb) for pb in PLAYBOOKS]
    scored = [(s, pb) for s, pb in scored if s > 0]
    scored.sort(key=lambda x: -x[0])
    return [pb for _, pb in scored[:limit]]
