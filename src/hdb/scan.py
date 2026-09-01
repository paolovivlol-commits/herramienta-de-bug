"""Verificacion pasiva de una pagina web.

Filosofia: SOLO lectura. La herramienta hace peticiones GET/HEAD normales, como
las de un navegador, y observa lo que el servidor responde. No inyecta payloads,
no fuerza nada, no envia trafico destructivo. Lo que encuentra son fallos de
configuracion visibles en las cabeceras y el cuerpo de la respuesta.

Cada check devuelve hallazgos ya mapeados a un VRT de Bugcrowd, listos para
convertirse en un `finding` y su reporte.

Antes de escanear, el llamador DEBE confirmar que el host esta en scope. El
motor de scope (scope.py) es quien lo decide; este modulo se niega a tocar nada
que no venga marcado como in-scope.
"""

from __future__ import annotations

import re
import ssl
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from http.cookies import SimpleCookie
from typing import Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlsplit

from .fetch import USER_AGENT

# Peticiones de solo lectura. Nunca se usa otro metodo.
SAFE_METHODS = ("GET", "HEAD")

# Cabecera -> (id VRT, nombre corto legible)
SECURITY_HEADERS = {
    "strict-transport-security": (
        "server_security_misconfiguration.lack_of_security_headers.strict_transport_security",
        "HSTS (Strict-Transport-Security)",
    ),
    "content-security-policy": (
        "server_security_misconfiguration.lack_of_security_headers.content_security_policy",
        "Content-Security-Policy",
    ),
    "x-content-type-options": (
        "server_security_misconfiguration.lack_of_security_headers.x_content_type_options",
        "X-Content-Type-Options",
    ),
    "x-frame-options": (
        "server_security_misconfiguration.lack_of_security_headers.x_frame_options",
        "X-Frame-Options",
    ),
}


@dataclass
class Response:
    url: str
    final_url: str
    status: int
    headers: Dict[str, str]  # claves en minuscula
    set_cookie: List[str]
    body: str
    scheme: str
    error: str = ""

    def header(self, name: str) -> str:
        return self.headers.get(name.lower(), "")


@dataclass
class Issue:
    title: str
    vrt_id: str
    priority: Optional[int]
    evidence: str
    recommendation: str
    url: str = ""

    def as_line(self) -> str:
        prio = f"P{self.priority}" if self.priority else "P?"
        return f"{prio:<4} {self.title}"


@dataclass
class ScanResult:
    url: str
    reachable: bool
    issues: List[Issue] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)
    security_txt: str = ""


def _build_opener() -> urllib.request.OpenerDirector:
    # No relajamos la validacion TLS; si el certificado es invalido, es un dato.
    ctx = ssl.create_default_context()
    return urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx))


def fetch(
    url: str,
    method: str = "GET",
    timeout: int = 20,
    extra_headers: Optional[Dict[str, str]] = None,
    max_body: int = 400_000,
    allow_redirects: bool = True,
) -> Response:
    if method not in SAFE_METHODS:
        raise ValueError(f"metodo no permitido: {method} (solo {SAFE_METHODS})")
    headers = {"User-Agent": USER_AGENT, "Accept": "*/*"}
    if extra_headers:
        headers.update(extra_headers)

    class _NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, hdrs, newurl):  # noqa: D401
            return None

    opener = urllib.request.build_opener() if allow_redirects else urllib.request.build_opener(_NoRedirect)
    req = urllib.request.Request(url, method=method, headers=headers)
    scheme = urlsplit(url).scheme
    try:
        with opener.open(req, timeout=timeout) as resp:
            raw = resp.read(max_body) if method == "GET" else b""
            hdr = {k.lower(): v for k, v in resp.headers.items()}
            cookies = resp.headers.get_all("Set-Cookie") or []
            return Response(
                url=url,
                final_url=resp.geturl(),
                status=resp.status,
                headers=hdr,
                set_cookie=cookies,
                body=raw.decode("utf-8", "replace"),
                scheme=urlsplit(resp.geturl()).scheme,
            )
    except urllib.error.HTTPError as exc:
        hdr = {k.lower(): v for k, v in exc.headers.items()} if exc.headers else {}
        cookies = exc.headers.get_all("Set-Cookie") if exc.headers else []
        return Response(url, url, exc.code, hdr, cookies or [], "", scheme)
    except (urllib.error.URLError, ssl.SSLError, TimeoutError, OSError) as exc:
        return Response(url, url, 0, {}, [], "", scheme, error=str(exc))


# --------------------------------------------------------------------------- checks


def check_security_headers(resp: Response) -> List[Issue]:
    issues: List[Issue] = []
    is_https = resp.scheme == "https"
    for name, (vrt_id, label) in SECURITY_HEADERS.items():
        if name == "strict-transport-security" and not is_https:
            continue  # HSTS solo aplica sobre HTTPS
        if not resp.header(name):
            issues.append(
                Issue(
                    title=f"Falta la cabecera {label}",
                    vrt_id=vrt_id,
                    priority=5,
                    evidence=f"La respuesta de {resp.final_url} no incluye '{label}'.",
                    recommendation=f"Añadir la cabecera {label} con una politica adecuada.",
                    url=resp.final_url,
                )
            )
    return issues


def check_clickjacking(resp: Response) -> List[Issue]:
    xfo = resp.header("x-frame-options")
    csp = resp.header("content-security-policy").lower()
    if xfo or "frame-ancestors" in csp:
        return []
    return [
        Issue(
            title="Pagina potencialmente enmarcable (posible clickjacking)",
            vrt_id="server_security_misconfiguration.clickjacking.non_sensitive_action",
            priority=5,
            evidence=f"{resp.final_url} no define X-Frame-Options ni 'frame-ancestors' en CSP.",
            recommendation="Definir X-Frame-Options: DENY o 'frame-ancestors' en la CSP. "
            "Sube de prioridad si la pagina ejecuta acciones sensibles (transferencias, cambios de cuenta).",
            url=resp.final_url,
        )
    ]


def check_cookies(resp: Response) -> List[Issue]:
    issues: List[Issue] = []
    for raw in resp.set_cookie:
        jar = SimpleCookie()
        try:
            jar.load(raw)
        except Exception:
            continue
        for name, morsel in jar.items():
            low = name.lower()
            looks_session = any(tok in low for tok in ("sess", "auth", "token", "sid", "jwt", "login"))
            problems = []
            if not morsel["secure"] and resp.scheme == "https":
                problems.append("sin flag Secure")
            if not morsel["httponly"]:
                problems.append("sin flag HttpOnly")
            if not problems:
                continue
            if looks_session:
                vrt_id = "server_security_misconfiguration.missing_secure_or_httponly_cookie_flag.session_token"
                prio = 4
            else:
                vrt_id = "server_security_misconfiguration.missing_secure_or_httponly_cookie_flag.non_session_cookie"
                prio = 5
            issues.append(
                Issue(
                    title=f"Cookie '{name}' {', '.join(problems)}",
                    vrt_id=vrt_id,
                    priority=prio,
                    evidence=f"Set-Cookie: {raw}",
                    recommendation="Marcar la cookie como Secure y HttpOnly (y SameSite cuando aplique).",
                    url=resp.final_url,
                )
            )
    return issues


PROBE_ORIGIN = "https://hdb-scan.example"


def check_cors(resp: Response, probe_origin: str = PROBE_ORIGIN) -> List[Issue]:
    """Analiza la respuesta a una peticion que llevaba un Origin de prueba.

    Es una peticion GET normal con una cabecera Origin; no altera datos.
    """
    acao = resp.header("access-control-allow-origin")
    acac = resp.header("access-control-allow-credentials").lower()
    if not acao:
        return []
    dangerous = acao == "*" or acao == probe_origin
    if acao == "*" and acac != "true":
        # Comodin sin credenciales: comun y de bajo riesgo, solo lo anotamos.
        return []
    if not dangerous:
        return []
    with_creds = acac == "true"
    return [
        Issue(
            title="CORS refleja un Origin arbitrario" + (" con credenciales" if with_creds else ""),
            vrt_id="server_security_misconfiguration.unsafe_cross_origin_resource_sharing",
            priority=3 if with_creds else 4,
            evidence=f"Con Origin: {probe_origin} el servidor respondio "
            f"Access-Control-Allow-Origin: {acao}"
            + (" y Access-Control-Allow-Credentials: true" if with_creds else ""),
            recommendation="No reflejar el Origin recibido. Usar una allowlist estricta y no combinar "
            "'*' o el Origin reflejado con Allow-Credentials: true.",
            url=resp.final_url,
        )
    ]


def check_server_disclosure(resp: Response) -> List[Issue]:
    issues: List[Issue] = []
    version_re = re.compile(r"\d+\.\d+")
    for name in ("server", "x-powered-by", "x-aspnet-version"):
        value = resp.header(name)
        if value and version_re.search(value):
            issues.append(
                Issue(
                    title=f"Divulgacion de version en '{name}'",
                    vrt_id="server_security_misconfiguration.fingerprinting_banner_disclosure.software_version_in_response_headers",
                    priority=5,
                    evidence=f"{name}: {value}",
                    recommendation="Ocultar o generalizar la cabecera para no revelar la version exacta.",
                    url=resp.final_url,
                )
            )
    return issues


def check_mixed_content(resp: Response) -> List[Issue]:
    if resp.scheme != "https" or not resp.body:
        return []
    refs = re.findall(r'(?:src|href)=["\'](http://[^"\']+)["\']', resp.body, re.IGNORECASE)
    refs = [r for r in refs if not r.startswith("http://localhost")]
    if not refs:
        return []
    sample = ", ".join(sorted(set(refs))[:3])
    return [
        Issue(
            title=f"Contenido mixto: {len(set(refs))} recurso(s) por HTTP en una pagina HTTPS",
            vrt_id="sensitive_data_exposure.mixed_content",
            priority=5,
            evidence=f"Ejemplos: {sample}",
            recommendation="Servir todos los recursos por HTTPS o usar rutas relativas al protocolo.",
            url=resp.final_url,
        )
    ]


def check_https_downgrade(http_resp: Response) -> List[Issue]:
    """El http:// no redirige a https://: trafico en claro."""
    if http_resp.error or http_resp.status == 0:
        return []
    location = http_resp.header("location")
    redirects_to_https = location.startswith("https://") or http_resp.final_url.startswith("https://")
    if redirects_to_https:
        return []
    return [
        Issue(
            title="HTTP no redirige a HTTPS (transporte en claro)",
            vrt_id="insecure_data_transport.cleartext_transmission_of_sensitive_data",
            priority=None,
            evidence=f"{http_resp.url} respondio {http_resp.status} sin redirigir a HTTPS.",
            recommendation="Forzar la redireccion 301 a HTTPS y aplicar HSTS.",
            url=http_resp.url,
        )
    ]


PASSIVE_CHECKS = (
    check_security_headers,
    check_clickjacking,
    check_cookies,
    check_server_disclosure,
    check_mixed_content,
)


def fetch_security_txt(host: str, timeout: int = 15) -> str:
    """Busca /.well-known/security.txt: el canal de contacto declarado."""
    for scheme in ("https", "http"):
        for path in ("/.well-known/security.txt", "/security.txt"):
            resp = fetch(f"{scheme}://{host}{path}", timeout=timeout)
            if resp.status == 200 and resp.body and "contact" in resp.body.lower():
                return resp.body.strip()
    return ""


def scan_url(url: str, delay: float = 1.0, timeout: int = 20, probe_cors: bool = True) -> ScanResult:
    """Escanea una URL con checks pasivos. `delay` = segundos entre peticiones."""
    if "://" not in url:
        url = "https://" + url
    result = ScanResult(url=url, reachable=False)

    # Peticion base LIMPIA (sin cabeceras raras) para leer la configuracion real.
    resp = fetch(url, "GET", timeout=timeout)
    if resp.error or resp.status == 0:
        result.notes.append(f"no se pudo conectar: {resp.error or 'sin respuesta'}")
        return result
    result.reachable = True
    result.notes.append(f"GET {url} -> {resp.status} ({resp.final_url})")

    # Sobre una respuesta de error las cabeceras no son representativas: avisamos
    # y no reportamos ausencias que podrian ser falsos positivos.
    if not (200 <= resp.status < 400):
        result.notes.append(
            f"la pagina respondio {resp.status}; se omiten los checks de cabeceras "
            "para no generar falsos positivos. Prueba con una URL que devuelva 200."
        )
        return result

    for check in PASSIVE_CHECKS:
        result.issues.extend(check(resp))

    # CORS: peticion dedicada con un Origin de prueba, para no contaminar la base.
    if probe_cors:
        time.sleep(delay)
        cors_resp = fetch(resp.final_url, "GET", timeout=timeout, extra_headers={"Origin": PROBE_ORIGIN})
        if not cors_resp.error and 200 <= cors_resp.status < 400:
            result.issues.extend(check_cors(cors_resp))

    # HTTP -> HTTPS: una sola peticion extra al puerto 80, sin seguir redirecciones.
    parts = urlsplit(resp.final_url)
    if parts.scheme == "https":
        time.sleep(delay)
        http_url = "http://" + parts.netloc + (parts.path or "/")
        http_resp = fetch(http_url, "GET", timeout=timeout, allow_redirects=False)
        result.issues.extend(check_https_downgrade(http_resp))

    result.issues.sort(key=lambda i: (i.priority if i.priority is not None else 6, i.title))
    return result
