"""Mapeo de superficie de solo lectura.

Reune, sin atacar nada, lo que la propia aplicacion publica: enlaces de la
home, robots.txt, sitemap.xml y los ficheros JS. De ahi salen endpoints y
parametros que probar A MANO. Todo son peticiones GET normales.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Set
from urllib.parse import parse_qs, urljoin, urlsplit

from . import scan

# Parametros cuyo nombre sugiere una clase de bug concreta.
INTERESTING_PARAMS = {
    "redirect": "redirect", "url": "redirect", "next": "redirect", "return": "redirect",
    "returnurl": "redirect", "continue": "redirect", "dest": "redirect", "goto": "redirect",
    "id": "idor", "user": "idor", "uid": "idor", "account": "idor", "order": "idor",
    "doc": "idor", "file": "upload", "callback": "ssrf", "webhook": "ssrf", "fetch": "ssrf",
    "q": "secrets", "search": "secrets", "debug": "secrets",
}


@dataclass
class Endpoint:
    url: str
    params: List[str] = field(default_factory=list)
    hints: Set[str] = field(default_factory=set)


@dataclass
class SurfaceMap:
    base: str
    endpoints: List[Endpoint] = field(default_factory=list)
    js_files: List[str] = field(default_factory=list)
    robots_paths: List[str] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)


def _extract_links(body: str, base: str) -> Set[str]:
    links = set()
    for m in re.findall(r'(?:href|src|action)=["\']([^"\'#]+)["\']', body, re.IGNORECASE):
        if m.startswith(("mailto:", "tel:", "javascript:", "data:")):
            continue
        links.add(urljoin(base, m))
    return links


def _analyze(url: str) -> Endpoint:
    parts = urlsplit(url)
    params = sorted(parse_qs(parts.query).keys())
    ep = Endpoint(url=url, params=params)
    for p in params:
        hint = INTERESTING_PARAMS.get(p.lower())
        if hint:
            ep.hints.add(hint)
    # pistas por la ruta
    low = (parts.path or "").lower()
    if "/api/" in low or low.endswith((".json",)):
        ep.hints.add("idor")
    if any(w in low for w in ("login", "signin", "auth", "session")):
        ep.hints.add("auth")
    if any(w in low for w in ("reset", "forgot", "recover")):
        ep.hints.add("pwreset")
    if "upload" in low:
        ep.hints.add("upload")
    return ep


def build(base_url: str, same_host_only: bool = True, delay: float = 1.0, timeout: int = 20) -> SurfaceMap:
    if "://" not in base_url:
        base_url = "https://" + base_url
    sm = SurfaceMap(base=base_url)
    base_host = urlsplit(base_url).netloc

    home = scan.fetch(base_url, "GET", timeout=timeout)
    if home.error or home.status == 0:
        sm.notes.append(f"no se pudo cargar la home: {home.error or 'sin respuesta'}")
        return sm
    sm.notes.append(f"GET {base_url} -> {home.status}")

    found = _extract_links(home.body, home.final_url)

    # robots.txt y sitemap.xml: rutas que el propio sitio declara.
    import time

    time.sleep(delay)
    robots = scan.fetch(urljoin(base_url, "/robots.txt"), "GET", timeout=timeout)
    if robots.status == 200 and robots.body:
        for line in robots.body.splitlines():
            m = re.match(r"\s*(?:allow|disallow)\s*:\s*(\S+)", line, re.IGNORECASE)
            if m and m.group(1) != "/":
                sm.robots_paths.append(m.group(1))
                found.add(urljoin(base_url, m.group(1)))

    time.sleep(delay)
    sitemap = scan.fetch(urljoin(base_url, "/sitemap.xml"), "GET", timeout=timeout)
    if sitemap.status == 200 and sitemap.body:
        for loc in re.findall(r"<loc>([^<]+)</loc>", sitemap.body, re.IGNORECASE):
            found.add(loc.strip())

    seen: Dict[str, Endpoint] = {}
    for link in found:
        host = urlsplit(link).netloc
        if same_host_only and host != base_host:
            continue
        if link.lower().endswith(".js"):
            sm.js_files.append(link)
            continue
        ep = _analyze(link)
        key = urlsplit(link)._replace(query="").geturl()
        if key not in seen or ep.params:
            seen[key] = ep
    sm.endpoints = sorted(seen.values(), key=lambda e: (not e.hints, e.url))
    sm.js_files = sorted(set(sm.js_files))
    return sm
