"""Motor de scope.

Convierte los targets de un programa de Bugcrowd en reglas comparables y
decide si una URL, host o IP esta dentro del scope.

Regla de oro: ante la duda, NO es scope. Una regla out-of-scope siempre gana
sobre una in-scope, y lo que no matchea con nada se reporta como desconocido
(nunca como permitido).
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from typing import Iterable, List, Optional, Sequence
from urllib.parse import urlsplit

IN_SCOPE = "in_scope"
OUT_OF_SCOPE = "out_of_scope"
NOT_LISTED = "not_listed"

# Tipos de target que no son hosts de red (apps moviles, binarios, hardware...).
# Nunca se pueden validar automaticamente contra una URL.
NON_NETWORK_TYPES = {
    "android", "ios", "windows", "macos", "linux", "hardware", "iot",
    "source_code", "sourcecode", "executable", "other",
}

_IPV4_CIDR = re.compile(r"^\d{1,3}(\.\d{1,3}){3}/\d{1,2}$")
_HOSTNAME = re.compile(r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+\.?$")


def normalize_host(value: str) -> str:
    """Baja a minusculas, quita el punto final y el puerto."""
    host = value.strip().lower().rstrip(".")
    if host.startswith("[") and "]" in host:  # IPv6 literal
        return host[1 : host.index("]")]
    if host.count(":") == 1:
        head, _, tail = host.partition(":")
        if tail.isdigit():
            return head
    return host


@dataclass(frozen=True)
class Query:
    """Lo que el usuario quiere comprobar."""

    raw: str
    host: str = ""
    path: str = "/"
    scheme: str = ""
    ip: Optional[str] = None

    @classmethod
    def parse(cls, value: str) -> "Query":
        raw = value.strip()
        candidate = raw if "//" in raw else "//" + raw
        parts = urlsplit(candidate, scheme="")
        host = normalize_host(parts.netloc or "")
        path = parts.path or "/"
        if not host:  # p.ej. "example.com/foo" sin esquema quedo todo en path
            head, _, rest = raw.partition("/")
            host = normalize_host(head)
            path = "/" + rest if rest else "/"
        ip = None
        try:
            ip = str(ipaddress.ip_address(host))
        except ValueError:
            pass
        return cls(raw=raw, host=host, path=path or "/", scheme=parts.scheme, ip=ip)


@dataclass(frozen=True)
class Rule:
    """Un target del programa, ya interpretado."""

    raw: str
    category: str  # IN_SCOPE u OUT_OF_SCOPE
    kind: str  # wildcard | domain | url | cidr | ip | non_network | unparsed
    host: str = ""
    path_prefix: str = ""
    target_type: str = ""
    name: str = ""
    network: Optional[str] = None

    @property
    def automatable(self) -> bool:
        """False = requiere que un humano lea el brief."""
        return self.kind in {"wildcard", "domain", "url", "cidr", "ip"}

    def describe(self) -> str:
        return f"[{self.category}] {self.raw or self.name}"

    def matches(self, query: Query) -> bool:
        if self.kind == "cidr" and query.ip:
            try:
                return ipaddress.ip_address(query.ip) in ipaddress.ip_network(self.network, strict=False)
            except ValueError:
                return False
        if self.kind == "ip":
            return bool(query.ip) and query.ip == self.host
        if self.kind == "wildcard":
            return query.host == self.host or query.host.endswith("." + self.host)
        if self.kind == "domain":
            return query.host == self.host
        if self.kind == "url":
            if query.host != self.host:
                return False
            if not self.path_prefix or self.path_prefix == "/":
                return True
            return query.path.startswith(self.path_prefix)
        return False


def parse_target(target: str, category: str, target_type: str = "", name: str = "") -> Rule:
    """Interpreta el string de un target de Bugcrowd."""
    raw = (target or "").strip()
    ttype = (target_type or "").strip().lower()
    base = dict(raw=raw, category=category, target_type=ttype, name=(name or "").strip())

    if not raw:
        return Rule(kind="unparsed", **base)

    # Apps moviles, binarios o hardware: no hay host que comparar.
    if ttype in NON_NETWORK_TYPES and "://" not in raw:
        return Rule(kind="non_network", **base)

    # El CIDR lleva "/" pero no es una ruta, hay que mirarlo antes de partir.
    if _IPV4_CIDR.match(raw):
        try:
            ipaddress.ip_network(raw, strict=False)
            return Rule(kind="cidr", host=raw, network=raw, **base)
        except ValueError:
            return Rule(kind="unparsed", **base)

    candidate = raw
    scheme_present = "://" in candidate
    if scheme_present:
        parts = urlsplit(candidate)
        host_part = parts.netloc
        path_part = parts.path or ""
    else:
        head, _, rest = candidate.partition("/")
        host_part = head
        path_part = "/" + rest if rest else ""

    host = normalize_host(host_part)
    path = path_part.split("?", 1)[0].split("#", 1)[0]
    path = path.rstrip("*")
    if path in ("", "/"):
        path = ""

    if host.startswith("*."):
        apex = host[2:]
        if _HOSTNAME.match(apex):
            return Rule(kind="wildcard", host=apex, path_prefix=path, **base)
        return Rule(kind="unparsed", **base)

    if "*" in host:
        # p.ej. "api-*.example.com": no lo adivinamos, lo marcamos manual.
        return Rule(kind="unparsed", **base)

    try:
        ipaddress.ip_address(host)
        return Rule(kind="ip", host=host, **base)
    except ValueError:
        pass

    if _HOSTNAME.match(host):
        if path:
            return Rule(kind="url", host=host, path_prefix=path, **base)
        if scheme_present:
            # "https://example.com" apunta a ese host exacto, no a sus subdominios.
            return Rule(kind="domain", host=host, **base)
        return Rule(kind="domain", host=host, **base)

    return Rule(kind="unparsed", **base)


@dataclass
class Verdict:
    """Resultado de comprobar un target contra un programa."""

    query: Query
    status: str
    matched: List[Rule] = field(default_factory=list)
    program: str = ""
    manual_review: List[Rule] = field(default_factory=list)

    @property
    def allowed(self) -> bool:
        return self.status == IN_SCOPE

    @property
    def exit_code(self) -> int:
        return {IN_SCOPE: 0, OUT_OF_SCOPE: 1, NOT_LISTED: 2}[self.status]

    def reason(self) -> str:
        if self.status == IN_SCOPE:
            return "coincide con " + ", ".join(r.raw for r in self.matched)
        if self.status == OUT_OF_SCOPE:
            return "excluido explicitamente por " + ", ".join(r.raw for r in self.matched)
        return "ningun target del programa coincide"


def check(query: str, rules: Sequence[Rule], program: str = "") -> Verdict:
    """Decide el veredicto. Out-of-scope siempre gana."""
    q = Query.parse(query)
    outs = [r for r in rules if r.category == OUT_OF_SCOPE and r.matches(q)]
    if outs:
        return Verdict(q, OUT_OF_SCOPE, _most_specific(outs), program)
    ins = [r for r in rules if r.category == IN_SCOPE and r.matches(q)]
    if ins:
        return Verdict(q, IN_SCOPE, _most_specific(ins), program)
    manual = [r for r in rules if not r.automatable]
    return Verdict(q, NOT_LISTED, [], program, manual_review=manual)


def _most_specific(rules: Iterable[Rule]) -> List[Rule]:
    order = {"url": 0, "ip": 1, "domain": 2, "cidr": 3, "wildcard": 4}
    return sorted(rules, key=lambda r: (order.get(r.kind, 9), -len(r.host), -len(r.path_prefix)))
