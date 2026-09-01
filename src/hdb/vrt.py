"""Vulnerability Rating Taxonomy de Bugcrowd.

El VRT es lo que el triager usa para clasificar y priorizar (P1..P5). Elegir el
VRT correcto al enviar acelera el triage y evita que te bajen la prioridad.

Fuente: https://github.com/bugcrowd/vulnerability-rating-taxonomy
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional

from . import fetch, store

VRT_URL = "https://raw.githubusercontent.com/bugcrowd/vulnerability-rating-taxonomy/master/vulnerability-rating-taxonomy.json"
CWE_URL = "https://raw.githubusercontent.com/bugcrowd/vulnerability-rating-taxonomy/master/mappings/cwe/cwe.json"

PRIORITY_LABEL = {
    1: "P1 - Critical",
    2: "P2 - Severe",
    3: "P3 - Moderate",
    4: "P4 - Low",
    5: "P5 - Informational (normalmente no se paga)",
}


@dataclass(frozen=True)
class Entry:
    """Una hoja o nodo del VRT, aplanado."""

    id: str  # ruta completa: categoria.subcategoria.variante
    name: str  # nombre legible completo
    type: str
    priority: Optional[int]  # None = "varies", lo decide el programa
    cwe: List[str]

    @property
    def priority_label(self) -> str:
        if self.priority is None:
            return "Varies (lo fija el programa)"
        return PRIORITY_LABEL.get(self.priority, f"P{self.priority}")


def data_dir() -> Path:
    path = store.home() / "vrt"
    path.mkdir(parents=True, exist_ok=True)
    return path


def _bundled(name: str) -> Path:
    return Path(__file__).parent / "data" / name


def _load_raw(name: str, url: str, refresh: bool = False) -> dict:
    """Cache local -> copia incluida en el paquete -> descarga.

    Asi funciona sin red desde el primer uso; `hdb sync` trae la version nueva.
    """
    cached = data_dir() / name
    if refresh:
        payload = fetch.get_json(url)
        cached.write_text(json.dumps(payload), encoding="utf-8")
        return payload
    if cached.exists():
        return json.loads(cached.read_text(encoding="utf-8"))
    bundled = _bundled(name)
    if bundled.exists():
        return json.loads(bundled.read_text(encoding="utf-8"))
    payload = fetch.get_json(url)
    cached.write_text(json.dumps(payload), encoding="utf-8")
    return payload


def sync() -> str:
    """Descarga la ultima version del VRT. Devuelve la fecha de release."""
    payload = _load_raw("vrt.json", VRT_URL, refresh=True)
    _load_raw("cwe.json", CWE_URL, refresh=True)
    return payload.get("metadata", {}).get("release_date", "desconocida")


def _cwe_index(node: dict, prefix: str, out: Dict[str, List[str]]) -> None:
    node_id = f"{prefix}.{node['id']}" if prefix else node["id"]
    cwe = node.get("cwe")
    if cwe:
        out[node_id] = list(cwe) if isinstance(cwe, list) else [cwe]
    for child in node.get("children", []):
        _cwe_index(child, node_id, out)


def flatten(payload: dict, cwe_map: Optional[Dict[str, List[str]]] = None) -> List[Entry]:
    """Aplana el arbol del VRT.

    Si un nodo no trae prioridad hereda la del ancestro mas cercano; si nadie en
    la rama la tiene, queda en None ("varies": la fija el programa). El CWE se
    hereda igual: el mapeo oficial solo lo declara en los nodos altos.
    """
    cwe_map = cwe_map or {}
    entries: List[Entry] = []

    def walk(
        node: dict,
        id_prefix: str,
        name_prefix: str,
        inherited: Optional[int],
        inherited_cwe: List[str],
    ) -> None:
        node_id = f"{id_prefix}.{node['id']}" if id_prefix else node["id"]
        node_name = f"{name_prefix} > {node['name']}" if name_prefix else node["name"]
        priority = node.get("priority")
        effective = priority if priority is not None else inherited
        cwe = cwe_map.get(node_id) or inherited_cwe
        entries.append(
            Entry(
                id=node_id,
                name=node_name,
                type=node.get("type", ""),
                priority=effective,
                cwe=list(cwe),
            )
        )
        for child in node.get("children", []):
            walk(child, node_id, node_name, effective, cwe)

    for category in payload.get("content", []):
        walk(category, "", "", None, [])
    return entries


def load(refresh: bool = False) -> List[Entry]:
    payload = _load_raw("vrt.json", VRT_URL, refresh=refresh)
    cwe_map: Dict[str, List[str]] = {}
    try:
        cwe_payload = _load_raw("cwe.json", CWE_URL)
        for node in cwe_payload.get("content", []):
            _cwe_index(node, "", cwe_map)
    except Exception:
        pass
    return flatten(payload, cwe_map)


def search(query: str, limit: int = 15, leaves_only: bool = False) -> List[Entry]:
    """Busca por palabras: todas deben aparecer en el id o en el nombre."""
    words = [w for w in query.lower().split() if w]
    results = []
    for entry in load():
        if leaves_only and entry.type == "category":
            continue
        haystack = (entry.id + " " + entry.name).lower().replace("_", " ")
        if all(w.replace("_", " ") in haystack for w in words):
            results.append(entry)
    # Primero lo mas severo, luego lo mas especifico.
    results.sort(key=lambda e: (e.priority if e.priority is not None else 9, -e.id.count(".")))
    return results[:limit]


def get(vrt_id: str) -> Optional[Entry]:
    for entry in load():
        if entry.id == vrt_id:
            return entry
    return None
