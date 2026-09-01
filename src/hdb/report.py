"""Plantilla de reporte para Bugcrowd.

Un reporte flojo se marca como duplicado o baja de prioridad aunque el bug sea
bueno. La plantilla fuerza lo que el triager necesita: pasos exactos, impacto
demostrado y una remediacion concreta.
"""

from __future__ import annotations

import sqlite3
from typing import Optional

from . import vrt

TEMPLATE = """# {title}

- **Programa:** {program}
- **Target afectado:** {target}
- **VRT:** `{vrt_id}` — {vrt_name}
- **Prioridad sugerida:** {priority}
- **CWE:** {cwe}

## Resumen

<!-- Dos o tres frases: que falla, donde, y que consigue un atacante.
     El triager decide la prioridad leyendo esto. -->

## Pasos para reproducir

<!-- Numerados, exactos y copiables. Incluye la cuenta usada (atacante/victima),
     el request completo y el valor concreto que hay que manipular.
     Si hacen falta dos cuentas, dilo desde el paso 1. -->

1.
2.
3.

### Request

```http

```

### Respuesta

```http

```

## Prueba de concepto

<!-- Captura, video corto o script minimo. Sin datos de terceros: si tocaste
     datos que no son tuyos, para y documenta solo lo imprescindible. -->

## Impacto

<!-- Que puede hacer un atacante en la practica y a cuanta gente afecta.
     Concreto: "leer el email y telefono de cualquier usuario conociendo su id",
     no "podria comprometer la seguridad". -->

## Remediacion sugerida

<!-- Una recomendacion accionable. Sube el valor percibido del reporte. -->

## Referencias

-

---
<!-- Antes de enviar, comprueba:
     [ ] El target esta en scope (hdb scope check <url> -p {program_slug})
     [ ] Los pasos funcionan desde cero, en una sesion limpia
     [ ] No hay datos de terceros ni acciones destructivas
     [ ] El VRT elegido es el mas especifico que aplica
     [ ] Buscaste el mismo bug en la actividad publica del programa (duplicados) -->
"""


def render(
    title: str,
    program: str = "",
    program_slug: str = "",
    target: str = "",
    vrt_id: str = "",
    priority: Optional[int] = None,
) -> str:
    entry = vrt.get(vrt_id) if vrt_id else None
    if entry is not None:
        vrt_name = entry.name
        cwe = ", ".join(entry.cwe) if entry.cwe else "n/d"
        prio = entry.priority_label if priority is None else vrt.PRIORITY_LABEL.get(priority, str(priority))
    else:
        vrt_name = "(elige uno con `hdb vrt search <palabra>`)"
        cwe = "n/d"
        prio = vrt.PRIORITY_LABEL.get(priority or 0, "(por determinar)")
    return TEMPLATE.format(
        title=title,
        program=program or "(programa)",
        program_slug=program_slug or "<slug>",
        target=target or "(url o endpoint)",
        vrt_id=vrt_id or "sin_asignar",
        vrt_name=vrt_name,
        priority=prio,
        cwe=cwe,
    )


def render_finding(conn: sqlite3.Connection, row: sqlite3.Row) -> str:
    prog = conn.execute("SELECT name FROM programs WHERE slug = ?", (row["program_slug"],)).fetchone()
    body = render(
        title=row["title"],
        program=prog["name"] if prog else row["program_slug"],
        program_slug=row["program_slug"],
        target=row["target"] or "",
        vrt_id=row["vrt_id"] or "",
        priority=row["priority"],
    )
    if row["notes"]:
        body += f"\n## Notas privadas\n\n{row['notes']}\n"
    return body
