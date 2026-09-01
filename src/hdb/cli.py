"""Interfaz de linea de comandos de hdb."""

from __future__ import annotations

import argparse
import sqlite3
import time
import sys
from typing import Iterable, List, Optional

from . import findings as findings_mod
from . import scan as scan_mod
from . import programs, report, store, vrt
from .scope import IN_SCOPE, NOT_LISTED, OUT_OF_SCOPE, check

COLORS = {"green": "\033[32m", "red": "\033[31m", "yellow": "\033[33m", "dim": "\033[2m", "bold": "\033[1m"}
STATUS_COLOR = {IN_SCOPE: "green", OUT_OF_SCOPE: "red", NOT_LISTED: "yellow"}
STATUS_TEXT = {IN_SCOPE: "IN-SCOPE", OUT_OF_SCOPE: "OUT-OF-SCOPE", NOT_LISTED: "NO-LISTADO"}


def paint(text: str, color: str) -> str:
    if not sys.stdout.isatty() or color not in COLORS:
        return text
    return f"{COLORS[color]}{text}\033[0m"


def err(message: str) -> int:
    print(f"error: {message}", file=sys.stderr)
    return 2


def read_lines(source: Optional[str]) -> List[str]:
    """Lee de un fichero, o de stdin si es '-' o no se indica nada."""
    if source and source != "-":
        with open(source, "r", encoding="utf-8") as fh:
            data = fh.read()
    else:
        data = sys.stdin.read()
    return [line.strip() for line in data.splitlines() if line.strip() and not line.strip().startswith("#")]


def pick_program(conn: sqlite3.Connection, needle: str) -> Optional[str]:
    matches = programs.resolve_slug(conn, needle)
    if not matches:
        err(f"no hay ningun programa que coincida con '{needle}'. Prueba: hdb program list -s {needle}")
        return None
    if len(matches) > 1:
        print(f"'{needle}' coincide con varios programas:", file=sys.stderr)
        for slug in matches[:15]:
            print(f"  {slug}", file=sys.stderr)
        return None
    return matches[0]


# --------------------------------------------------------------------------- sync


def cmd_sync(args: argparse.Namespace) -> int:
    with store.session() as conn:
        print("Descargando programas publicos de Bugcrowd...")
        n_prog, n_targets = programs.sync(conn)
        print(f"  {n_prog} programas, {n_targets} targets")
    print("Descargando el VRT...")
    release = vrt.sync()
    print(f"  VRT release {release}")
    print(f"\nDatos en {store.home()}")
    return 0


# --------------------------------------------------------------------------- program


def cmd_program_list(args: argparse.Namespace) -> int:
    with store.session() as conn:
        rows = programs.search(conn, args.search or "", args.min_payout, args.safe_harbor or "", args.limit)
        if not rows:
            print("Sin resultados. Si es la primera vez, ejecuta: hdb sync")
            return 1
        for row in rows:
            payout = f"${row['max_payout']:,}" if row["max_payout"] else "-"
            harbor = row["safe_harbor"] or "?"
            print(f"{row['slug']:<38} {payout:>10}  safe-harbor:{harbor:<8} {row['name']}")
        print(paint(f"\n{len(rows)} programas", "dim"))
    return 0


def cmd_program_show(args: argparse.Namespace) -> int:
    with store.session() as conn:
        slug = pick_program(conn, args.program)
        if not slug:
            return 2
        row = programs.get_program(conn, slug)
        print(paint(f"{row['name']}  ({slug})", "bold"))
        print(f"  url:          {row['url'] or '-'}")
        print(f"  max payout:   {row['max_payout'] or '-'}")
        print(f"  safe harbor:  {row['safe_harbor'] or '-'}")
        print(f"  gestionado:   {'si' if row['managed'] else 'no'}")
        print(f"  divulgacion:  {'permitida' if row['disclosure'] else 'no permitida'}")
        rules = programs.rules_for(conn, slug)
        for category, title in ((IN_SCOPE, "IN SCOPE"), (OUT_OF_SCOPE, "OUT OF SCOPE")):
            subset = [r for r in rules if r.category == category]
            print(paint(f"\n{title} ({len(subset)})", "green" if category == IN_SCOPE else "red"))
            for rule in subset:
                flag = "" if rule.automatable else paint("  <- revisar a mano", "yellow")
                ttype = f"[{rule.target_type}] " if rule.target_type else ""
                print(f"  {ttype}{rule.raw}{flag}")
    return 0


def cmd_program_import(args: argparse.Namespace) -> int:
    in_scope = read_lines(args.in_scope) if args.in_scope else []
    out_scope = read_lines(args.out_of_scope) if args.out_of_scope else []
    if not in_scope and not out_scope:
        return err("no hay targets que importar (usa --in-scope y/o --out-of-scope)")
    with store.session() as conn:
        count = programs.upsert_manual(
            conn, args.slug, args.name or args.slug, in_scope, out_scope, args.url or "", replace=not args.append
        )
        print(f"{args.slug}: {count} targets importados")
    return 0


# --------------------------------------------------------------------------- scope


def _print_verdict(verdict, show_program: bool = False) -> None:
    label = paint(STATUS_TEXT[verdict.status], STATUS_COLOR[verdict.status])
    prefix = f"{verdict.program}  " if show_program and verdict.program else ""
    print(f"{prefix}{label:<24} {verdict.query.raw}  {paint(verdict.reason(), 'dim')}")


def cmd_scope_check(args: argparse.Namespace) -> int:
    targets = args.targets or read_lines(None)
    if not targets:
        return err("no hay nada que comprobar")
    worst = 0
    with store.session() as conn:
        if args.program:
            slug = pick_program(conn, args.program)
            if not slug:
                return 2
            rules = programs.rules_for(conn, slug)
            if not rules:
                return err(f"el programa {slug} no tiene targets guardados (ejecuta: hdb sync)")
            manual = [r for r in rules if not r.automatable]
            for target in targets:
                verdict = check(target, rules, slug)
                _print_verdict(verdict)
                worst = max(worst, verdict.exit_code)
            if manual:
                print(paint(f"\nAviso: {len(manual)} targets del brief no son comprobables automaticamente:", "yellow"))
                for rule in manual[:10]:
                    print(paint(f"  {rule.describe()}", "yellow"))
        else:
            index = programs.all_rules(conn)
            if not index:
                return err("no hay programas cargados. Ejecuta: hdb sync")
            for target in targets:
                hits = []
                for slug, rules in index.items():
                    verdict = check(target, rules, slug)
                    if verdict.status != NOT_LISTED:
                        hits.append(verdict)
                if not hits:
                    print(f"{paint('NO-LISTADO', 'yellow'):<24} {target}  {paint('en ningun programa publico', 'dim')}")
                    worst = max(worst, 2)
                    continue
                hits.sort(key=lambda v: 0 if v.status == OUT_OF_SCOPE else 1)
                for verdict in hits:
                    _print_verdict(verdict, show_program=True)
                    worst = max(worst, verdict.exit_code)
    return worst


def cmd_scope_filter(args: argparse.Namespace) -> int:
    """Lee hosts por stdin y deja pasar solo los que estan en scope."""
    with store.session() as conn:
        slug = pick_program(conn, args.program)
        if not slug:
            return 2
        rules = programs.rules_for(conn, slug)
        if not rules:
            return err(f"el programa {slug} no tiene targets guardados (ejecuta: hdb sync)")
        kept = dropped = 0
        for target in read_lines(args.file):
            verdict = check(target, rules, slug)
            if verdict.status == IN_SCOPE or (args.include_unknown and verdict.status == NOT_LISTED):
                print(target)
                kept += 1
            else:
                dropped += 1
                if args.verbose:
                    print(f"descartado {target}: {verdict.reason()}", file=sys.stderr)
        print(f"{kept} dentro de scope, {dropped} descartados", file=sys.stderr)
    return 0


# --------------------------------------------------------------------------- vrt


def cmd_vrt_search(args: argparse.Namespace) -> int:
    results = vrt.search(" ".join(args.query), limit=args.limit, leaves_only=not args.all)
    if not results:
        print("Sin coincidencias. Prueba con menos palabras o en ingles (el VRT esta en ingles).")
        return 1
    for entry in results:
        color = "red" if entry.priority in (1, 2) else ("yellow" if entry.priority == 3 else "dim")
        print(f"{paint(entry.priority_label, color):<28} {entry.id}")
        print(f"    {entry.name}")
    return 0


def cmd_vrt_show(args: argparse.Namespace) -> int:
    entry = vrt.get(args.vrt_id)
    if entry is None:
        return err(f"no existe el VRT '{args.vrt_id}'. Busca con: hdb vrt search <palabra>")
    print(paint(entry.name, "bold"))
    print(f"  id:        {entry.id}")
    print(f"  tipo:      {entry.type}")
    print(f"  prioridad: {entry.priority_label}")
    print(f"  cwe:       {', '.join(entry.cwe) if entry.cwe else 'n/d'}")
    return 0


# --------------------------------------------------------------------------- assets


def cmd_assets_add(args: argparse.Namespace) -> int:
    """Guarda hosts descubiertos y muestra cuales son nuevos desde la ultima vez."""
    with store.session() as conn:
        slug = pick_program(conn, args.program)
        if not slug:
            return 2
        rules = programs.rules_for(conn, slug)
        stamp = store.now()
        new_hosts: List[str] = []
        seen = 0
        for host in read_lines(args.file):
            verdict = check(host, rules, slug) if rules else None
            status = verdict.status if verdict else NOT_LISTED
            if args.only_in_scope and status != IN_SCOPE:
                continue
            seen += 1
            row = conn.execute(
                "SELECT id FROM assets WHERE program_slug = ? AND host = ?", (slug, host)
            ).fetchone()
            if row:
                conn.execute(
                    "UPDATE assets SET last_seen = ?, scope_status = ? WHERE id = ?", (stamp, status, row["id"])
                )
            else:
                conn.execute(
                    """INSERT INTO assets(program_slug, host, source, scope_status, first_seen, last_seen)
                       VALUES(?,?,?,?,?,?)""",
                    (slug, host, args.source or "", status, stamp, stamp),
                )
                new_hosts.append(f"{host}\t{status}")
        for line in new_hosts:
            print(line)
        print(f"{seen} hosts procesados, {len(new_hosts)} nuevos", file=sys.stderr)
    return 0


def cmd_assets_list(args: argparse.Namespace) -> int:
    with store.session() as conn:
        slug = pick_program(conn, args.program)
        if not slug:
            return 2
        sql = "SELECT * FROM assets WHERE program_slug = ?"
        params: List[object] = [slug]
        if args.in_scope:
            sql += " AND scope_status = ?"
            params.append(IN_SCOPE)
        sql += " ORDER BY first_seen DESC, host"
        rows = conn.execute(sql, params).fetchall()
        for row in rows:
            print(f"{row['host']:<50} {row['scope_status'] or '?':<14} visto {row['first_seen'][:10]} -> {row['last_seen'][:10]}")
        print(f"{len(rows)} assets", file=sys.stderr)
    return 0


# --------------------------------------------------------------------------- findings


def cmd_finding_new(args: argparse.Namespace) -> int:
    with store.session() as conn:
        slug = pick_program(conn, args.program)
        if not slug:
            return 2
        priority = args.priority
        if args.vrt and priority is None:
            entry = vrt.get(args.vrt)
            if entry is None:
                return err(f"no existe el VRT '{args.vrt}'")
            priority = entry.priority
        if args.target:
            rules = programs.rules_for(conn, slug)
            if rules:
                verdict = check(args.target, rules, slug)
                _print_verdict(verdict)
                if verdict.status == OUT_OF_SCOPE and not args.force:
                    return err("ese target esta fuera de scope. Usa --force si aun asi quieres registrarlo.")
        fid = findings_mod.create(conn, slug, args.title, args.vrt or "", priority, args.target or "", args.notes or "")
        print(f"hallazgo #{fid} creado en {slug}")
        print(f"  plantilla: hdb report {fid} -o reporte-{fid}.md")
    return 0


def cmd_finding_list(args: argparse.Namespace) -> int:
    with store.session() as conn:
        program = ""
        if args.program:
            program = pick_program(conn, args.program) or ""
            if not program:
                return 2
        rows = findings_mod.listing(conn, program, args.status or "")
        for row in rows:
            prio = f"P{row['priority']}" if row["priority"] else "P?"
            print(f"#{row['id']:<4} {prio:<4} {row['status']:<14} {row['program_slug']:<28} {row['title']}")
        print(f"{len(rows)} hallazgos", file=sys.stderr)
    return 0


def cmd_finding_set(args: argparse.Namespace) -> int:
    with store.session() as conn:
        if args.status and args.status not in findings_mod.STATUSES:
            return err(f"estado invalido. Validos: {', '.join(findings_mod.STATUSES)}")
        ok = findings_mod.update(
            conn,
            args.id,
            status=args.status,
            title=args.title,
            vrt_id=args.vrt,
            priority=args.priority,
            target=args.target,
            notes=args.notes,
        )
        if not ok:
            return err(f"no se actualizo el hallazgo #{args.id} (revisa el id y los campos)")
        print(f"hallazgo #{args.id} actualizado")
    return 0


def cmd_report(args: argparse.Namespace) -> int:
    with store.session() as conn:
        row = findings_mod.get(conn, args.id)
        if row is None:
            return err(f"no existe el hallazgo #{args.id}")
        body = report.render_finding(conn, row)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(body)
        print(f"escrito en {args.output}")
    else:
        print(body)
    return 0


# --------------------------------------------------------------------------- scan


GUARDRAILS = (
    "Guardarrailes activos: solo peticiones de lectura (GET/HEAD), solo hosts "
    "in-scope, con rate limit. No inyecta payloads ni fuerza nada."
)


def cmd_scan(args: argparse.Namespace) -> int:
    with store.session() as conn:
        slug = pick_program(conn, args.program)
        if not slug:
            return 2
        rules = programs.rules_for(conn, slug)
        if not rules:
            return err(f"el programa {slug} no tiene targets guardados (ejecuta: hdb sync)")

        targets = args.targets or read_lines(None)
        if not targets:
            return err("no hay urls que escanear")

        print(paint(GUARDRAILS, "dim"))
        scanned = skipped = saved = 0
        worst_priority = 6
        for raw in targets:
            verdict = check(raw, rules, slug)
            if verdict.status != IN_SCOPE:
                skipped += 1
                label = STATUS_TEXT[verdict.status]
                print(paint(f"SALTADO   {raw}  ({label}: {verdict.reason()})", "yellow"))
                continue
            print(paint(f"\nescaneando {raw} ...", "bold"))
            result = scan_mod.scan_url(raw, delay=args.delay, timeout=args.timeout, probe_cors=not args.no_cors)
            for note in result.notes:
                print(paint(f"  {note}", "dim"))
            if not result.reachable:
                continue
            scanned += 1
            if not result.issues:
                print(paint("  sin hallazgos automaticos (revisa a mano la logica de negocio)", "green"))
            for issue in result.issues:
                color = "red" if issue.priority in (1, 2, 3) else "dim"
                print("  " + paint(issue.as_line(), color))
                print(paint(f"      {issue.evidence}", "dim"))
                if issue.priority is not None:
                    worst_priority = min(worst_priority, issue.priority)
                if args.save:
                    fid = findings_mod.create(
                        conn, slug, issue.title, issue.vrt_id, issue.priority, issue.url,
                        notes=f"Detectado por hdb scan.\nEvidencia: {issue.evidence}\nRemediacion: {issue.recommendation}",
                    )
                    saved += 1
                    print(paint(f"      -> guardado como hallazgo #{fid}", "green"))
            time.sleep(args.delay)

        msg = f"\n{scanned} host(s) escaneados, {skipped} saltados fuera de scope"
        if args.save:
            msg += f", {saved} hallazgos guardados"
        print(paint(msg, "dim"))
        if saved:
            print(paint("Revisa cada hallazgo antes de reportar: hdb finding list -p " + slug, "dim"))
    return 0


# --------------------------------------------------------------------------- submit


def cmd_submit(args: argparse.Namespace) -> int:
    """Prepara el paquete de envio y muestra el canal oficial. NO envia nada."""
    with store.session() as conn:
        row = findings_mod.get(conn, args.id)
        if row is None:
            return err(f"no existe el hallazgo #{args.id}")
        prog = programs.get_program(conn, row["program_slug"])
        body = report.render_finding(conn, row)

    out = args.output or f"reporte-{args.id}.md"
    with open(out, "w", encoding="utf-8") as fh:
        fh.write(body)

    print(paint("Paquete de envio preparado (no se ha enviado nada).", "bold"))
    print(f"  reporte:  {out}")
    print(paint("\nCanal oficial de envio:", "bold"))
    if prog and prog["url"]:
        print(f"  Bugcrowd: {prog['url']}")
        print("            Sube el reporte por la plataforma; es el canal valido y protegido.")
    else:
        print("  (programa sin URL guardada) Envia por el canal oficial del programa en Bugcrowd.")
    host = ""
    if row["target"]:
        from urllib.parse import urlsplit
        host = urlsplit(row["target"] if "://" in row["target"] else "//" + row["target"]).netloc
    if args.check_securitytxt and host:
        print(paint("\nBuscando security.txt del target...", "dim"))
        txt = scan_mod.fetch_security_txt(host)
        if txt:
            print("  security.txt encontrado (contacto declarado por la empresa):")
            for line in txt.splitlines():
                if line.strip().lower().startswith(("contact", "policy", "encryption")):
                    print(f"    {line.strip()}")
        else:
            print("  sin security.txt: usa el canal de Bugcrowd.")
    print(paint(
        "\nAntes de enviar, revisa el reporte a mano: los hallazgos automaticos son un "
        "punto de partida, no un envio en un clic.", "yellow"))
    return 0


# --------------------------------------------------------------------------- parser


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="hdb",
        description="Herramienta de bug bounty para Bugcrowd: scope, VRT y seguimiento de hallazgos.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("sync", help="descarga programas publicos de Bugcrowd y el VRT")
    p.set_defaults(func=cmd_sync)

    prog = sub.add_parser("program", help="programas y sus scopes").add_subparsers(dest="sub", required=True)

    p = prog.add_parser("list", help="lista programas")
    p.add_argument("-s", "--search", help="filtra por nombre o slug")
    p.add_argument("--min-payout", type=int, default=0, help="pago maximo minimo")
    p.add_argument("--safe-harbor", help="full | partial | none")
    p.add_argument("--limit", type=int, default=40)
    p.set_defaults(func=cmd_program_list)

    p = prog.add_parser("show", help="muestra el scope completo de un programa")
    p.add_argument("program")
    p.set_defaults(func=cmd_program_show)

    p = prog.add_parser("import", help="importa a mano el scope de un programa privado")
    p.add_argument("slug")
    p.add_argument("--name")
    p.add_argument("--url")
    p.add_argument("--in-scope", help="fichero con un target por linea, o - para stdin")
    p.add_argument("--out-of-scope", help="fichero con un target por linea")
    p.add_argument("--append", action="store_true", help="anade en vez de reemplazar")
    p.set_defaults(func=cmd_program_import)

    scope = sub.add_parser("scope", help="comprueba si algo esta en scope").add_subparsers(dest="sub", required=True)

    p = scope.add_parser("check", help="comprueba uno o varios targets (exit 0=in, 1=out, 2=no listado)")
    p.add_argument("targets", nargs="*", help="urls o hosts; si se omite, lee de stdin")
    p.add_argument("-p", "--program", help="limita la comprobacion a un programa")
    p.set_defaults(func=cmd_scope_check)

    p = scope.add_parser("filter", help="filtra una lista de hosts dejando solo los de scope")
    p.add_argument("-p", "--program", required=True)
    p.add_argument("-f", "--file", help="fichero de entrada (por defecto stdin)")
    p.add_argument("--include-unknown", action="store_true", help="deja pasar tambien los no listados")
    p.add_argument("-v", "--verbose", action="store_true", help="explica los descartes por stderr")
    p.set_defaults(func=cmd_scope_filter)

    vrt_p = sub.add_parser("vrt", help="taxonomia VRT de Bugcrowd").add_subparsers(dest="sub", required=True)

    p = vrt_p.add_parser("search", help="busca una categoria VRT y su prioridad")
    p.add_argument("query", nargs="+")
    p.add_argument("--limit", type=int, default=15)
    p.add_argument("--all", action="store_true", help="incluye tambien las categorias raiz")
    p.set_defaults(func=cmd_vrt_search)

    p = vrt_p.add_parser("show", help="detalle de un id VRT")
    p.add_argument("vrt_id")
    p.set_defaults(func=cmd_vrt_show)

    assets = sub.add_parser("assets", help="inventario de hosts descubiertos").add_subparsers(dest="sub", required=True)

    p = assets.add_parser("add", help="guarda hosts y muestra los nuevos (ideal para diffs de recon)")
    p.add_argument("-p", "--program", required=True)
    p.add_argument("-f", "--file", help="fichero de entrada (por defecto stdin)")
    p.add_argument("--source", help="etiqueta de origen, p.ej. subfinder")
    p.add_argument("--only-in-scope", action="store_true")
    p.set_defaults(func=cmd_assets_add)

    p = assets.add_parser("list", help="lista los hosts guardados")
    p.add_argument("-p", "--program", required=True)
    p.add_argument("--in-scope", action="store_true")
    p.set_defaults(func=cmd_assets_list)

    finding = sub.add_parser("finding", help="seguimiento de hallazgos").add_subparsers(dest="sub", required=True)

    p = finding.add_parser("new", help="registra un hallazgo")
    p.add_argument("-p", "--program", required=True)
    p.add_argument("-t", "--title", required=True)
    p.add_argument("--vrt", help="id VRT (busca con hdb vrt search)")
    p.add_argument("--priority", type=int, choices=[1, 2, 3, 4, 5])
    p.add_argument("--target", help="url o endpoint afectado")
    p.add_argument("--notes")
    p.add_argument("--force", action="store_true", help="registra aunque el target este fuera de scope")
    p.set_defaults(func=cmd_finding_new)

    p = finding.add_parser("list", help="lista hallazgos")
    p.add_argument("-p", "--program")
    p.add_argument("--status", choices=list(findings_mod.STATUSES))
    p.set_defaults(func=cmd_finding_list)

    p = finding.add_parser("set", help="actualiza un hallazgo")
    p.add_argument("id", type=int)
    p.add_argument("--status", choices=list(findings_mod.STATUSES))
    p.add_argument("--title")
    p.add_argument("--vrt")
    p.add_argument("--priority", type=int, choices=[1, 2, 3, 4, 5])
    p.add_argument("--target")
    p.add_argument("--notes")
    p.set_defaults(func=cmd_finding_set)

    p = sub.add_parser("report", help="genera la plantilla de reporte de un hallazgo")
    p.add_argument("id", type=int)
    p.add_argument("-o", "--output", help="fichero de salida")
    p.set_defaults(func=cmd_report)

    p = sub.add_parser("scan", help="verifica una pagina con checks pasivos de solo lectura (in-scope)")
    p.add_argument("targets", nargs="*", help="urls o hosts; si se omite, lee de stdin")
    p.add_argument("-p", "--program", required=True, help="programa contra cuyo scope se valida")
    p.add_argument("--delay", type=float, default=1.0, help="segundos entre peticiones (rate limit)")
    p.add_argument("--timeout", type=int, default=20)
    p.add_argument("--no-cors", action="store_true", help="omite la prueba de CORS")
    p.add_argument("--save", action="store_true", help="guarda cada hallazgo para seguimiento")
    p.set_defaults(func=cmd_scan)

    p = sub.add_parser("submit", help="prepara el paquete de un hallazgo y muestra el canal oficial (no envia)")
    p.add_argument("id", type=int)
    p.add_argument("-o", "--output")
    p.add_argument("--check-securitytxt", action="store_true", help="busca el security.txt del target")
    p.set_defaults(func=cmd_submit)

    return parser


def main(argv: Optional[Iterable[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)
    try:
        return int(args.func(args))
    except KeyboardInterrupt:
        return 130
    except BrokenPipeError:
        return 0
    except Exception as exc:  # noqa: BLE001 - la CLI reporta el fallo, no revienta
        return err(str(exc))


if __name__ == "__main__":
    sys.exit(main())
