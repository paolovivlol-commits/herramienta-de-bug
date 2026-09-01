# hdb — herramienta de bug bounty para Bugcrowd

CLI en Python sin dependencias externas. Resuelve tres cosas que en Bugcrowd
cuestan tiempo o dinero:

1. **Scope.** Comprobar que un host está dentro del alcance *antes* de tocarlo.
   Testear fuera de scope se cierra como *not applicable* y, con safe harbor
   parcial, te deja sin protección legal.
2. **VRT.** Elegir la categoría correcta de la Vulnerability Rating Taxonomy de
   Bugcrowd, que es lo que fija la prioridad P1–P5 y por tanto el pago.
3. **Seguimiento.** Saber qué hallazgos tienes, en qué estado y con qué reporte.

## Instalación

```bash
pip install -e .        # deja el comando `hdb` en el PATH
# o sin instalar nada:
PYTHONPATH=src python3 -m hdb --help
```

Requiere Python 3.9+. Los datos se guardan en `~/.hdb` (cambiable con `HDB_HOME`).

## Primer uso

```bash
hdb sync    # descarga los 265 programas públicos de Bugcrowd y el VRT oficial
```

`sync` toma los scopes de [bounty-targets-data](https://github.com/arkadiyt/bounty-targets-data)
(que rastrea las páginas públicas de Bugcrowd a diario) y el VRT del
[repo oficial de Bugcrowd](https://github.com/bugcrowd/vulnerability-rating-taxonomy).
El VRT viene además incluido en el paquete, así que funciona sin red desde el
primer momento.

## Scope

```bash
hdb program list --min-payout 10000        # dónde hay dinero
hdb program show tesla                     # scope completo, in y out

hdb scope check https://api.tesla.com/v1 -p tesla
# IN-SCOPE    https://api.tesla.com/v1   coincide con *.tesla.com

hdb scope check https://engage.tesla.com -p tesla
# OUT-OF-SCOPE  ...  excluido explicitamente por *.engage.tesla.com

hdb scope check api.tesla.com              # sin -p: busca en todos los programas
```

Los códigos de salida están pensados para scripts: **0** in-scope, **1**
out-of-scope, **2** no listado. Así puedes cortar un pipeline antes de lanzar
nada:

```bash
hdb scope check "$TARGET" -p tesla || { echo "fuera de scope, no toco"; exit 1; }
```

Y para filtrar la salida de una herramienta de recon:

```bash
subfinder -d tesla.com -silent | hdb scope filter -p tesla | httpx -silent
```

### Cómo decide

- Una regla **out-of-scope siempre gana** sobre una in-scope.
- `*.example.com` cubre el apex y todos los subdominios; `example.com` a secas
  cubre solo ese host, no sus subdominios.
- Un target con ruta (`https://example.com/api`) exige que la ruta coincida.
- Los CIDR se comparan como red (`10.0.0.0/24` incluye `10.0.0.9`).
- Lo que **no** se puede comparar automáticamente —apps móviles, hardware,
  texto libre tipo *"cualquier host propiedad de la empresa"*— se marca como
  «revisar a mano» y nunca se da por permitido.
- Lo que no coincide con nada sale como `NO-LISTADO`, jamás como permitido.

Esto último importa: la herramienta te dice qué es seguro descartar, no te
autoriza a atacar. **El brief del programa manda siempre**; léelo, sobre todo
las reglas de rate limit, cuentas de prueba y datos de terceros.

## VRT

```bash
hdb vrt search idor
# P1 - Critical   broken_access_control.idor.modify_view_sensitive_information_iterable_object_identifiers
# P2 - Severe     broken_access_control.idor.modify_sensitive_information_iterable_object_identifiers
# P3 - Moderate   broken_access_control.idor.view_sensitive_information_iterable_object_identifiers

hdb vrt show server_side_injection.sql_injection
```

Ver las variantes ordenadas por prioridad te dice qué falta demostrar para
subir de P3 a P1: normalmente, que los datos sean sensibles y que el
identificador sea iterable.

## Recon y assets

```bash
subfinder -d tesla.com -silent | hdb assets add -p tesla --source subfinder
```

Imprime **solo los hosts nuevos** desde la última vez, ya etiquetados por su
estado de scope. Los subdominios nuevos son donde suelen estar los bugs sin
encontrar. Repítelo periódicamente y trabaja el diff.

```bash
hdb assets list -p tesla --in-scope
```

## Hallazgos y reportes

```bash
hdb finding new -p tesla -t "IDOR permite leer pedidos de otros usuarios" \
  --vrt broken_access_control.idor.modify_view_sensitive_information_iterable_object_identifiers \
  --target https://api.tesla.com/orders/1337
```

Valida el target contra el scope antes de registrarlo y hereda la prioridad del
VRT. Luego:

```bash
hdb report 1 -o reporte-1.md    # plantilla con resumen, pasos, PoC, impacto y remediación
hdb finding set 1 --status submitted
hdb finding list --status triaged
```

Estados: `draft`, `submitted`, `triaged`, `accepted`, `duplicate`,
`not_applicable`, `resolved`.

## Programas privados

Los programas privados no están en el dataset público. Pega su scope a mano:

```bash
cat > in.txt <<'EOF'
*.cliente-privado.com
https://api.cliente-privado.com/v2
EOF
hdb program import cliente-privado --name "Cliente Privado" --in-scope in.txt --out-of-scope out.txt
```

A partir de ahí funciona igual que cualquier otro programa.

## Tests

```bash
python3 -m pytest tests -q
```

## Alcance de uso

Esta herramienta consulta scopes publicados y organiza tu trabajo; no escanea,
no explota y no envía tráfico a ningún target. Úsala sobre programas en los que
estés inscrito y dentro de sus reglas.
