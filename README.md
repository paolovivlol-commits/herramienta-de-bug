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

## BOB — el copiloto

BOB es el asistente. **No ataca nada**: revisa la superficie in-scope de solo
lectura, te avisa de los puntos que valen la pena probar a mano (ordenados por
impacto potencial), y cuando le dices "lo encontré" te arma el reporte. El
testing lo haces tú.

### 1. BOB revisa y te avisa

```bash
hdb bob review https://app.tesla.com -p tesla
```

BOB combina el mapa de superficie y el escaneo pasivo, y te devuelve:

- **Config visible** (cabeceras, cookies, CORS) que ya se ve sin explotar nada.
- **Puntos críticos a probar**, ordenados por impacto: un endpoint con `id` →
  IDOR; un `/login` → auth; un `?url=` → SSRF; un `?next=` → open redirect; los
  ficheros JS → secretos. Cada uno enlaza a su playbook y al comando exacto para
  reportarlo si lo confirmas.

BOB se niega a revisar nada que no esté confirmado in-scope.

### 2. Tú lo pruebas

Abre el playbook del punto que BOB señaló y síguelo a mano:

```bash
hdb playbook show idor
```

### 3. "BOB, lo encontré" → reporte

```bash
hdb bob found idor -p tesla \
  --target https://app.tesla.com/api/orders/123 \
  --title "IDOR permite leer pedidos de otros usuarios"
# 🤖 BOB: hecho. Hallazgo #1 registrado en tesla.
#   reporte inicial: reporte-1.md
```

BOB hereda el VRT y la prioridad del playbook, valida que el target esté en
scope, y genera el reporte. Rellenas los pasos y el impacto, y lo envías con
`hdb submit`.

### Buscar y señalar todo de un tiro: `bob hunt`

El arranque de sesión. BOB busca por **toda** la superficie in-scope y te señala
lo que vale la pena, en un solo comando:

```bash
hdb bob hunt https://app.tesla.com -p tesla
```

Encadena todo lo anterior:
1. **Mapea** la superficie (home, robots, sitemap, endpoints, params, JS).
2. **Escanea** la configuración visible (cabeceras, cookies, CORS).
3. **Lee los ficheros JS** en busca de secretos y endpoints internos.
4. **Prioriza** todo por impacto potencial y **siembra tu cuaderno**.

Un secreto de alto riesgo (clave AWS, `sk_live_` de Stripe) sube a lo más alto
de la lista; una clave pública (Google, Stripe *publishable*) baja. Sigue siendo
todo **de solo lectura y solo in-scope** — BOB señala, tú confirmas.

### "¿Esto es importante?" — `bob triage`

BOB **no ha visto tu target**, así que no puede jurarte que un hallazgo sea real
con solo mirarlo. Lo que sí hace: te tasa el hallazgo con preguntas de sí/no
sobre lo que TÚ observaste, y mapea tus respuestas a la taxonomía de Bugcrowd.

```bash
hdb bob triage idor
# 🤖 BOB: ¿Accediste a datos de OTRA cuenta (no la tuya)? [s/n] s
# 🤖 BOB: ¿Esos datos son sensibles (PII, financieros)?   [s/n] s
# 🤖 BOB: ¿Puedes MODIFICARLOS (no solo verlos)?           [s/n] s
# 🤖 BOB: ¿El identificador es predecible/iterable?        [s/n] s
#
# 🤖 BOB: SI, importante
#   Prioridad estimada: P1 - Critical
#   VRT: broken_access_control.idor.modify_view_sensitive_information_iterable_object_identifiers
```

Cambia una respuesta y el veredicto cambia: si el id es un UUID no adivinable
baja a P4; si no probaste acceso cross-cuenta, BOB te dice que aún no está
demostrado; si la "clave" que hallaste es pública por diseño, te dice que
probablemente no es elegible. También puedes responder sin interactivo:

```bash
hdb bob triage idor -a crossuser=y -a sensitive=y -a modify=y -a iterable=n
```

Clases con tasación: `idor`, `auth`, `cors`, `redirect`, `secrets`, `ssrf`.

**El veredicto vale lo que valgan tus respuestas.** BOB siempre te recuerda:
busca duplicados, relee las reglas del programa, y que esto se basa en lo que TÚ
le dijiste — no en haber visto el target. La decisión final es tuya.

### El cuaderno de caza

Mientras pruebas, BOB te lleva la cuenta de qué falta y qué confirmaste.
`hdb bob review` ya siembra el cuaderno con los puntos que detecta.

```bash
hdb bob note "revisar IDOR en /api/orders" -p tesla --target https://app.tesla.com/api/orders/1 --playbook idor
hdb bob todo -p tesla        # que tienes abierto, en curso y confirmado
hdb bob mark 1 testing       # lo estas probando
hdb bob mark 1 confirmed     # ¡bug! BOB te da el comando para reportarlo
```

Estados: `todo` (pendiente), `testing` (probándolo), `confirmed` (bug),
`clear` (probado, nada), `skip` (descartado). El cuaderno ordena lo abierto
primero para que no pierdas el hilo entre sesiones.

### Análisis de ficheros JS (solo lectura)

Los `.js` que `bob review` detecta suelen filtrar claves y endpoints internos.
BOB los descarga y busca patrones — **sin ejecutarlos ni probar las claves**:

```bash
hdb bob js https://app.tesla.com/main.js -p tesla --endpoints
```

Detecta claves de AWS/Google/Slack/GitHub/Stripe, JWT, claves privadas y
asignaciones tipo `api_key=...`, más endpoints internos (`/api/`, `/admin/`).
Solo escanea ficheros in-scope y enmascara los valores en pantalla.

**Un match es una PISTA, no un bug.** Muchas claves públicas (Google Maps,
Stripe *publishable*) son inofensivas por diseño: verifica alcance y validez a
mano antes de reportar. BOB te lo recuerda en cada corrida.

### Consultarle sobre la marcha

Mientras cazas, pregúntale a BOB qué probar en cualquier cosa que veas:

```bash
hdb assist "https://api.tesla.com/v1/orders/123?user_id=5"
hdb assist "formulario de forgot password que manda un magic link"
```

Responde con los playbooks más relevantes y su checklist. Sin red, al instante.

## Verificar una página (scan)

Verificación **de solo lectura** de un host in-scope. Hace peticiones GET/HEAD
como las de un navegador y observa la configuración; **no inyecta payloads, no
fuerza nada, no envía tráfico destructivo** — justo lo que casi todos los
programas de Bugcrowd permiten (el escaneo agresivo y la inyección suelen estar
prohibidos en las reglas).

```bash
hdb scan app.tesla.com api.tesla.com -p tesla --delay 1 --save
```

Guardarraíles que **no se pueden desactivar**:

- Solo escanea hosts que el motor de scope confirme **in-scope**. Lo que esté
  fuera de scope o no listado se **salta automáticamente** y te lo dice.
- Solo métodos de lectura (GET/HEAD), forzado en el código.
- Rate limit obligatorio entre peticiones (`--delay`, 1s por defecto).

Qué comprueba, y a qué VRT mapea cada hallazgo:

| Check | VRT | Prioridad típica |
|-------|-----|------------------|
| Cabeceras de seguridad ausentes (HSTS, CSP, X-Frame-Options, X-Content-Type-Options) | `server_security_misconfiguration.lack_of_security_headers.*` | P5 |
| Clickjacking (sin protección de frame) | `server_security_misconfiguration.clickjacking.*` | P4–P5 |
| Cookies sin Secure/HttpOnly | `server_security_misconfiguration.missing_secure_or_httponly_cookie_flag.*` | P4–P5 |
| CORS que refleja un Origin arbitrario | `server_security_misconfiguration.unsafe_cross_origin_resource_sharing` | P3–P4 |
| Contenido mixto (HTTP en página HTTPS) | `sensitive_data_exposure.mixed_content` | P5 |
| Divulgación de versión de servidor | `server_security_misconfiguration.fingerprinting_banner_disclosure.software_version_in_response_headers` | P5 |
| HTTP sin redirigir a HTTPS | `insecure_data_transport.cleartext_transmission_of_sensitive_data` | varies |

Con `--save`, cada hallazgo entra como `finding` para su seguimiento. **Son un
punto de partida, no un envío en un clic**: revisa cada uno a mano, descarta lo
que el programa marque como no elegible (muchos consideran los P5 de cabeceras
fuera de recompensa) y sube de prioridad lo que de verdad tenga impacto.

## Enviar a la empresa

En Bugcrowd el reporte se envía **por la plataforma**, que es el canal válido y
con protección legal (safe harbor). La herramienta prepara el paquete y te
muestra el canal; **el clic de enviar lo das tú**:

```bash
hdb submit 5 --check-securitytxt
# Paquete de envio preparado (no se ha enviado nada).
#   reporte:  reporte-5.md
# Canal oficial de envio:
#   Bugcrowd: https://bugcrowd.com/engagements/tesla
```

No manda correos automáticos: enviar reportes no solicitados por email a una
empresa es la forma más rápida de que te cierren la cuenta o algo peor.

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
