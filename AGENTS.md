# nureq — Investigador OSINT 100% libre (CLI)

> Proyecto separado de redteam-lab. OSINT avanzado "desde afuera" contra targets autorizados,
> sin guion: un agente IA (DeepSeek v4) investiga libremente con shell total via netns redteam.
> Base de conocimiento: arsenal de elementalsouls/Claude-OSINT (ya en la KB del lab).

## Lo que es (y lo que NO es)
- **ES**: un investigador autónomo. Arranca con el target y decide SOLO qué hacer:
  DNS/CT/Wayback/Shodan/brechas, HTTP arbitrario, shell libre (nmap, nuclei, ffuf, curl, dig...),
  mineria de JS, deteccion de Docker/K8s/registry, barrido de secretos, validadores read-only.
- **NO ES**: un pipeline fijo con checklist. El recon fijo existe pero solo via `--pipeline-only`.

## Reglas del proyecto
- **Regla de oro VPN**: todo el trafico sale por el netns `redteam`. `--no-vpn` para tests locales.
- **Scope auto-expansivo**: el target + todo host/IP/dominio que aparezca en outputs. `run_shell`/
  `probe_http` solo aceptan red hacia el scope o servicios OSINT publicos (shodan, crt.sh, wayback,
  cavalier, github, slack, openai...). Comandos destructivos bloqueados.
- **Nunca** pegar secretos literales al LLM: todos los outputs pasan por `sanitize_output`
  (solo ultimos 4 chars). Los secretos completos quedan solo en `findings.jsonl` local.
- **Auto-harvest**: cualquier output (curl crudo, probe, wayback) que contenga secretos o
  exposiciones (.env, .git, docker 2375, registry 5000, swagger, kubelet) se registra SOLO
  como finding. El agente ademas puede contextualizar con la tool `hallazgo`.
- Shodan: key compartida con CyberLab (plan dev, 100 creditos/mes). Cache 7d + presupuesto por corrida.

## Uso
```
nureq <dominio|ip|host:puerto> [--perfil rapido|medio|profundo] [--max-steps N]
                               [--no-vpn] [--pipeline-only] [--json]
```
- `--perfil` ajusta presupuesto (pasos/minutos/creditos Shodan), NO el guion.
- `--pipeline-only`: recon fijo (legacy, sin agente).

## Estructura
- `nureq.py` — CLI + orquestador (arranca el agente, guarda reporte, `--resume`)
- `nureq/agent.py` — **EL INVESTIGADOR**: loop agentic con function calling, scope auto-expansivo,
  presupuesto, anti-loop, auto-harvest, validadores read-only, escalamiento a v4-pro, checkpoint
- `nureq/ai.py` — DeepSeek v4-flash (loop) + v4-pro (analista/reporte) via canal directo (Session)
- `nureq/netexec.py` — canales A/B/C, batch_http, DNS batch + cache, streaming anti-cuelgue
- `nureq/_netbatch.py` — worker del batch HTTP (corre dentro del netns o directo)
- `nureq/ledger.py` — ledger ya-consultado por target (TTL 24h crtsh/wayback)
- `nureq/secrets.py` — catalogo 60+ patrones (port de secret_scan.py) + passwords/connection strings
- `nureq/findings.py` — schema de findings (Claude-OSINT §3) + redaccion de secretos
- `nureq/stage1..4.py` — libreria de tools del agente (DNS, CT, email-sec, Shodan, Wayback, Cavalier,
  always-on, swagger, graphql, JS mine, Docker/K8s, vendor) — con batch paralelo
- `nureq/report.py` — consola + `reports/<target>_<ts>/{report.md, findings.jsonl, assets.json, run-log.jsonl, evidence/}`

## Modelos (20/08/2026)
- Loop ejecutor: `deepseek-v4-flash` (function calling cada turno).
- `consultar_analista` + reporte final: `deepseek-v4-pro` (thinking high).
- Nombres legacy `deepseek-chat`/`deepseek-reasoner` deprecados (resuelven a V4-Flash temporal).

## 🚀 V2 — Velocidad + robustez (03/09/2026)
**Tráfico segregado en 3 canales** (regla de oro intacta: el target SIEMPRE por netns redteam):
- Canal A (DeepSeek): DIRECTA por host con `requests.Session` keep-alive (reusa TLS entre pasos). Env: `NUREQ_API_DIRECT=0` vuelve por VPN.
- Canal B (target): por netns (cambia nada).
- Canal C (OSINT público: shodan/crt.sh/wayback/cavalier/rdap): directa si `NUREQ_OSINT_DIRECT` (default ON; `=0` vuelve por VPN).
- **Ganancia medida**: batch 16 workers vs secuencial = **~8.5x** con latencia real (30 req delay-0.5s: 2.8s vs ~24s).

**Batch HTTP**: `netexec.batch_http()` — 1 subprocess `_netbatch.py` (dentro del netns si vpn) con Session + hilos + rate limiter. Refactorizados a batch: always_on, swagger, graphql, docker_probe, vendor_fingerprint, bucket_permutations, wayback_cdx. Fallback automático si falla.
- `prefix_sweep` → `resolve_many()` (1 subprocess, 120 prefijos ~16 min → ~1-2 min). DNS cache 1h (memoria+disco `cache/dns.json`).
- Rate limiter por perfil: rapido 10 / medio 25 / profundo 40 rps (env `NUREQ_RPS`). No quemar la IP Mullvad (lección 24/08).
- `run_cmd_stream()`: streaming con `select` + idle_timeout (sin output en N s → kill + aviso). `_run_shell` lo usa (nunca más cuelgues de nmap/ffuf mudos).
- `check_vpn()` con fallback (ipify → icanhazip → api64.ipify).

**Bugs arreglados**: `_run_shell` ahora usa `bash -c` (pipes/comillas OK, antes `cmd.split(" ")` los rompía) · budget Shodan real en `_shodan_host` (antes `+=0`) · `ffuf_dirs` usa tempfile único (antes `/tmp/nureq_ffuf.json` fijo → race en corridas paralelas) · `vendor_fingerprint` exige fingerprint real (antes marcaba cualquier 200/401/302) · branch muerto heapdump eliminado · dedup de secretos en auto-harvest.

**Checkpoint/resume**: `save_checkpoint()` cada 5 pasos + al cerrar (findings+scope+runs+steps). Ctrl+C guarda y sale limpio. `--resume` recarga (mismo target). `--no-ai` nuevo (solo desactiva el reporte v4-pro).

**Ledger ya-consultado**: `nureq/ledger.py` — `cache/ledger_<target>.json`. crtsh/wayback con TTL 24h; se inyecta al system prompt ("YA CONSULTADO... no repetir").

**Validadores read-only nuevos** (16 tipos): + aws (SigV4 GetCallerIdentity, formato `ACCESS_KEY:SECRET_KEY`), stripe, twilio, digitalocean, azure, telegram, google, mailgun, sendgrid, shodan.

**Loop del agente**: tool_calls del mismo turno en paralelo (4 hilos) · reasoning de cada paso al run-log · timings por tool (`elapsed` en run-log) · métricas de corrida al reporte final (pasos/tools/tiempo/shodan) · triage v4-flash conectado en wayback (>25 URLs → top 12).

**Verificado 03/09**: selftest OK · batch directo/VPN OK (salida Mullvad confirmada) · DNS batch A/TXT OK · streaming idle_timeout OK · **test local end-to-end con IA real OK** (todos los PASS: .env, .git, swagger, docker, secretos — con `--max-steps 22` en el test, el modelo divaga más que antes) · checkpoint/resume OK · benchmark 8.5x.

## 🧲 ASPIRADORA DE ENTIDADES (03/09/2026)
**Concepto**: el OSINT es de la página entera; de TODO output el agente "aspira" emails/nombres/empresas automáticamente y lo entrega como entregable del reporte.
- `nureq/entities.py` — extractor local (sin red): regex de emails (filtra example.com/no-reply/test/@2x), nombres (contextos `"name":`/`nombre:`/`sr.` etc. + **inferidos de la parte local del email**: `juan.perez@` → "Juan Perez"), empresas (`"company"`/`empresa:`). `EntityStore` con dedup + fuentes + contador. `build_schema()` → aristas persona↔mail↔empresa (inferidas + co-ocurrencia por fuente) → `schema_mermaid()` + `schema_ascii()`.
- **Hook**: `_auto_harvest` aspira todo output del agente (curl/probe/JS/wayback) + al cierre peina los raw de todos los findings. Sin pedido del agente.
- **Entrega**: `entities.json` + `entities.csv` en el reporte + sección "Entidades aspiradas" en report.md + esquema en PDF. Checkpoint guarda/restaura el EntityStore.
- **Tools nuevas (canal DIRECTO, sin VPN — regla del dueño)**: `buscar_persona(nombre)` (dorks DDG HTML + Bing: `"Nombre" site:linkedin.com/in`), `buscar_email(email)` (hunter.io + emailrep.io + dorks), `buscar_empresa(empresa)` (dorks + RDAP + cavalier). En `nureq/enrich.py`.
- **hunter.io multi-key round-robin (2 keys cargadas)**: `HUNTER_API_KEY_1..N` en .env. `hunter_verify()` rota entre keys y si una falla (error/rate limit/agotada) prueba con la siguiente automáticamente. Plan free ~50 verifs/mes c/u → ~100/mes. El agente las usa a criterio (system prompt: enriquecer entidades relevantes).
- Verificado 03/09: selftest entidades PASS (10 checks) · hunter con 2 keys OK (verificación real responde) · aspiradora+esquema integrados OK (2 emails, 2 nombres inferidos, 4 aristas con fuente) · test local end-to-end OK (el server trucho no tiene emails → 0 aspirados, correcto).

## 📡 CT MULTI-FUENTE (03/09/2026) — "la página de crt.sh es una mierda"
**Diagnóstico**: `crtsh()` consultaba SOLO crt.sh (lento/inestable, 3-30s+). Alternativas probadas en vivo: **subfinder v2.14.0 YA instalado** en el host (estándar ProjectDiscovery, ~30 fuentes pasivas: crt.sh, CertSpotter, HackerTarget, RapidDNS, Anubis, DNSDumpster...) + **CertSpotter API** (gratis, estable, `api.certspotter.com/v1/issuances?...&expand=dns_names`) + **HackerTarget** (gratis, texto plano `host,ip`).
- **`ct_subdomains(domain)`** (stage1_seed.py): multi-fuente con merge+dedup:
  1. **subfinder** `-silent -ip` (primaria, 2-10s, `-all` en profundo) — por netns
  2. **crt.sh** JSON con retry (histórico profundo, en paralelo con subfinder)
  3. **CertSpotter + HackerTarget** (fallback si las anteriores dan 0, canal directo)
  - Registra findings SUBDOMAIN + **IP_ASSOCIATED** (host->IP) y devuelve (subs, ips) para el scope del pre-recon.
- `crtsh()` = wrapper compat → mismo resultado. La tool del agente usa `ct_subdomains` (con `-all` en profundo) y agrega las IPs al scope.
- **Resultado en vivo (culturainteractiva.com)**: 13 subdominios en segundos (ads/comentarios/encuestas/facturacion/mail nuevos vs los 12 del 20/08).
- Verificado: selftest OK · CT multi-fuente OK (13 subs) · test local OK.

## ⚡ V3 — Pre-recon + perfiles turbo (03/09/2026) — "2 horas no va"
**Paradigma**: el 80% del OSINT de un target es determinista y en batch → corre ANTES del agente.
- **`nureq/prerecon.py`**: corre SIEMPRE antes del agente (batch/paralelo): DNS catalog + CT + email-security + RDAP + prefix_sweep (medio/profundo) + Shodan (internetdb+host, cache) + Cavalier + Wayback (medio/profundo) + probe web + always_on + swagger + graphql + saml/oidc + js_mine + vendor + headers + docker_probe + **ffuf + nuclei en paralelo**. Registra findings + devuelve resumen condensado inyectado al agente como primer mensaje ("ya sabés esto, NO lo repitas").
- **Fuzzers por perfil** (el usuario: "¿por qué rápido/medio no tienen ffuf?" → ahora SÍ los 3):
  - rapido: ffuf common 4.7k (60s) · nuclei `-tags exposure,config` (~1 min)
  - medio: ffuf common (90s) · nuclei `-tags exposure,config,misconfig`
  - profundo: ffuf 24k (90s) · nuclei severidad high,critical completo
- **Perfiles nuevos**: pasos 12/20/30 · minutos 15/25/45 · shodan 4/8/12. Todos en paralelo con rate limit.
- **Loop exprimido**: max_tokens 1600→700 · temperature 0.6→0.3 · compactación 55→30 mensajes · **streaming de DeepSeek** (`deepseek_raw_stream`, canal directo) con **timeout de primer token 30s** (pasos colgados se cortan y reintentan).
- **Tiempos estimados**: rapido 3-5 min · medio 6-9 min · profundo 8-12 min.
- Fix latente: `vendor_fingerprint` usaba regex strings (no compilados) — nunca explotó porque nadie lo llamaba; el pre-recon lo expuso → `re.compile` dinámico.
- Verificado 03/09: selftest OK (checks de perfiles/wordlists/tags) · streaming OK (content+reasoning) · test local end-to-end OK con pre-recon (17 hallazgos base + agente profundizando).

## 🦾 MODO AUTÓNOMO TOTAL (03/09/2026) — "hace todo sin pedir permiso"
**Doctrina**: el dueño manda, el agente hace. Nada de pedir permiso ni frenos de scope.
- **Scope auto-expansivo total**: cualquier host/IP/dominio que el agente quiera tocar se auto-agrega al scope y EJECUTA. Se registra como finding `ASSET_NUEVO` (cadena de custodia: qué host y cuándo). Cero rechazos "[RECHAZADO] fuera de scope" (eliminados de `_run_shell`/`_probe_http`).
- **Herramientas de auditoría LIBRES**: sacados de BLOCK_PATTERNS `hydra`, `nikto`, `sqlmap --drop` (eran bloqueos de redteam-lab, no aplican acá). Queda SOLO el kill-switch del host del lab: `rm -rf /`, `mkfs`, `dd` a disco, `reboot/shutdown/poweroff/halt`, `iptables -FXZ`, `docker rm -f`, `chmod -R 777 /`, `mv /etc`, fork-bomb, `whoami=`.
- **Anti-loop**: umbral 4 → **8**, configurable `NUREQ_ANTILOOP`.
- **Gate de cierre por falta de progreso**: DESACTIVADO por defecto (el agente cierra solo por `concluir()` o presupuesto). Reactivable con `NUREQ_FORCE_CLOSE=1`.
- **Presupuesto**: rapido 12 / medio 20 / profundo 30 pasos · 15/25/45 minutos (techo duro).
- **Flags en .env**: `NUREQ_AUTONOMO=1` (default ON; `=0` vuelve a guardrails de scope) · `NUREQ_ALLOW_METADATA=1` para permitir 169.254.169.254 (metadata AWS — default bloqueado, es SSRF interno no OSINT) · `NUREQ_ANTILOOP` · `NUREQ_FORCE_CLOSE`.
- System prompt actualizado: doctrina autónoma explícita ("no existe fuera de scope", "único límite real: no romper el host del lab").
- Verificado 03/09: selftest con 10 checks de modo autónomo (PASS) · auto-expand en acción (host fuera de scope → ASSET_NUEVO + ejecución, hydra liberado, rm -rf / sigue bloqueado) · test local end-to-end OK (el agente expandió 127.0.0.53 solo).

## 🧹 ANTI-SCOPE-SOUP + CHECKPOINT POR PERFIL (03/09/2026, noche) — "busca cosas sin sentido"
**Diagnóstico en vivo (beygoo.io profundo)**: el scope se contaminaba con tokens de JS minificado
(`a.join`, `a.length`, `$h`, `b.qa`, `agentx-lg-en.webp`) y se registraban ASSET_NUEVO falsos
(incluso `$h` literal y `api.hackertarget.com`, que es servicio OSINT público).
- **`Scope.add()` reescrito** (agent.py): normalización (`$` → rechazo, esquema/puerto fuera) +
  `_plausible_host()`: IP o TLD en `VALID_TLDS` (~140 IANA comunes) y no en `BAD_TLDS`
  (extensiones de archivo webp/svg/png/ts/cust... + tokens JS join/length/push/src/width...),
  o subdominio de algo ya en scope (TLD raro pero target legítimo). Tokens `b.qa`/`a.pu`
  (SLD 1 char + 2 labels) rechazados aunque el TLD exista. El target inicial SIEMPRE entra.
- **`_register_new_assets`**: solo registra ASSET_NUEVO si `Scope.add()` aceptó (antes registraba
  aunque el host fuera basura) y saltea `OSINT_ALLOW` (api.hackertarget.com, crt.sh... ya no son assets).
- **OSINT_ALLOW ampliado**: + api.hackertarget.com, api.certspotter.com, api.hunter.io, emailrep.io,
  html.duckduckgo.com, duckduckgo.com, www.bing.com (fuentes de tools CT-fallback/enrich).
- **Checkpoint por perfil**: `checkpoint_<target>_<perfil>.json` — corridas rápido/medio/profundo
  ya NO se pisan entre sí (antes `checkpoint_<target>.json` y la corrida nueva pisaba la anterior).
  `--resume` usa target+perfil. Los checkpoints viejos se renombraron a `_profundo`/`_medio`.
  Bonus: al cargar un checkpoint viejo con basura, el nuevo `add()` la filtra sola.
- Selftest +4 checks (rechaza tokens JS/webp/$h, acepta TLD válido, subdominio TLD raro,
  ASSET_NUEVO solo plausible) → **SELFTEST OK**.
- **Verificado en vivo 03/09 (beygoo.io rápido, 12 pasos)**: scope de 41 hosts 100% limpio
  (cero basura), único ASSET_NUEVO = `1.1.1.1` (DNS de Cloudflare usado en dig, real), reporte
  con PDF en `reports/beygoo.io_20260903_183932Z/`.

## 🔍 DORKS FIX + AUTO-ENRICH AL CIERRE (03/09/2026, noche) — "la idea es que haga todos los pasos"
**Diagnóstico en vivo**: el agente NUNCA llamaba las tools `buscar_persona/buscar_email/buscar_empresa`
(0 usos en rápido y profundo) — las entidades aspiradas morían sin enriquecer. Además los dorks
estaban rotos: DDG html/lite → 202 (anti-bot IP datacenter), Bing ignoraba comillas y devolvía
redirects `/ck/a` sin decodificar, Startpage/Brave/SearXNG → challenge.
- **`enrich.py` fixes**: `_bing_unredirect()` decodifica los redirects de Bing (param `u` base64
  url-safe, tolerando el prefijo ofuscado `a1a...` — busca el offset de `aHR0cHM` = "https:").
  Regex `<h2[^>]*><a[^>]+href=...` (el formato de Bing cambió). `_relevant()` filtra por
  relevancia (término en URL/título) porque Bing ignora comillas desde IPs de datacenter.
  `search_person` sin comillas + términos + linkedin. Limitación actual: todos los buscadores
  web bloquean/degradan desde la IP Mullvad (Bing devuelve basura genérica) → los dorks quedan
  como fallback; lo que SÍ responde: hunter.io + emailrep.io (canal directo).
- **AUTO-ENRICH al cierre** (`agent.py _auto_enrich_entities`): después del loop del agente,
  las entidades aspiradas se enriquecen SOLAS (sin depender del modelo): hasta 3 emails
  (hunter verify round-robin 3 keys + emailrep), 2 personas (dorks), 2 empresas (dorks).
  Registra findings `enrich/EMAIL_ENRICH` (deliverable/score/smtp), `EMAIL_BREACH` (emailrep,
  medium), `PERSONA_ENRICH`/`EMPRESA_ENRICH` (solo si hay linkedin). + finding resumen
  `Auto-enrich: N entidades`. Hunter result acepta `valid/deliverable/risky/accepted`.
- Selftest +5 checks (unredirect directo, unredirect prefijo ofuscado, URL directa, relevancia
  filtra, relevancia descarta genérico) → **SELFTEST OK**.
- **Verificado en vivo 03/09**: auto-enrich sobre checkpoint rápido de beygoo → `privacy@beygoo.io`
  verificado (deliverable, score 89, smtp OK, 1 crédito hunter) + finding resumen. Reporte
  regenerado (8854 chars, incluye el email). Los próximos pasos (emails → hunter verify) corren
  solos al cierre de cada corrida.

## 🐛 FIX REPORTE TRUNCADO + PDF VPN (04/09/2026) — "el v4-pro corta el reporte a mitad"
**Bug visto en vivo (beygoo.io rápido)**: `final_report` (ai.py) con `thinking=True` +
`reasoning_effort="high"` devolvió el reporte **cortado a 3 líneas** (el thinking se comió el
presupuesto). El fallback solo reintentaba si `content` venía **vacío** — output parcial nunca
se reintentaba. Report.md original quedó en 611 bytes.
- **Fix `ai.py`**: nuevo helper `_report_completo(content)` — True solo si el reporte tiene
  ≥600 chars Y las secciones clave (resumen/hallazgos/superficie). Si viene vacío, cortado o sin
  secciones → reintenta sin thinking (verificado: 7158-8854 chars completos).
- **Fix report.md/PDF**: el script de regeneración previo cortó el encabezado del report.md y
  generó el PDF con `vpn=False` → decía "VPN: OFF". Reconstruido `report.md` completo
  (encabezado VPN: ON + entidades + reporte IA) y PDF regenerado con `vpn=True` → dice
  "VPN: ON (netns redteam)" (verificado con strings del PDF).
- Selftest +4 checks de `_report_completo` → **SELFTEST OK**.

## 🔚 CIERRE A TIEMPO (04/09/2026) — "el agente divaga y cierra sin resumen"
**Problema visto en vivo**: las corridas cerraban con "(el agente cerro sin resumen explicito)"
— el modelo gastaba los últimos pasos abriendo frentes nuevos (emails en páginas inexistentes)
en vez de llamar `concluir()`.
- **System prompt** (`agent.py`): regla "CIERRE A TIEMPO" — con 3 pasos o menos de presupuesto,
  NO abrir frentes nuevos: cerrar con `concluir(resumen)`. No repetir tools que dieron vacío.
- **Gate de progreso ACTIVADO**: `NUREQ_FORCE_CLOSE=1` en .env (aviso a los 8 pasos sin hallazgos
  nuevos, cierre forzado a los 12). Antes estaba OFF por diseño del modo autónomo.
- Selftest OK (49 PASS). Server de descarga (puerto 9999) apagado al cerrar.

## 🌐 NUREQ-API V3 (04/09/2026) — UNA sola consulta, perfil único profundo, SIN VPN
**`nureq/nureq_api.py`** — Flask, API REST de OSINT "por página": `POST /consulta` con una URL
lanza la investigación COMPLETA (pre-recon + agente + aspiradora de emails/personas/empresas +
auto-enrich + reporte) y devuelve todo adentro. Cero endpoints granulares (dns/ct/email/persona/
empresa fueron ELIMINADOS — la investigación ya trae esas ramas solas).
- **SIN VPN (regla del dueño, 04/09)**: la API corre cada consulta con `nureq.py --no-vpn`.
  El tráfico sale DIRECTO desde la IP de la VPS. El netns redteam es solo de los proyectos del lab,
  NO de nureq-api. El reporte/PDF del cliente NO menciona VPN en ningún lado (saco el header,
  la fila de la tabla y el footer de report.py).
- **Perfil ÚNICO = profundo**: si el cliente manda `rapido`/`medio` (o nada), se coer a profundo
  con `aviso` en la respuesta. El CLI de nureq conserva sus 3 perfiles.
- **Servicio**: `nureq-api.service` (systemd, `Restart=always`) → `0.0.0.0:9998`
  (puerto configurable `NUREQ_API_PORT`, IP VPS 103.199.186.207).
  ⏸ **API BAJADA (01/10/2026)**: stop+disabled a pedido del operador (puerto 9998 libre,
  sin procesos). Se retoma el deploy cuando el repo esté pulido; el CLI sigue funcionando igual.
- **Auth**: SOLO `Authorization: Bearer <NUREQ_API_TOKEN>` (se sacó `?key=` — quedaba en logs).
  Token autogenerado en .env, 401 sin token. Rate limit `NUREQ_API_RATE` (default 20/min).
- **Endpoints**:
  - `GET /health` (sin auth)
  - `POST /consulta` `{"target":"https://x.com/path|dominio|ip|host:puerto","no_ai":bool,"fresca":bool}`
    → 202 `{job_id}` en background, siempre perfil profundo y sin VPN.
    `"fresca": true` saltea el cache (corrida nueva a propósito). `?sincrono=1`:
    espera y devuelve resultado completo en la misma llamada.
    Normaliza URLs crudas (quita esquema/path).
  - `GET /corridas` (últimas 20, con `tiempo_s` — cronómetro) · `GET /corridas/<id>` → estado +
    **resultado completo** (resumen por severidad + findings + entidades + `tiempo_s` +
    resumen del investigador + links report/pdf)
  - `GET /corridas/<id>/report` (markdown) · `GET /corridas/<id>/pdf` (binario)
  - `POST /corridas/<id>/link` (Bearer) → **links de descarga temporales** sin Bearer
    (`?tk=<hmac>` expira en `NUREQ_API_DL_TTL`, default 3600s, `?ttl=N` máx 12h) — para
    abrir el PDF/report desde el navegador.
- **Guardrails**: semáforo `NUREQ_API_MAXJOBS` (default 2, 429 al 3ro) · dedup (mismo target
  corriendo → mismo job_id) · **cache TTL `NUREQ_API_CACHE_TTL` (default 24h)**: reporte
  profundo fresco → respuesta instantánea con `estado:"cached"` · timeout por perfil
  (minutes*60+1200). Favicon → 404 (no 401).
- **Jobs persistidos** en `cache/api_jobs/<id>.json`: sobreviven restart (los `running` pasan
  a `interrumpido` al boot).
- Fix: `import sys` movido arriba (antes solo en `__main__`, frágil bajo gunicorn).
- Verificado 04/09: selftest OK (53 PASS, +3 hunter domain search) · coerce a profundo OK ·
  subprocess con `--no-vpn` confirmado · auth 401/200 · cache-hit · 429 · report/pdf/link OK.
- Reinicio tras editar: `systemctl restart nureq-api`.
- ⚠ **V4 (01/10/2026) reemplaza**: BYOK persistente + SIN PDF + IA obligatoria (ver sección abajo).

## 🔑 NUREQ-API V4 (01/10/2026) — BYOK + sin PDF + IA obligatoria
**Pulido del repo (decisión del operador)**: la API ya no usa la key del dueño ni genera PDFs.
- **BYOK persistente**: `PUT /api-key` (Bearer) guarda la key de DeepSeek DEL CLIENTE
  (`sk-...`) en `cache/client_deepseek_key.json` (chmod 600, nunca al repo ni a logs),
  **validada antes** contra `GET /models` (401 → 400 con mensaje). `GET /api-key` estado
  enmascarado (`...abcd`), `DELETE /api-key` borra. Override de validación para tests:
  `NUREQ_API_VALIDATE_URL`.
- **IA obligatoria**: `/consulta` sin key guardada → **400** ("cargala con PUT /api-key");
  no existe modo data-only por API. `no_ai` eliminado del contrato.
- **La key del `.env` NUNCA se usa en la API**: el subprocess recibe `env` explícito con
  `DEEPSEEK_API_KEY` = key del cliente (nunca en argv/ps); el `setdefault` de `config`
  no la pisa. Verificado en `/proc/*/environ`.
- **SIN PDF en ningún lado**: `report.py` sin `make_pdf`/wkhtmltopdf (función eliminada),
  `nureq.py` sin aviso de PDF, API sin `reporte_pdf`, `/corridas/<id>/pdf` → 404 JSON,
  `/link` solo report. Entregable = **data**: JSON (findings + entidades + resumen) +
  `report.md`; el PDF final lo arma el cliente por su lado.
- **Sin permisos**: agente autónomo total (NUREQ_AUTONOMO); la API no agrega gates.
- **Tests 01/10 (11 PASS)**: `/tmp/opencode/test_nureq_api.py` (health, api-key estado/guardado/
  borrado, sin key → 400, formato inválido → 400, validador simulado, key del cliente en el
  subprocess, key fuera de argv, /pdf 404, resultado sin pdf). Selftest offline OK.
- La API sigue **BAJADA** (stop+disabled); deploy cuando el operador retome.

## 👥 EMPLEADOS / DUEÑOS (04/09/2026) — Hunter Domain Search + LinkedIn vía r.jina.ai
**Diagnóstico**: las dorks de buscadores no traían empleados (bloqueados desde datacenter) y el
agente nunca tocaba LinkedIn. Ahora:
- **`enrich.hunter_domain_search(domain)`** — Hunter Domain Search API (emails + first/last/
  position de empleados), multi-key round-robin como `hunter_verify`. Plan free: ~25
  searches/mes por key, **máx 10 emails por resultado** (limit=10; `limit=100` da error de
  paginación — visto en vivo 04/09). Verificado en vivo: beygoo.io → 6 empleados con cargo.
- **`enrich.linkedin_company(slug)`** — datos públicos de la página de LinkedIn company:
  **fetch DIRECTO** (responde 200 sin login, 334KB; r.jina.ai dio 403 Cloudflare en vivo →
  quedó como fallback). Extrae JSON-LD + texto visible (la aspiradora peina nombres/cargos).
  Verificado en vivo: BeyGoo — Security & Investigations, Madrid, 7.380 followers, 25 empleados.
- `r.jina.ai` + `www.linkedin.com` agregados a `OSINT_ALLOW`.
- Tools del agente: **`buscar_emails_dominio(dominio)`** y **`linkedin_empresa(slug)`**.
  System prompt: "para empleados/dueños usá buscar_emails_dominio primero (Hunter)".
- Reglas nuevas en el prompt del agente: `docker_probe` contra TODAS las IPs resueltas (si CDN
  no responde → info y seguís) · si `js_mine` expone endpoints, bajarlos con `probe_http` y
  correr `scan_secrets` sobre el body (sessions/passwords/tokens en JSON ≥ HIGH).
- `ai.py` (v4-pro): **categorías sin hallazgos en el digest se OMITEN** — nunca más
  "no aplica"/"no hay" en el reporte.
- El reporte/PDF ya no menciona VPN (report.py: header + tabla + footer limpios).

## Keys en .env
- `DEEPSEEK_API_KEY` y `SHODAN_API_KEY` copiadas de `redteam-lab/cyberlab/.env` (20/08/2026). NUNCA commitear.
- `HUNTER_API_KEY_1` y `HUNTER_API_KEY_2` (02/09/2026, cuentas del dueño, plan free ~50 verifs/mes c/u). NUNCA commitear.
- Nuevas opcionales: `NUREQ_API_DIRECT=1` (default), `NUREQ_OSINT_DIRECT=1` (default), `NUREQ_RPS`.

## Verificacion
- `nureq --selftest` — tests offline (regex, scoring, scope, sanitize).
- Test local con IA real: `python3 /tmp/opencode/test_nureq_local.py` levanta servers truchos
  (web 18080 con .env/config.json/swagger/.git + docker fake 2375) y nureq debe detectar todo
  decidiendo solo. Verificado 20/08: 10 hallazgos (Docker CRIT, .env CRIT, passwords HIGH, swagger HIGH)
  en ~2.5 min con 14 pasos.

## Estado
- ✅ Agente libre operativo (test local OK end-to-end con IA real).
- ✅ Selftest OK · curl v4-flash/v4-pro via netns OK · cache Shodan 7d · anti-loop · compactacion de historial.
- ✅ **Corrida en vivo 20/08 — culturainteractiva.com** (perfil profundo, VPN): 17 hallazgos
  (12 subdominios CT incl. payments/dashboard/fiscalizacion/simulador/tools; 3 MEDIUM JS en
  tools.culturainteractiva.com/login; hosting Cloudways/DigitalOcean 104.248.60.46). Reporte en
  `reports/culturainteractiva.com_20260820_160747Z/`.
- ✅ **Profundizacion 20/08 — subdominios jugosos** (3 en paralelo, perfil profundo):
  - `tools.culturainteractiva.com` (2 MEDIUM: 6 endpoints API/JS + 3 hosts internos en JS; SPA React/Vite)
  - `payments.culturainteractiva.com` (8 hallazgos: puertos 8080/8443 abiertos segun Shodan en la IP de
    origen 104.248.60.46 — NO accesibles desde aca (firewall Cloudways bloquea origen, 80/443 dan 403;
    8080/8443 timeout); subdominio raro `25.culturainteractiva.com`; endpoints de auth probados)
  - `fiscalizacion.culturainteractiva.com` (2 MEDIUM: host interno + 2 endpoints en JS)
  - Todos con PDF: `reports/<sub>*.pdf`. Sin secretos ni vuln critica confirmada.
  - Nota: dashboard/simulador/laplata NO resuelven (descomisionados).
- ✅ **Fixes del 20/08 (por bugs vistos en vivo)**:
  - `check_vpn()` desempaquetaba mal el return de `_curl` (3 valores) → VPN reportada caida.
  - Loop agentic: un assistant con `tool_calls` + `concluir` en el mismo turno dejaba tool_calls
    sin respuesta → API 400 "insufficient tool messages". Fix: responder a TODAS las tool_calls
    siempre + fallback de reconstruccion de historial a texto plano ante 400 de tools.
  - `final_report` (v4-pro thinking) podia gastar el presupuesto razonando sin escribir →
    reintenta sin thinking (max_tokens 6000).
  - JS mining: filtrado de TLD `.test` (falsos positivos) y endpoints solo del host del target
    (antes tomaba CDN/github/vimeo como endpoints).
- ✅ **PDF en el reporte**: `report.py make_pdf()` — wkhtmltopdf (patron CyberLab): portada NUREQ +
  tabla de hallazgos por severidad + reporte IA + cadena de custodia. Se genera solo en cada corrida.
- Pendiente: profundizar en subdominios jugosos (payments/dashboard/tools) de culturainteractiva.