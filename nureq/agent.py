"""EL INVESTIGADOR — loop agentic 100% libre (sin guion).

deepseek-v4-flash ejecuta y decide (function calling en cada turno);
deepseek-v4-pro es el analista senior que el agente consulta cuando quiere
pensar profundo (tool consultar_analista) y escribe el reporte final.

Guardrails de seguridad (no de guion):
- Scope auto-expansivo: el target + todo host/IP/dominio que aparezca en outputs.
  run_shell/probe_http solo aceptan red hacia el scope o servicios OSINT publicos.
- VPN ON por defecto (todo sale por netns redteam).
- Secretos REDACTADOS al modelo (ultimos 4 chars); completos solo en findings.jsonl.
- Anti-loop: misma tool+mismo target >=4 veces -> bloqueada temporal.
- Presupuesto: max_steps, timeout global, tope de creditos Shodan.
"""
import json
import re
import shlex
import time

from . import netexec
from . import secrets as secretlib
from . import stage1_seed, stage2_expand, stage3_enrich, stage4_expose
from .ai import deepseek_raw, deepseek_call, deepseek_raw_stream
from .ai import triage_candidates as ailib_triage
from .config import MODEL_FLASH, MODEL_PRO
from .findings import secret_safe
from .ledger import Ledger
from .entities import EntityStore, extract_entities
from . import enrich

# --- Scope auto-expansivo ---
RE_IP = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
RE_HOST = re.compile(r"\b([a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b")
RE_URL_HOST = re.compile(r"https?://([^/\s:]+)")

# Servicios OSINT publicos permitidos para red (no son targets, son fuentes)
OSINT_ALLOW = [
    "api.shodan.io", "internetdb.shodan.io", "cavalier.hudsonrock.com", "crt.sh",
    "web.archive.org", "rdap.org", "www.iana.org", "api.deepseek.com",
    "api.github.com", "slack.com", "api.openai.com", "api.anthropic.com",
    "registry.npmjs.org", "api.getpostman.com", "gitlab.com", "api.twilio.com",
    "login.microsoftonline.com", "autodiscover-s.outlook.com", "hub.docker.com",
    "quay.io", "api.github.com", "gallery.ecr.aws", "teams.microsoft.com",
    "learn.microsoft.com", "raw.githubusercontent.com", "pastebin.com",
    # fuentes usadas por tools (CT fallback, enrich, dorks) — nunca son assets
    "api.hackertarget.com", "api.certspotter.com", "api.hunter.io",
    "emailrep.io", "html.duckduckgo.com", "duckduckgo.com", "www.bing.com",
    "r.jina.ai", "www.linkedin.com",
]

# TLDs que NUNCA son host: extensiones de archivo y tokens de JS minificado
# (aparecen en outputs de curl/JS: agentx-lg-en.webp, a.join, a.length...)
BAD_TLDS = {
    "webp", "svg", "png", "jpg", "jpeg", "gif", "ico", "css", "mjs", "map",
    "min", "ts", "json", "txt", "html", "htm", "xml", "pdf", "zip", "gz",
    "tar", "woff", "woff2", "ttf", "eot", "mp4", "mp3", "yaml", "yml", "conf",
    "ini", "cfg", "old", "bak", "cust", "py", "rb", "exe", "dll", "so", "jar",
    "war", "csv", "log", "md", "lock", "scss", "less", "vue", "jsx", "tsx",
    "env", "sql", "swf", "test",
    # tokens de codigo JS/minificado
    "join", "length", "push", "src", "top", "left", "width", "height",
    "visibility", "position", "border", "isprintable", "pu", "style",
}

# TLDs validos comunes (IANA): host plausible si termina en uno de estos
# o si es subdominio de un dominio ya en scope.
VALID_TLDS = {
    "com", "net", "org", "edu", "gov", "mil", "int", "info", "biz", "name",
    "pro", "mobi", "tel", "jobs", "travel", "museum", "coop", "aero", "post",
    "asia", "cat", "io", "ai", "app", "dev", "xyz", "tech", "site", "online",
    "store", "cloud", "live", "services", "digital", "space", "network",
    "systems", "solutions", "security", "tools", "group", "team", "world",
    "today", "media", "news", "blog", "shop", "email", "host", "hosting",
    "website", "vip", "club", "social", "company", "ventures", "capital",
    "agency", "software", "works", "studio", "lab", "labs", "page",
    # ccTLD
    "ar", "us", "uk", "ca", "au", "nz", "de", "fr", "it", "es", "pt", "mx",
    "cl", "br", "pe", "uy", "py", "bo", "ve", "ec", "pa", "do", "gt", "cr",
    "hn", "sv", "ni", "cu", "pr", "jp", "cn", "in", "kr", "sg", "hk", "tw",
    "th", "vn", "id", "my", "ph", "il", "ae", "sa", "qa", "kw", "eg", "ma",
    "ng", "za", "ru", "pl", "nl", "be", "ch", "at", "se", "no", "fi", "dk",
    "ie", "gr", "cz", "hu", "ro", "bg", "hr", "si", "sk", "lt", "lv", "ee",
    "ua", "tr", "cy", "mt", "lu", "is", "li", "gg", "je", "im", "sh", "ms",
    "sc", "ac", "tv", "cc", "ws", "to", "fm", "me", "co", "eu", "su",
    # infra interna
    "localhost", "local", "lan", "internal", "corp",
}

# Patrones destructivos del HOST del lab (kill-switch — NUNCA se relajan).
# El resto de herramientas de auditoria (hydra, nikto, sqlmap, etc.) son LIBRES.
BLOCK_PATTERNS = [
    r"\brm\s+-rf\s*/", r"\bmkfs", r"\bdd\s+if=/\w+/sd", r">\s*/dev/sd", r"\b:\(\)\s*\{",
    r"\breboot\b", r"\bshutdown\b", r"\bpoweroff\b", r"\bhalt\b",
    r"\biptables\s+-[FXZ]", r"\bdocker\s+(rm|system)\s+-f", r"\bchmod\s+-R\s+777\s*/",
    r"\bwhoami\s*=\s*.*;", r"\bmv\s+/etc",
    r"169\.254\.169\.254",
]

SECRET_SKIP_SOURCES = {"<tools_list>"}


class Scope:
    """Conjunto de hosts/dominios/IPs autorizados, auto-expansivo."""
    def __init__(self, initial):
        self.values = set()
        # el target del usuario SIEMPRE entra (aunque tenga TLD raro)
        v = self._normalize(initial)
        if v:
            self.values.add(v)

    def _normalize(self, value):
        v = str(value).strip().lower().rstrip(".")
        if not v or "$" in v:
            return ""
        if "://" in v:
            v = re.sub(r"^https?://", "", v)
        v = v.split("/")[0].split(":")[0]
        return v

    def _plausible_host(self, v):
        """Host real (resuelve DNS) vs tokens de codigo/JS (a.join, x.webp)."""
        if not RE_HOST.match(v):
            return False
        labels = v.split(".")
        tld = labels[-1]
        if tld in BAD_TLDS:
            return False
        if tld in VALID_TLDS:
            # rechazar tokens JS tipo b.qa / a.pu (SLD de 1 char, 2 labels)
            if len(labels) == 2 and len(labels[0]) < 2:
                return False
            return True
        # TLD raro pero subdominio de algo ya en scope (target legit)
        return any(v.endswith("." + s) for s in self.values if s and not RE_IP.match(s))

    def add(self, value):
        v = self._normalize(value)
        if not v:
            return False
        if RE_IP.match(v) or v in OSINT_ALLOW:
            self.values.add(v)
            return True
        if self._plausible_host(v):
            self.values.add(v)
            return True
        return False

    def add_from_output(self, text):
        if not text:
            return
        for m in RE_IP.finditer(text):
            self.add(m.group(0))
        for m in RE_URL_HOST.finditer(text):
            self.add(m.group(1))
        for m in RE_HOST.finditer(text):
            self.add(m.group(0))

    def in_scope(self, host):
        host = str(host).strip().lower().rstrip(".")
        if host in OSINT_ALLOW or host in self.values:
            return True
        # subdominio de un dominio en scope
        for v in self.values:
            if v and host.endswith("." + v):
                return True
        return False

    def has_hosts(self, text):
        return bool(RE_IP.search(text) or RE_HOST.search(text))

    def snapshot(self):
        return sorted(self.values)


def sanitize_output(text, maxlen=4000):
    """Redacta secretos del output ANTES de mandarlo al modelo y lo trunca."""
    if not text:
        return "(sin output)"
    text = text[:8000]
    for hit in secretlib.scan_text_all(text, source="<output>"):
        m = hit["match"]
        if m and len(m) > 6:
            text = text.replace(m, f"[REDACTED:{hit['pattern']}:{secret_safe(m, 4)}]")
    if len(text) > maxlen:
        text = text[:maxlen] + "\n...[truncado]"
    return text


# --- Validadores read-only (arsenal §23) ---
def validate_credential(ctype, secret):
    """Valida una credencial con una llamada read-only. Devuelve string."""
    secret = secret.strip()
    try:
        if ctype == "github":
            st, h, b = netexec.http_get("https://api.github.com/user", vpn=True, timeout=15,
                                        headers={"Authorization": f"token {secret}", "User-Agent": "nureq"})
            return f"github: HTTP {st} -> {'VIVA (read-only ok)' if st == 200 else 'muerta/invalida'}"
        if ctype == "slack":
            st, h, b = netexec.http_post("https://slack.com/api/auth.test", vpn=True, timeout=15,
                                         headers={"Authorization": f"Bearer {secret}"})
            return f"slack: HTTP {st} -> {'VIVA' if ('\"ok\":true' in b) else 'muerta/invalida'}"
        if ctype == "openai":
            st, h, b = netexec.http_get("https://api.openai.com/v1/models", vpn=True, timeout=15,
                                        headers={"Authorization": f"Bearer {secret}"})
            return f"openai: HTTP {st} -> {'VIVA' if st == 200 else 'muerta/invalida'}"
        if ctype == "anthropic":
            st, h, b = netexec.http_get("https://api.anthropic.com/v1/models", vpn=True, timeout=15,
                                        headers={"Authorization": f"Bearer {secret}", "anthropic-version": "2023-06-01"})
            return f"anthropic: HTTP {st} -> {'VIVA' if st == 200 else 'muerta/invalida'}"
        if ctype == "npm":
            st, h, b = netexec.http_get("https://registry.npmjs.org/-/whoami", vpn=True, timeout=15,
                                        headers={"Authorization": f"Bearer {secret}"})
            return f"npm: HTTP {st} -> {'VIVA' if st == 200 else 'muerta/invalida'}"
        if ctype == "postman":
            st, h, b = netexec.http_get("https://api.getpostman.com/me", vpn=True, timeout=15,
                                        headers={"X-Api-Key": secret})
            return f"postman: HTTP {st} -> {'VIVA' if st == 200 else 'muerta/invalida'}"
        if ctype == "gitlab":
            st, h, b = netexec.http_get("https://gitlab.com/api/v4/user", vpn=True, timeout=15,
                                        headers={"PRIVATE-TOKEN": secret})
            return f"gitlab: HTTP {st} -> {'VIVA' if st == 200 else 'muerta/invalida'}"
        if ctype in ("aws", "aws_access_key"):
            parts = secret.split(":", 1)
            ak = parts[0].strip()
            sk = parts[1].strip() if len(parts) > 1 else ""
            if not sk:
                return "aws: formato esperado ACCESS_KEY:SECRET_KEY (separados por :)."
            import hmac, hashlib, base64, urllib.parse
            now = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
            day = now[:8]
            service, region = "sts", "us-east-1"
            payload = "Action=GetCallerIdentity&Version=2011-06-15"
            host = f"sts.{region}.amazonaws.com"
            canonical = (f"GET\n/\n\nhost:{host}\nx-amz-date:{now}\n\n"
                         f"host;x-amz-date\n{hashlib.sha256(payload.encode()).hexdigest()}")
            scope = f"{day}/{region}/{service}/aws4_request"
            to_sign = f"AWS4-HMAC-SHA256\n{now}\n{scope}\n{hashlib.sha256(canonical.encode()).hexdigest()}"
            def _hmac(k, m):
                return hmac.new(k, m.encode(), hashlib.sha256).digest()
            kdate = _hmac(("AWS4" + sk).encode(), day)
            kreg = _hmac(kdate, region)
            ksvc = _hmac(kreg, service)
            ksign = _hmac(ksvc, "aws4_request")
            sig = hmac.new(ksign, to_sign.encode(), hashlib.sha256).hexdigest()
            auth = (f"AWS4-HMAC-SHA256 Credential={ak}/{scope}, SignedHeaders=host;x-amz-date, "
                    f"Signature={sig}")
            st, h, b = netexec.http_get(f"https://{host}/?{payload}", vpn=True, timeout=15,
                                        headers={"Authorization": auth, "X-Amz-Date": now})
            if st == 200 and "GetCallerIdentityResult" in b:
                return f"aws: VIVA (identity confirmada). {b[:150]}"
            return f"aws: HTTP {st} -> {'muerta/invalida' if st in (401, 403) else 'revisar'}"
        if ctype == "stripe":
            st, h, b = netexec.http_get("https://api.stripe.com/v1/charges?limit=1", vpn=True, timeout=15,
                                        headers={"Authorization": f"Bearer {secret}"})
            return f"stripe: HTTP {st} -> {'VIVA' if st == 200 else 'muerta/invalida'}"
        if ctype == "twilio":
            import base64
            tok = base64.b64encode(secret.encode()).decode()
            st, h, b = netexec.http_get("https://api.twilio.com/2010-04-01/Accounts.json", vpn=True, timeout=15,
                                        headers={"Authorization": f"Basic {tok}"})
            return f"twilio: HTTP {st} -> {'VIVA' if st == 200 else 'muerta/invalida'}"
        if ctype == "digitalocean":
            st, h, b = netexec.http_get("https://api.digitalocean.com/v2/account", vpn=True, timeout=15,
                                        headers={"Authorization": f"Bearer {secret}"})
            return f"digitalocean: HTTP {st} -> {'VIVA' if st == 200 else 'muerta/invalida'}"
        if ctype == "azure":
            st, h, b = netexec.http_get("https://management.azure.com/subscriptions?api-version=2020-01-01",
                                        vpn=True, timeout=15, headers={"Authorization": f"Bearer {secret}"})
            return f"azure: HTTP {st} -> {'VIVA' if st == 200 else 'muerta/invalida'}"
        if ctype == "telegram":
            st, h, b = netexec.http_get(f"https://api.telegram.org/bot{secret}/getMe", vpn=True, timeout=15)
            return f"telegram: HTTP {st} -> {'VIVA' if ('\"ok\":true' in b) else 'muerta/invalida'}"
        if ctype == "google":
            st, h, b = netexec.http_get("https://maps.googleapis.com/maps/api/geocode/json?address=test&key=" + secret,
                                        vpn=True, timeout=15)
            return f"google: HTTP {st} -> {'VIVA' if st == 200 and 'error_message' not in b else 'muerta/invalida'}"
        if ctype == "mailgun":
            import base64
            tok = base64.b64encode(("api:" + secret).encode()).decode()
            st, h, b = netexec.http_get("https://api.mailgun.net/v3/domains", vpn=True, timeout=15,
                                        headers={"Authorization": f"Basic {tok}"})
            return f"mailgun: HTTP {st} -> {'VIVA' if st == 200 else 'muerta/invalida'}"
        if ctype == "sendgrid":
            st, h, b = netexec.http_get("https://api.sendgrid.com/v3/user/profile", vpn=True, timeout=15,
                                        headers={"Authorization": f"Bearer {secret}"})
            return f"sendgrid: HTTP {st} -> {'VIVA' if st == 200 else 'muerta/invalida'}"
        if ctype == "shodan":
            st, h, b = netexec.http_get("https://api.shodan.io/api-info?key=" + secret, vpn=True, timeout=15)
            return f"shodan: HTTP {st} -> {'VIVA' if st == 200 else 'muerta/invalida'}"
        return (f"tipo '{ctype}' no soportado para validar (opciones: github, slack, openai, anthropic, "
                f"npm, postman, gitlab, aws, stripe, twilio, digitalocean, azure, telegram, google, "
                f"mailgun, sendgrid, shodan)")
    except Exception as e:
        return f"error validando: {e}"


# --- Schema de tools (function calling) ---
def _tool(name, description, properties, required=None):
    return {"type": "function", "function": {
        "name": name, "description": description,
        "parameters": {"type": "object", "properties": properties,
                       "required": required or list(properties.keys())}}}

TOOLS_SCHEMA = [
_tool("run_shell", "Ejecuta un comando shell ARBITRARIO (bash). "
                        "Es tu poder total: podes correr nmap, nuclei, ffuf, feroxbuster, curl, dig, "
                        "whatweb, python, etc. Solo red hacia el scope (el target + hosts descubiertos) "
                        "o servicios OSINT publicos. NO son destructivos. El output se te devuelve.",
          {"cmd": {"type": "string", "description": "comando bash a ejecutar"},
           "timeout": {"type": "integer", "description": "segundos max (default 60)"}},
          required=["cmd"]),
    _tool("probe_http", "Request HTTP/HTTPS libre (GET/POST/HEAD, headers, body) contra un host en scope.",
          {"method": {"type": "string", "enum": ["GET", "POST", "HEAD"]},
           "url": {"type": "string"},
           "headers": {"type": "string", "description": "headers 'Clave: Valor\\nClave2: Valor2' (opcional)"},
           "body": {"type": "string", "description": "body para POST (opcional)"},
           "timeout": {"type": "integer"}},
          required=["method", "url"]),
    _tool("shodan_host", "Shodan host lookup por IP (1 credito, cache 7d). Puertos, vulns, org, ASN.",
          {"ip": {"type": "string"}}, required=["ip"]),
    _tool("shodan_search", "Shodan search con DSL libre (1 credito). Ej: 'product:Docker', 'http.title:admin', "
                           "'ssl.cert.subject.cn:DOMINIO'. Top de creditos por corrida.",
          {"query": {"type": "string"}}, required=["query"]),
    _tool("cavalier", "HudsonRock Cavalier: cuentas de empleados comprometidas en logs de infostealers "
                      "para un dominio. Gratis.",
          {"domain": {"type": "string"}}, required=["domain"]),
    _tool("crtsh", "Subdominios de un dominio via cert transparency (crt.sh).",
          {"domain": {"type": "string"}}, required=["domain"]),
    _tool("wayback_cdx", "URLs historicas (Wayback CDX) de un dominio, con filtro opcional de extension "
                         "(js, json, php, asp, zip, env...).",
          {"domain": {"type": "string"}, "ext": {"type": "string"}},
          required=["domain"]),
    _tool("wayback_fetch", "Baja el contenido de un snapshot historico de Wayback por URL original.",
          {"url": {"type": "string"}}, required=["url"]),
    _tool("always_on_sweep", "Prueba las ~30 rutas sensibles clasicas (.git, .env, actuator, phpinfo, "
                             "config.json, swagger, backups, docker-compose, etc.) contra una webapp viva.",
          {"url": {"type": "string"}}, required=["url"]),
    _tool("swagger_find", "Busca y parsea specs OpenAPI/Swagger (28 paths) en una webapp; lista endpoints.",
          {"url": {"type": "string"}}, required=["url"]),
    _tool("graphql_probe", "Busca endpoints GraphQL (13 paths) y corre introspection.",
          {"url": {"type": "string"}}, required=["url"]),
    _tool("js_mine", "Mineria de JS de una webapp: endpoints de API, hosts internos, sourcemaps y secretos.",
          {"url": {"type": "string"}}, required=["url"]),
    _tool("docker_probe", "Prueba Docker API (2375/2376), kubelet (10250/10255), etcd (2379), k8s (6443) "
                          "y registry (5000 /v2/_catalog) contra una IP.",
          {"ip": {"type": "string"}}, required=["ip"]),
    _tool("scan_secrets", "Escanea un texto/body con el catalogo de 60+ patrones de secretos "
                          "(AWS, GitHub, OpenAI, passwords, connection strings, etc). Devuelve hits.",
          {"text": {"type": "string"}, "source": {"type": "string"}},
          required=["text"]),
    _tool("buscar_persona", "OSINT de persona (canal directo, sin VPN): dorks en DuckDuckGo/Bing "
                            "buscando perfiles publicos (linkedin.com/in, redes) y empresa asociada "
                            "a un nombre completo. Read-only.",
          {"nombre": {"type": "string"}}, required=["nombre"]),
    _tool("buscar_email", "OSINT de email (canal directo, sin VPN): verifica el email con hunter.io "
                          "(nombre/empresa asociados, status) + emailrep.io (reputacion, breaches) "
                          "+ dorks. Read-only. OJO: hunter gasta verificaciones del plan free.",
          {"email": {"type": "string"}}, required=["email"]),
    _tool("buscar_empresa", "OSINT de empresa (canal directo, sin VPN): dorks (sitio, linkedin "
                            "company) + RDAP + cavalier (empleados comprometidos en infostealers). "
                            "Read-only.",
          {"empresa": {"type": "string"}}, required=["empresa"]),
    _tool("buscar_emails_dominio", "Emails de EMPLEADOS de un dominio via Hunter Domain Search "
                                   "(canal directo, sin VPN): devuelve emails + nombre + cargo de "
                                   "cada persona encontrada. Usala para responder 'quien trabaja "
                                   "aca / dueño de la empresa'. Read-only.",
          {"dominio": {"type": "string"}}, required=["dominio"]),
    _tool("linkedin_empresa", "Datos publicos de una pagina de LinkedIn company (fetch directo, "
                              "canal directo, sin VPN): nombre, descripcion, empleados y texto "
                              "visible de la pagina. Ej: slug='beygoo'. Read-only.",
          {"slug": {"type": "string"}}, required=["slug"]),
    _tool("validar_credencial", "Valida una credencial encontrada con una llamada READ-ONLY. "
                                "Tipos: github, slack, openai, anthropic, npm, postman, gitlab, aws "
                                "(formato ACCESS_KEY:SECRET_KEY), stripe, twilio, digitalocean, azure, "
                                "telegram (bot token), google (API key), mailgun, sendgrid, shodan.",
          {"tipo": {"type": "string"}, "secreto": {"type": "string"}},
          required=["tipo", "secreto"]),
    _tool("hallazgo", "Registra un hallazgo estructurado con evidencia (para el reporte final). "
                      "Severidades: critical/high/medium/low/info. Categoria: DOCKER_EXPOSED, "
                      "SECRET_LEAK, LEAKY_API_SPEC, SUBDOMAIN_TAKEOVER, etc.",
          {"severidad": {"type": "string"}, "categoria": {"type": "string"},
           "titulo": {"type": "string"}, "descripcion": {"type": "string"},
           "url": {"type": "string"}, "evidencia": {"type": "string"}},
          required=["severidad", "categoria", "titulo", "descripcion"]),
    _tool("consultar_analista", "Escala a DeepSeek v4-pro (razonamiento profundo) para analizar un "
                                "problema/hallazgo complejo y decidir el proximo movimiento.",
          {"pregunta": {"type": "string"}, "contexto": {"type": "string"}},
          required=["pregunta"]),
    _tool("concluir", "Cierra la investigacion con un resumen de lo encontrado y lo que queda pendiente.",
          {"resumen": {"type": "string"}}, required=["resumen"]),
]

TOOL_NAMES = {t["function"]["name"] for t in TOOLS_SCHEMA}


# --- Dispatch ---
class Agent:
    def __init__(self, cfg, findings, seed=""):
        self.cfg = cfg
        self.findings = findings
        self.seed = seed or ""
        self.scope = Scope(cfg.target.replace("http://", "").replace("https://", "").split("/")[0])
        self.ledger = Ledger(cfg.cache_dir, cfg.target)
        self.entities = EntityStore()
        self.steps = 0
        self.max_steps = cfg.max_steps
        self.t0 = time.time()
        self.max_minutes = cfg.max_minutes
        self.shodan_budget = cfg.shodan_budget
        self.shodan_used = 0
        self.tool_stats = {}
        self.runs = []
        self.final_summary = ""
        self._findings_before = 0
        self._no_progress = 0

    def _budget_left(self):
        mins = max(0, int(self.max_minutes - (time.time() - self.t0) / 60))
        return f"pasos restantes: {max(0, self.max_steps - self.steps)} | minutos restantes: {mins} | shodan: {self.shodan_budget - self.shodan_used} creditos"

    def _anti_loop(self, name, args):
        key = (name, str(args)[:80])
        self.tool_stats[key] = self.tool_stats.get(key, 0) + 1
        return self.tool_stats[key]

    def _auto_harvest(self, output_text, source):
        """Registra hallazgos automaticamente desde cualquier output del agente
        (curl crudo, probe_http, wayback...). Detecta secretos y exposiciones clasicas.
        ADEMAS: aspira entidades (emails/nombres/empresas) de todo output."""
        if not output_text or len(output_text) < 4:
            return
        # aspiradora de entidades (local, sin red)
        try:
            self.entities.add_text(output_text, source=str(source)[:120])
        except Exception:
            pass
        low = output_text.lower()
        # 1) secretos (dedup: si ya existe el match exacto, no duplicar)
        existing_raws = {f["evidence"].get("raw") for f in self.findings.items
                         if f.get("category") == "SECRET_LEAK"}
        for h in secretlib.scan_text_all(output_text, source=source)[:25]:
            if h["match"][:300] in existing_raws:
                continue
            self.findings.add(
                module="agent_auto", category="SECRET_LEAK", severity=h["severity"],
                confidence="firm",
                title=f"Secreto ({h['pattern']}) en {source}",
                description=f"Patron {h['pattern']} ({h['category']}). Severidad del catalogo: {h['severity']}.",
                asset_key=source, url=source, raw=h["match"][:300],
                remediation="Rotar/revocar la credencial expuesta.")
        # 2) exposiciones clasicas por contenido
        src = source.lower()
        if "2375" in src and '"apiversion"' in low:
            self.findings.add(module="agent_auto", category="DOCKER_EXPOSED", severity="critical",
                              confidence="confirmed", title=f"Docker API respondiendo en {source}",
                              description="La API de Docker responde (ApiVersion visible). Takeover del host posible.",
                              asset_key=source, url=source, raw=output_text[:400],
                              remediation="Cerrar el socket Docker a la red.")
        if "5000" in src and '"repositories"' in low:
            self.findings.add(module="agent_auto", category="REGISTRY_EXPOSED", severity="high",
                              confidence="confirmed", title=f"Docker registry abierto en {source}",
                              description="El registry responde /v2/_catalog sin auth (lista de imagenes).",
                              asset_key=source, url=source, raw=output_text[:400],
                              remediation="Poner auth en el registry.")
        if ".git/config" in src and "[core]" in low:
            self.findings.add(module="agent_auto", category="GIT_CONFIG", severity="critical",
                              confidence="confirmed", title=f"Repo .git expuesto en {source}",
                              description=".git/config accesible: se puede clonar el codigo fuente.",
                              asset_key=source, url=source, raw=output_text[:400],
                              remediation="Bloquear acceso a /.git.")
        if "swagger" in low and '"paths"' in low:
            self.findings.add(module="agent_auto", category="LEAKY_API_SPEC", severity="high",
                              confidence="firm", title=f"Spec Swagger/OpenAPI en {source}",
                              description="Spec de API con paths visible (superficie completa).",
                              asset_key=source, url=source, raw=output_text[:400],
                              remediation="Sacar la spec del acceso publico.")
        if "/pods" in src and '"items"' in low:
            self.findings.add(module="agent_auto", category="KUBELET_EXPOSED", severity="critical",
                              confidence="confirmed", title=f"kubelet sin auth en {source}",
                              description="El kubelet responde /pods sin auth.",
                              asset_key=source, url=source, raw=output_text[:300],
                              remediation="Habilitar auth en kubelet.")
        if re.search(r"(?m)^[A-Z][A-Z0-9_]{2,}\s*=\s*\S", output_text) and any(
                k in src for k in (".env", "config", "properties", "docker")):
            self.findings.add(module="agent_auto", category="ENV_FILE", severity="critical",
                              confidence="firm", title=f"Archivo de configuracion con variables en {source}",
                              description="Variables KEY=valor expuestas (posibles credenciales).",
                              asset_key=source, url=source, raw=output_text[:400],
                              remediation="Sacar el archivo del acceso publico y rotar secretos.")

    # --- tools ---
    def _block_patterns(self):
        """Kill-switch del host + metadata AWS configurable (NUREQ_ALLOW_METADATA)."""
        pats = list(BLOCK_PATTERNS)
        if self.cfg.allow_metadata:
            pats = [p for p in pats if "169.254.169.254" not in p]
        return pats

    def _register_new_assets(self, hosts):
        """Modo autonomo: hosts fuera de scope se auto-agregan y se registran
        como ASSET_NUEVO (cadena de custodia). Solo hosts plausibles: un
        servicio OSINT publico o un token de codigo (a.join, $h) NO es asset."""
        added = []
        for h in hosts:
            h = str(h).strip().lower().rstrip(".")
            if not h or h in OSINT_ALLOW or self.scope.in_scope(h):
                continue
            if not self.scope.add(h):
                continue
            added.append(h)
            self.findings.add(
                module="scope", category="ASSET_NUEVO", severity="info",
                confidence="firm", title=f"Asset expandido: {h}",
                description=(f"Host {h} descubierto/abordado durante la investigacion "
                             f"y agregado al scope automaticamente (modo autonomo)."),
                asset_key=f"host:{h}", url=f"http://{h}/")
        return added

    def _run_shell(self, args):
        cmd = args.get("cmd", "").strip()
        timeout = int(args.get("timeout") or 60)
        if not cmd:
            return "falta cmd"
        for pat in self._block_patterns():
            if re.search(pat, cmd):
                return f"[BLOQUEADO] el comando matchea un patron destructivo del host del lab: {pat}. Busca otra via."
        hosts = []
        for m in RE_URL_HOST.finditer(cmd):
            hosts.append(m.group(1))
        for m in RE_IP.finditer(cmd):
            hosts.append(m.group(0))
        for m in RE_HOST.finditer(cmd):
            h = m.group(0)
            if h.rsplit(".", 1)[-1] in ("com", "net", "org", "io", "ar", "ai", "dev") and len(h.split(".")) >= 3:
                hosts.append(h)
        note = ""
        if hosts and self.cfg.autonomo:
            added = self._register_new_assets(hosts)
            if added:
                note = f"\n[autonomo] assets nuevos agregados al scope: {', '.join(added[:4])}"
        timeout = min(timeout, 300)
        rc, out, err = netexec.run_cmd_stream(["bash", "-c", cmd], vpn=self.cfg.vpn,
                                              timeout=timeout, idle_timeout=min(90, timeout // 2 or 45))
        text = f"$ {cmd}\n[exit {rc}]\n{out}\n{err}"
        self.scope.add_from_output(text)
        self._auto_harvest(out + "\n" + err, source=cmd[:120])
        return sanitize_output(text + note)

    def _probe_http(self, args):
        method = args.get("method", "GET").upper()
        url = args.get("url", "")
        m = RE_URL_HOST.search(url)
        if not m:
            return f"[RECHAZADO] URL invalida: {url}"
        note = ""
        if self.cfg.autonomo and not self.scope.in_scope(m.group(1)):
            added = self._register_new_assets([m.group(1)])
            if added:
                note = f"\n[autonomo] asset nuevo agregado al scope: {m.group(1)}"
        headers = {}
        if args.get("headers"):
            for line in args["headers"].splitlines():
                if ":" in line:
                    k, _, v = line.partition(":")
                    headers[k.strip()] = v.strip()
        timeout = int(args.get("timeout") or 15)
        if method == "POST":
            st, h, body = netexec.http_post(url, data=args.get("body") or "", headers=headers,
                                            vpn=self.cfg.vpn, timeout=timeout)
        elif method == "HEAD":
            st, h, body = netexec.http_head(url, vpn=self.cfg.vpn, timeout=timeout)
        else:
            st, h, body = netexec.http_get(url, headers=headers, vpn=self.cfg.vpn, timeout=timeout)
        out = f"{method} {url}\nHTTP {st}\nHeaders: {json.dumps(h)}\n\n{body}"
        self.scope.add_from_output(out)
        self._auto_harvest(body, source=url)
        return sanitize_output(out + note)

    def _shodan_host(self, args):
        if self.shodan_used >= self.shodan_budget:
            return "[SHODAN] sin presupuesto de creditos. Usa internetdb (gratis) via run_shell."
        self.shodan_used += 1
        if not self.cfg.shodan_key:
            return "[SHODAN] no hay SHODAN_API_KEY configurada"
        data = stage3_enrich.shodan_host(args["ip"], self.cfg, self.findings, vpn=self.cfg.vpn)
        return sanitize_output(json.dumps(data, default=str)[:3000]) if data else "sin datos shodan para esa IP"

    def _shodan_search(self, args):
        if self.shodan_used >= self.shodan_budget:
            return "[SHODAN] sin presupuesto de creditos. Usa internetdb (gratis) o corre un nmap via run_shell."
        self.shodan_used += 1
        if not self.cfg.shodan_key:
            return "[SHODAN] no hay SHODAN_API_KEY configurada"
        st, data, body = netexec.http_get_json(
            f"https://api.shodan.io/shodan/host/search?query={urllib_quote(args['query'])}&key={self.cfg.shodan_key}",
            vpn=self.cfg.vpn, timeout=25)
        if st != 200 or not data:
            return f"shodan search error HTTP {st}: {body[:200]}"
        res = data.get("matches", [])
        lines = [f"total: {data.get('total')}"]
        for m in res[:12]:
            lines.append(f"{m.get('ip_str')}:{m.get('port')} {m.get('product')} {m.get('os','')} org={m.get('org','')}")
        out = "\n".join(lines)
        self.scope.add_from_output(out)
        return sanitize_output(out)

    def _cavalier(self, args):
        d = args["domain"]
        data = stage3_enrich.cavalier(d, self.findings, vpn=self.cfg.vpn)
        out = json.dumps(data, default=str) if data else "sin resultados cavalier"
        self.scope.add_from_output(out)
        return sanitize_output(out[:2500])

    def _crtsh(self, args):
        d = args["domain"]
        key = f"crtsh:{d}"
        if self.ledger.done(key, ttl=24):
            return "[LEDGER] crtsh ya consultado para este dominio en las ultimas 24h. No repetir salvo nuevo subdominio detectado en otra fuente."
        subs, ips = stage1_seed.ct_subdomains(d, self.findings, vpn=self.cfg.vpn,
                                              all_sources=(self.cfg.perfil == "profundo"))
        self.ledger.mark(key, f"{len(subs)} subs")
        for h, il in ips.items():
            if il:
                self.scope.add(il[0])
        out = "\n".join(subs) if subs else "sin subdominios en CT"
        self.scope.add_from_output(out)
        return sanitize_output(out[:2500])

    def _wayback_cdx(self, args):
        ext = args.get("ext")
        d = args["domain"]
        key = f"wayback:{d}"
        if self.ledger.done(key, ttl=24):
            return "[LEDGER] wayback ya consultado para este dominio en las ultimas 24h. Usa wayback_fetch si necesitas contenido puntual."
        urls = stage3_enrich.wayback_cdx(d, self.findings, vpn=self.cfg.vpn, rps=self.cfg.rps)
        self.ledger.mark(key, f"{len(urls)} urls")
        if ext:
            urls = [u for u in urls if u.endswith("." + ext)]
        interesting = [u for u in urls if any(k in u for k in
                       ("api", "admin", "config", "backup", "internal", "swagger", "graphql", "env", "token", "auth"))]
        shown = interesting or urls
        if len(shown) > 25 and self.cfg.deepseek_key:
            # triage con v4-flash (batch barato): mostrar solo las que valen la pena
            triaged = ailib_triage(shown, self.cfg.deepseek_key)
            if triaged:
                shown = [t.get("url") for t in triaged if t.get("url")][:12]
        out = "\n".join(shown[:120]) if shown else "sin URLs historicas"
        self.scope.add_from_output(out)
        return sanitize_output(out[:3000])

    def _wayback_fetch(self, args):
        url = args["url"]
        st, _, body = netexec.http_get(f"https://web.archive.org/web/{url}", vpn=self.cfg.vpn, timeout=20)
        self._auto_harvest(body, source=url)
        return sanitize_output(f"HTTP {st}\n{body[:3500]}")

    def _always_on(self, args):
        hits = stage4_expose.always_on(args["url"], self.findings, vpn=self.cfg.vpn)
        return sanitize_output(f"{len(hits)} exposiciones detectadas (ver findings). Detalle:\n" +
                               "\n".join(f"{u} [{s}] {c}" for u, s, c, _ in hits) if hits else
                               "sin exposiciones en rutas clasicas")

    def _swagger(self, args):
        data = stage4_expose.swagger_find(args["url"], self.findings, vpn=self.cfg.vpn)
        return sanitize_output(json.dumps(data, default=str)[:2500]) if data else "sin spec swagger/openapi"

    def _graphql(self, args):
        names = stage4_expose.graphql_probe(args["url"], self.findings, vpn=self.cfg.vpn)
        return sanitize_output(", ".join(names)) if names else "sin graphql con introspection"

    def _js_mine(self, args):
        res = stage4_expose.js_mine(args["url"], self.findings, vpn=self.cfg.vpn)
        out = (f"endpoints: {res.get('endpoints', [])}\ninternal: {res.get('internal', [])}\n"
               f"secrets: {[s['pattern'] for s in res.get('secrets', [])]}")
        self.scope.add_from_output(out)
        return sanitize_output(out[:3000])

    def _docker(self, args):
        res = stage4_expose.docker_probe(args["ip"], self.findings, vpn=self.cfg.vpn)
        return sanitize_output("\n".join(res) if res else "sin docker/k8s/registry expuesto (o no responde)")

    def _scan_secrets(self, args):
        text = args.get("text", "")[:50000]
        source = args.get("source") or "<user>"
        hits = secretlib.scan_text_all(text, source=source)
        if not hits:
            return "sin secretos detectados"
        lines = [f"- {h['pattern']} ({h['severity']}) cat={h['category']} valor={secret_safe(h['match'], 4)} linea={h['line']}"
                 for h in hits[:40]]
        return sanitize_output("Secretos detectados:\n" + "\n".join(lines))

    def _validate(self, args):
        return validate_credential(args["tipo"].lower(), args["secreto"])

    def _finding(self, args):
        ev = args.get("evidencia") or ""
        try:
            f = self.findings.add(
                module="agent", category=args["categoria"].upper(), severity=args["severidad"].lower(),
                confidence="confirmed" if args.get("url") else "firm",
                title=args["titulo"][:160], description=args["descripcion"][:400],
                asset_key=args.get("url") or self.cfg.target, url=args.get("url"),
                raw=ev[:1500])
            return f"hallazgo registrado id={f['id']} (total {self.findings.count()})" if f else "hallazgo duplicado (ya existe)"
        except Exception as e:
            return f"error registrando hallazgo: {e}"

    def _analyst(self, args):
        q = args["pregunta"][:1500]
        ctx = (args.get("contexto") or "")[:1500]
        content, err = deepseek_call(
            [{"role": "system", "content": "Sos un analista OSINT senior (v4-pro). Razonas profundo y "
                                           "respondes con un plan concreto y accionable."},
             {"role": "user", "content": f"Pregunta: {q}\n\nContexto:\n{ctx}"}],
            model=MODEL_PRO, max_tokens=2500, thinking=True, reasoning_effort="high",
            timeout=180, key=self.cfg.deepseek_key)
        return sanitize_output(content if content else f"error analista: {err}", maxlen=2500)

    # --- OSINT de entidades (canal directo, sin VPN) ---
    def _buscar_persona(self, args):
        nombre = args["nombre"].strip()
        if not nombre or len(nombre) < 4:
            return "nombre invalido"
        results = enrich.search_person(nombre)
        if not results:
            return f"sin resultados de busqueda para '{nombre}'"
        lines = []
        for r in results[:8]:
            url = r.get("url", "")
            self.scope.add_from_output(url)
            lines.append(f"{r.get('title', '')[:90]}\n  {url}\n  {r.get('snippet', '')[:140]}")
        out = f"Dorks para '{nombre}':\n" + "\n".join(lines)
        self.entities.add_text(out, source=f"dork:{nombre}")
        return sanitize_output(out[:2800])

    def _buscar_email(self, args):
        email = args["email"].strip().lower()
        if not email or "@" not in email:
            return "email invalido"
        lines = [f"Email: {email}"]
        hv = enrich.hunter_verify(email)
        if hv and "error" in hv:
            lines.append(f"hunter: {hv['error']}")
        elif hv:
            lines.append(f"hunter: status={hv.get('status')} result={hv.get('result')} "
                         f"disposable={hv.get('disposable')} webmail={hv.get('webmail')} "
                         f"mx={hv.get('mx_found')} smtp={hv.get('smtp_check')}")
            if hv.get("first_name") or hv.get("last_name"):
                nombre = " ".join(x for x in (hv.get("first_name"), hv.get("last_name")) if x)
                lines.append(f"hunter: nombre asociado -> {nombre}")
                self.entities.add({"nombres": [{"value": nombre, "inferred": True, "source": "hunter"}]})
            if hv.get("company"):
                lines.append(f"hunter: empresa -> {hv['company']}")
                self.entities.add({"empresas": [{"value": hv["company"], "inferred": True, "source": "hunter"}]})
        else:
            lines.append("hunter: sin resultado (sin key o sin data)")
        er = enrich.emailrep(email)
        if er:
            lines.append(f"emailrep: reputation={er.get('reputation')} breached={er.get('breached')} "
                         f"data_breach={er.get('data_breach')} deliverable={er.get('deliverable')} "
                         f"dominio={er.get('domain')}")
            if er.get("sources"):
                lines.append(f"emailrep: fuentes -> {', '.join(str(s)[:40] for s in er['sources'][:4])}")
        else:
            lines.append("emailrep: sin respuesta")
        dorks = enrich.search_email(email)
        if dorks:
            lines.append("dorks:")
            for r in dorks[:5]:
                lines.append(f"  {r.get('url', '')}")
        out = "\n".join(lines)
        self.entities.add_text(out, source=f"dork:{email}")
        return sanitize_output(out[:2800])

    def _buscar_empresa(self, args):
        empresa = args["empresa"].strip()
        if not empresa or len(empresa) < 3:
            return "empresa invalida"
        lines = [f"Empresa: {empresa}"]
        results = enrich.search_company(empresa)
        if results:
            lines.append("dorks:")
            for r in results[:6]:
                url = r.get("url", "")
                self.scope.add_from_output(url)
                lines.append(f"  {r.get('title', '')[:80]}\n  {url}")
        cav = stage3_enrich.cavalier(empresa.lower().replace(" ", ""), self.findings, vpn=False)
        if cav:
            lines.append(f"cavalier: {cav.get('employees', 0)} empleados comprometidos, "
                         f"{cav.get('users', 0)} usuarios")
        out = "\n".join(lines)
        self.entities.add_text(out, source=f"dork:{empresa}")
        return sanitize_output(out[:2800])

    def _buscar_emails_dominio(self, args):
        dominio = args["dominio"].strip().lower()
        if not dominio:
            return "dominio invalido"
        res = enrich.hunter_domain_search(dominio)
        if "error" in res:
            return f"hunter domain search: {res['error']}"
        emails = res.get("emails") or []
        if not emails:
            return f"hunter domain search: sin emails publicos para {dominio} (pattern {res.get('pattern')})"
        lines = [f"Hunter Domain Search — {dominio} (pattern {res.get('pattern')}):"]
        for e in emails[:40]:
            nombre = " ".join(x for x in (e.get("first_name"), e.get("last_name")) if x)
            cargo = e.get("position") or ""
            lines.append(f"  {e.get('email')} | {nombre} | {cargo}")
            if nombre:
                self.entities.add({"nombres": [{"value": nombre, "inferred": True, "source": "hunter"}]})
            if e.get("email"):
                self.entities.add({"emails": [{"value": e["email"], "inferred": True, "source": "hunter"}]})
        out = "\n".join(lines)
        self.entities.add_text(out, source=f"hunter:{dominio}")
        return sanitize_output(out[:2800])

    def _linkedin_empresa(self, args):
        slug = args["slug"].strip().lower()
        if not slug:
            return "slug invalido"
        res = enrich.linkedin_company(slug)
        if "error" in res:
            return f"linkedin: {res['error']}"
        texto = res.get("texto", "")
        self.entities.add_text(texto, source=f"linkedin:{slug}")
        if res.get("nombre"):
            self.entities.add({"empresas": [{"value": res["nombre"], "inferred": True,
                                             "source": "linkedin"}]})
        head = f"LinkedIn company /{slug}/ ({res.get('chars')} chars)"
        if res.get("nombre"):
            head += f"\nNombre: {res['nombre']}"
        if res.get("descripcion"):
            head += f"\nDescripcion: {res['descripcion'][:200]}"
        if res.get("empleados"):
            head += f"\nEmpleados: {res['empleados']}"
        return sanitize_output(f"{head}\n\nTexto visible:\n{texto[:2000]}", maxlen=2800)

    def _concluir(self, args):
        self.final_summary = args.get("resumen", "")
        return "investigacion cerrada"

    def dispatch(self, name, args):
        method = {"hallazgo": "_finding"}.get(name, "_" + name)
        fn = getattr(self, method, None)
        if fn is None:
            return f"tool desconocida: {name}"
        try:
            return fn(args)
        except Exception as e:
            return f"error en tool {name}: {e}"

    # --- checkpoint ---
    def _ckpt_path(self):
        from pathlib import Path
        from . import config
        return config.BASE_DIR / "cache" / f"checkpoint_{_safe_name(self.cfg.target)}_{self.cfg.perfil}.json"

    def save_checkpoint(self):
        """Guarda estado para --resume: findings, scope, runs, steps, summary.
        Nombre por target+perfil: corridas rapido/medio/profundo no se pisan."""
        ck = self._ckpt_path()
        ck.parent.mkdir(parents=True, exist_ok=True)
        data = {
            "target": self.cfg.target, "perfil": self.cfg.perfil,
            "steps": self.steps, "scope": self.scope.snapshot(),
            "final_summary": self.final_summary, "ts": time.time(),
            "runs": self.runs[-200:],
            "shodan_used": self.shodan_used,
            "findings": self.findings.items,
            "entities": self.entities.to_dict(),
        }
        try:
            ck.write_text(json.dumps(data, ensure_ascii=False, indent=2))
            return str(ck)
        except Exception as e:
            return f"error guardando checkpoint: {e}"

    def load_checkpoint(self):
        """Carga checkpoint si existe y es del mismo target+perfil."""
        ck = self._ckpt_path()
        if not ck.exists():
            return False
        try:
            data = json.loads(ck.read_text())
        except Exception:
            return False
        if data.get("target") != self.cfg.target:
            return False
        self.steps = data.get("steps", 0)
        for v in data.get("scope") or []:
            self.scope.add(v)
        self.final_summary = data.get("final_summary") or ""
        self.shodan_used = data.get("shodan_used", 0)
        for f in data.get("findings") or []:
            self.findings.add(
                module=f.get("module", "resume"), category=f.get("category", "?"),
                severity=f.get("severity", "info"), confidence=f.get("confidence", "firm"),
                title=f.get("title", "?"), description=f.get("description", ""),
                asset_key=f.get("asset_key"), url=(f.get("evidence") or {}).get("url"),
                raw=(f.get("evidence") or {}).get("raw"),
                references=f.get("references") or [],
                remediation=f.get("remediation") or "")
        self.runs = data.get("runs") or []
        for ent in (data.get("entities") or {}).get("emails", []):
            self.entities.emails[ent["value"]] = {
                "sources": set(ent.get("sources") or []), "count": ent.get("count", 1),
                "inferred": ent.get("inferred", False),
                "first": ent.get("first", ""), "last": ent.get("last", "")}
        for ent in (data.get("entities") or {}).get("nombres", []):
            self.entities.nombres[ent["value"]] = {
                "sources": set(ent.get("sources") or []), "count": ent.get("count", 1),
                "inferred": ent.get("inferred", False),
                "first": ent.get("first", ""), "last": ent.get("last", "")}
        for ent in (data.get("entities") or {}).get("empresas", []):
            self.entities.empresas[ent["value"]] = {
                "sources": set(ent.get("sources") or []), "count": ent.get("count", 1),
                "inferred": ent.get("inferred", False),
                "first": ent.get("first", ""), "last": ent.get("last", "")}
        return True

    # --- loop ---
    def _system_prompt(self):
        ledger_note = self.ledger.summary(15)
        return f"""Sos EL INVESTIGADOR: un agente de OSINT 100% autonomo y libre. No tenes guion ni checklist fijo:
investigás con tu criterio, perseguís pistas, cruzas fuentes y decidís vos qué hacer en cada paso.

Target autorizado: {self.cfg.target}
Scope autorizado (se auto-expande con cada host/IP/dominio que descubras): {', '.join(self.scope.snapshot()[:15])}
Presupuesto: {self._budget_left()}

{ledger_note}

REGLAS DE INVESTIGACION (no son limites, son criterio):
- PERSISTENCIA EXPLORATORIA: "no se puede" no es primera respuesta. Si una via no anda, proba otra.
- MODO AUTONOMO TOTAL: no necesitas pedir permiso para nada. Todo host/IP/dominio que quieras
  tocar se auto-agrega al scope y se ejecuta (queda registrado como ASSET_NUEVO). No existe
  "fuera de scope". Herramientas de auditoria (hydra, nikto, sqlmap, ffuf, nuclei...) son LIBRES.
- Persegui pistas: un hostname interno filtrado en JS -> resolvelo y probealo. Una conexion de DB en un
  config.json -> proba resolver el host, buscarlo en crt.sh/wayback, probar otros paths. Un registry Docker
  -> enumera tags y baja manifests. Un dominio en un certificado -> agregalo y segui.
- Cuando encuentres algo, REGISTRALO con la tool hallazgo (evidencia concreta). ADEMAS: si ves
  secretos o exposiciones en cualquier output (curl, probe, wayback), se registran SOLOS como
  hallazgos — no hace falta duplicarlos, pero sí contextualizarlos con hallazgo() cuando sean
  importantes (severidad, impacto, siguiente paso).
- Distingui HECHO / HIPOTESIS / SOSPECHA. No sobre-vendás. Un dato no es hecho hasta verlo.
- Cruzá fuentes: DNS + CT + wayback + shodan + brechas juntos valen mas que uno solo.
- ASPIRADORA DE ENTIDADES: de TODO output se extraen SOLOS los emails, nombres completos y
  empresas (con su fuente). No hace falta que los registres a mano. Tu trabajo extra: cuando
  un email/nombre/empresa sea relevante, ENRIQUECELO con buscar_email / buscar_persona /
  buscar_empresa (canal directo, sin VPN) y registra el resultado con hallazgo cuando aporte
  (ej. email verificado, persona vinculada a la empresa, empleados comprometidos).
- EMPLEADOS / DUEÑOS DE LA EMPRESA DEL TARGET: para responder "quien trabaja aca / de quien
  es esto", usa buscar_emails_dominio(dominio) (Hunter Domain Search: emails + nombre + cargo
  de empleados) y linkedin_empresa(slug) (texto publico de la pagina de LinkedIn company).
  No dependas solo de las dorks de buscadores (suelen estar bloqueadas).
- DOCKER/CONTENEDORES: probá docker_probe contra TODAS las IPs que vayas resolviendo
  (2375/2376/10250/10255/2379/6443/5000). Si la IP es de un CDN y no responde, queda como
  info y seguís — pero SIEMPRE se prueba.
- SECRETOS EN ENDPOINTS: si js_mine te devuelve endpoints de API, bajalos con probe_http y
  corré scan_secrets sobre el body (y el texto completo del response). JSON con sessions,
  passwords, users, tokens o connection strings es al menos HIGH: registralo con hallazgo.
- Si encontres una credencial, validala read-only (validar_credencial) y registra el resultado.
- Los secretos te llegan REDACTADOS (ultimos 4 chars). Nunca los adivines ni los inventes.
- Sin presion: cuando sientas que ya no queda jugo (todo agotado, sin pistas nuevas), llama concluir
  con un resumen honesto de lo encontrado y lo que queda pendiente.
- CIERRE A TIEMPO: con 3 pasos o menos de presupuesto restante, NO abras frentes nuevos: cerrá con
  concluir(resumen). Un resumen honesto vale más que un paso más de recon. No repitas tools que ya
  dieron vacío.
- UNICO LIMITE REAL: no rompas el host del lab (rm -rf /, mkfs, dd a disco, reboot, iptables -FXZ,
  mv /etc). Todo lo demas es investigacion.
- El filesystem del lab es SOLO de trabajo (wordlists, /tmp para bajarte archivos a analizar).
  NO lo explores por curiosidad (ls, pwd, cat de archivos del lab): enfocate en investigar el target.

TENES PODER TOTAL: podes correr shell libre (nmap, nuclei, ffuf, curl, dig, lo que quieras),
HTTP arbitrario, Shodan, CT logs, Wayback, brechas de infostealers, mineria de JS, deteccion de
Docker/K8s y barrido de secretos. Elegí la herramienta justa para cada paso.

Estilo: conciso, tecnico, en espanol rioplatense. Antes de cada accion explicá brevemente el porqué
(1 linea)."""

    def run(self):
        seed_block = ""
        if self.seed:
            seed_block = (f"\n\n== PRE-RECON YA HECHO (findings registrados, NO repitas esto) ==\n"
                          f"{self.seed}")
        if self.findings.count():
            seed_block += (f"\n\nHallazgos base ya registrados: {self.findings.count()} "
                           f"(los ves en el reporte final; podes consultarlos con la tool hallazgo).")
        messages = [{"role": "system", "content": self._system_prompt()},
                    {"role": "user", "content": (
                        f"Target: {self.cfg.target}{seed_block}\n\n"
                        f"Perfil de profundidad: {self.cfg.perfil}. Arrancá PROFUNDIZANDO: "
                        f"el pre-recon ya cubrio lo basico. Segui las pistas que el pre-recon "
                        f"dejo, expandi a hosts nuevos, enriquece entidades, y cerrá con "
                        f"concluir() cuando no quede jugo. Pasos grandes y eficientes.")}]
        final = False
        while self.steps < self.max_steps:
            if (time.time() - self.t0) / 60 > self.max_minutes:
                messages.append({"role": "user", "content": "[PRESUPUESTO] se acabo el tiempo. Concluí con lo que hay."})
            self.steps += 1
            if self.steps % 5 == 0:
                self.save_checkpoint()
            msg = None
            err = None
            for attempt in range(3):
                msg, err = deepseek_raw_stream(messages, model=MODEL_FLASH, max_tokens=700,
                                               temperature=0.3, timeout=90,
                                               first_token_timeout=30,
                                               key=self.cfg.deepseek_key,
                                               tools=TOOLS_SCHEMA)
                if err and "tool_calls" in err and ("must be followed by tool messages"
                                                    in err or "insufficient tool messages" in err):
                    # historial de tools corrupto -> reconstruir a texto plano y reintentar
                    recent = "; ".join(f"{r.get('tool')}" for r in self.runs[-20:])
                    messages = [messages[0], {"role": "user", "content": (
                        f"[recuperacion] {err[:120]}. Herramientas ejecutadas: {recent}. "
                        f"Los hallazgos ya registrados persisten. Segui investigando.")}]
                    continue
                break
            if err:
                print(f"  [ai] error: {err}")
                break
            tool_calls = msg.get("tool_calls") or []
            if msg.get("content") or tool_calls:
                assistant_msg = {"role": "assistant"}
                if msg.get("content"):
                    assistant_msg["content"] = msg["content"]
                if tool_calls:
                    assistant_msg["tool_calls"] = tool_calls
                messages.append(assistant_msg)
                if msg.get("reasoning_content"):
                    self.runs.append({"step": self.steps, "tool": "_reasoning",
                                      "text": msg["reasoning_content"][:1200]})
            if not tool_calls:
                # el modelo respondio texto sin tools: si NO concluyo, empujarlo a continuar
                # (solo cierra si llamo concluir() explicitamente, agoto pasos o el gate lo corta)
                if "concluir" in json.dumps(msg.get("content") or "")[:200]:
                    print("  [ai] cerrando por mensaje de cierre")
                    self.final_summary = self.final_summary or msg["content"][:600]
                    break
                if self.steps >= self.max_steps:
                    break
                messages.append({"role": "user", "content": (
                    "No llamaste ninguna tool y no cerraste la investigacion. "
                    "Si ya agotaste el terreno, llama concluir(resumen). "
                    "Si todavia hay pistas, segui usando las tools.")})
                continue

            # gate de progreso (configurable: NUREQ_FORCE_CLOSE=1 lo reactiva)
            if self.cfg.force_close:
                if self.findings.count() > self._findings_before:
                    self._findings_before = self.findings.count()
                    self._no_progress = 0
                else:
                    self._no_progress += 1
                if self._no_progress == 8:
                    messages.append({"role": "user", "content": (
                        "[TEAM LEAD] Hace 8 pasos que no registras ningun hallazgo nuevo. "
                        "Si ya agotaste el terreno, CERRÁ con concluir(). No repitas herramientas sin resultado.")})
                elif self._no_progress >= 12:
                    print("  [team-lead] sin progreso — forzando cierre")
                    self.final_summary = self.final_summary or "(cerrado por falta de progreso)"
                    break
            stop = False
            results = []

            def _exec_one(tc):
                name = tc["function"]["name"]
                try:
                    args = json.loads(tc["function"]["arguments"] or "{}")
                except Exception:
                    args = {}
                t0 = time.time()
                if name not in TOOL_NAMES:
                    result = f"tool desconocida: {name}"
                elif name == "concluir":
                    result = self._concluir(args)
                else:
                    n = self._anti_loop(name, args)
                    if n >= self.cfg.anti_loop:
                        result = (f"[ANTI-LOOP] ya ejecutaste {name} con estos parametros {n} veces "
                                  f"sin resultado nuevo. Buscá otra aproximacion.")
                    else:
                        result = self.dispatch(name, args)
                        self.runs.append({"step": self.steps, "tool": name, "args": args,
                                          "elapsed": round(time.time() - t0, 2)})
                print(f"  ▸ {name}({json.dumps(args)[:80]})")
                return (tc["id"], result, name)

            # ejecutar en paralelo las tool_calls independientes del mismo turno
            from concurrent.futures import ThreadPoolExecutor
            if len(tool_calls) > 1:
                with ThreadPoolExecutor(max_workers=min(4, len(tool_calls))) as ex:
                    executed = list(ex.map(_exec_one, tool_calls))
            else:
                executed = [_exec_one(tc) for tc in tool_calls]
            for tid, result, name in executed:
                results.append((tid, result))
                if name == "concluir":
                    stop = True
            # responder a TODAS las tool_calls (aunque haya concluir en el medio)
            for tid, result in results:
                messages.append({"role": "tool", "tool_call_id": tid, "content": result})
            if stop:
                final = True
                break
            # compactacion: descartar todo el historial con tool_calls/tool (que exige
            # emparejamiento) y dejar SOLO texto plano valido para la API
            if len(messages) > 30:
                recent = self.runs[-15:]
                resumen = "; ".join(f"{r.get('tool')}({json.dumps(r.get('args') or {})[:60]})" for r in recent)
                last_text = ""
                for m in reversed(messages):
                    if m["role"] == "assistant" and not m.get("tool_calls") and m.get("content"):
                        last_text = m["content"][:800]
                        break
                messages = [messages[0], {"role": "user", "content": (
                    f"[compactacion del historial] Herramientas ejecutadas recientemente: {resumen}. "
                    f"Ultima consideracion del investigador: {last_text}. "
                    f"Los hallazgos ya registrados con hallazgo() persisten. Segui investigando.")}]
        if not final and not self.final_summary:
            self.final_summary = "(el agente cerro sin resumen explicito)"
        # auto-enrich: las entidades aspiradas se enriquecen SOLAS al cierre
        # (hunter verify + emailrep + dorks), sin depender del agente.
        self._auto_enrich_entities()
        try:
            self.save_checkpoint()
        except Exception:
            pass
        return self.final_summary

    def _auto_enrich_entities(self):
        """Al cierre: enriquece las entidades aspiradas (emails/nombres/empresas)
        con hunter verify + emailrep + dorks (canal directo, read-only).
        Limites por corrida: 3 emails, 2 personas, 2 empresas.
        Solo registra finding cuando el dato aporta (breach, perfil, empresa)."""
        try:
            ents = self.entities
            if not (ents.emails or ents.nombres or ents.empresas):
                return
            enr = 0
            for email in sorted(ents.emails)[:3]:
                enr += self._enrich_email(email)
            for nombre in sorted(ents.nombres)[:2]:
                enr += self._enrich_persona(nombre)
            for empresa in sorted(ents.empresas)[:2]:
                enr += self._enrich_empresa(empresa)
            if enr:
                self.findings.add(
                    module="enrich", category="ENRICHMENT", severity="info",
                    confidence="firm",
                    title=f"Auto-enrich: {enr} entidades enriquecidas al cierre",
                    description="Hunter/emailrep/dorks sobre las entidades aspiradas (canal directo, read-only).",
                    asset_key=f"domain:{self.cfg.target}")
        except Exception:
            pass

    def _enrich_email(self, email):
        """Un email aspirado: hunter verify + emailrep + dorks. Devuelve cuantos findings sumo."""
        n = 0
        hv = enrich.hunter_verify(email, timeout=20)
        if hv and hv.get("result") in ("valid", "deliverable", "risky", "accepted") and not hv.get("error"):
            n += 1
            self.findings.add(
                module="enrich", category="EMAIL_ENRICH", severity="info",
                confidence="firm",
                title=f"Email verificado: {email}",
                description=(f"hunter.io: {hv.get('result')} | score {hv.get('score')} | "
                             f"mx_found {hv.get('mx_found')} | smtp {hv.get('smtp_check')} | "
                             f"accept_all {hv.get('accept_all')} | persona: {hv.get('first_name') or ''} "
                             f"{hv.get('last_name') or ''} | posicion: {hv.get('position') or ''} | "
                             f"empresa: {hv.get('company') or ''}"),
                asset_key=f"email:{email}")
        er = enrich.emailrep(email, timeout=20)
        if er and (er.get("breached") or er.get("data_breach")):
            n += 1
            self.findings.add(
                module="enrich", category="EMAIL_BREACH", severity="medium",
                confidence="firm",
                title=f"Email en brecha: {email}",
                description=(f"emailrep.io: reputacion {er.get('reputation')} | breached "
                             f"{er.get('breached')} | data_breach {er.get('data_breach')} | "
                             f"fuentes: {', '.join((er.get('sources') or [])[:4])}"),
                asset_key=f"email:{email}")
        elif er and er.get("deliverable") is not None:
            n += 1
            self.findings.add(
                module="enrich", category="EMAIL_ENRICH", severity="info",
                confidence="firm",
                title=f"Email chequeado: {email}",
                description=(f"emailrep.io: reputacion {er.get('reputation')} | deliverable "
                             f"{er.get('deliverable')} | domain {er.get('domain')}"),
                asset_key=f"email:{email}")
        return n

    def _enrich_persona(self, nombre):
        """Un nombre aspirado: dorks (linkedin/perfiles). Devuelve cuantos findings sumo."""
        res = enrich.search_person(nombre, timeout=30)
        buenos = [r for r in res if "linkedin.com" in (r.get("url") or "")]
        if buenos:
            self.findings.add(
                module="enrich", category="PERSONA_ENRICH", severity="info",
                confidence="firm",
                title=f"Perfil de {nombre} en la web",
                description=("LinkedIn/dork: " + "; ".join(
                    f"{r['title'][:60]} -> {r['url'][:80]}" for r in buenos[:3])),
                asset_key=f"persona:{nombre}")
            return 1
        return 0

    def _enrich_empresa(self, empresa):
        """Una empresa aspirada: dorks (linkedin company / web). Devuelve cuantos findings sumo."""
        res = enrich.search_company(empresa, timeout=30)
        buenos = [r for r in res if "linkedin.com" in (r.get("url") or "")]
        if buenos:
            self.findings.add(
                module="enrich", category="EMPRESA_ENRICH", severity="info",
                confidence="firm",
                title=f"Empresa {empresa} en la web",
                description=("LinkedIn/dork: " + "; ".join(
                    f"{r['title'][:60]} -> {r['url'][:80]}" for r in buenos[:3])),
                asset_key=f"empresa:{empresa}")
            return 1
        return 0


def urllib_quote(s):
    import urllib.parse
    return urllib.parse.quote(s)


def _safe_name(name):
    return "".join(c if c.isalnum() or c in "-._" else "_" for c in name)[:60]