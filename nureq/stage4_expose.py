"""Stage 4 — Analisis de exposicion (Claude-OSINT §16.5, §16.1, §16.2, §16.6, §16.9-16.11,
§16.18, §16.16, §16.19): always-on checks, swagger/graphql/saml/oidc, JS mining,
Docker/K8s/registry exposure, vendor fingerprints, y en profundo ffuf+nuclei."""
import json
import re
import urllib.parse

from . import netexec
from .findings import Findings
from . import secrets as secretlib

# --- Always-on HTTP checks (§16.5) ---
ALWAYS_ON = [
    ("/.git/config", "critical", "git_config", r"\[core\]|\[remote|repositoryformatversion",
     "Repositorio .git expuesto: se puede clonar TODO el codigo fuente."),
    ("/.git/HEAD", "high", "git_head", r"^ref:\s",
     "HEAD del repo .git accesible (filtracion de codigo)."),
    ("/.env", "critical", "env_file", r"^\s*[A-Z_][A-Z0-9_]*\s*=",
     "Archivo .env expuesto con variables de entorno (posibles credenciales)."),
    ("/.env.backup", "high", "env_backup", r"^\s*[A-Z_][A-Z0-9_]*\s*=",
     "Backup de .env expuesto."),
    ("/.env.old", "high", "env_backup", r"^\s*[A-Z_][A-Z0-9_]*\s*=",
     "Backup de .env expuesto."),
    ("/.git-credentials", "critical", "git_credentials", r"https?://",
     "Credenciales git en claro expuestas."),
    ("/server-status", "medium", "apache_status", r"Apache Server Status",
     "Apache server-status: expone requests activos, IPs internas y endpoints."),
    ("/server-info", "medium", "apache_info", r"Apache Server Information",
     "Apache mod_info expuesto."),
    ("/.DS_Store", "low", "ds_store", None,
     "Archivo .DS_Store expuesto (metadata de archivos)."),
    ("/phpinfo.php", "high", "phpinfo", r"phpinfo\(\)|PHP Version",
     "phpinfo() expuesto: configuracion completa de PHP + extensiones."),
    ("/info.php", "high", "phpinfo", r"phpinfo\(\)|PHP Version",
     "phpinfo() expuesto (path alternativo)."),
    ("/actuator/env", "critical", "spring_actuator", r'"propertySources"|systemProperties|systemEnvironment',
     "Spring Boot /actuator/env expuesto: variables de entorno + secretos."),
    ("/actuator/heapdump", "critical", "spring_heapdump", None,
     "Spring Boot heapdump: puede contener passwords y tokens en memoria (archivo HPROF)."),
    ("/actuator/health", "medium", "spring_actuator", r'"status"\s*:\s*"(UP|DOWN)"',
     "Spring Boot actuator health expuesto (info de estado del app)."),
    ("/_cat/indices", "high", "elasticsearch", r"(?:index|status|health)",
     "Elasticsearch abierto: lista indices (datos del cluster)."),
    ("/console", "high", "jenkins", r"Jenkins|Script Console|Groovy",
     "Consola Jenkins accesible (RCE si no hay auth)."),
    ("/manager/html", "high", "tomcat", r"Tomcat Web Application Manager",
     "Tomcat Manager expuesto (deploy de WARs si hay creds)."),
    ("/adminer.php", "high", "adminer", r"Adminer|Login",
     "Adminer (admin de DB) expuesto: acceso a la base."),
    ("/phpmyadmin/", "high", "phpmyadmin", r"phpMyAdmin",
     "phpMyAdmin expuesto."),
    ("/wp-admin/install.php", "low", "wordpress", r"WordPress Installation",
     "Instalador de WordPress huerfano."),
    ("/Dockerfile", "medium", "dockerfile", r"FROM\s+\S+",
     "Dockerfile expuesto (revela imagen y build)."),
    ("/docker-compose.yml", "high", "docker_compose", r"services:|image:",
     "docker-compose.yml expuesto: revela servicios, puertos y a veces secretos."),
    ("/.dockerenv", "medium", "docker_env", r"",
     "Presencia de .dockerenv: el app corre dentro de un contenedor."),
    ("/config.json", "high", "config_file", r"(?i)password|passwd|pwd|api[_-]?key|secret|token",
     "Archivo de configuracion JSON expuesto con credenciales."),
    ("/settings.json", "high", "config_file", r"(?i)password|passwd|pwd|api[_-]?key|secret|token",
     "Archivo de configuracion JSON expuesto con credenciales."),
    ("/appsettings.json", "high", "config_file", r"(?i)password|passwd|pwd|api[_-]?key|secret|token",
     "appsettings.json expuesto (credenciales de .NET)."),
    ("/application.properties", "high", "config_file", r"(?i)password|passwd|pwd|secret|token",
     "Configuracion Spring expuesta."),
    ("/wp-config.php", "critical", "config_file", r"(?i)DB_PASSWORD|DB_USER|define\(",
     "wp-config.php expuesto: credenciales de la base."),
    ("/config.php", "high", "config_file", r"(?i)password|passwd|pwd|db_pass|secret",
     "Archivo PHP de configuracion expuesto."),
    ("/db.php", "high", "config_file", r"(?i)password|passwd|pwd|mysqli|pg_connect",
     "Configuracion de base de datos expuesta."),
    ("/configuration.json", "high", "config_file", r"(?i)password|passwd|pwd|secret|token",
     "Archivo de configuracion JSON expuesto."),
    ("/.well-known/security.txt", "info", "security_txt", None,
     "security.txt: contacto de divulgacion (INFO)."),
]

SWAGGER_PATHS = [
    "swagger.json", "swagger.yaml", "swagger/v1/swagger.json", "swagger/v2/swagger.json",
    "swagger-ui.html", "swagger-ui/", "swagger-resources", "api-docs", "api-docs.json",
    "api/swagger", "api/swagger.json", "api/swagger-ui.html", "api/v1/swagger.json",
    "api/v2/swagger.json", "api/v3/api-docs", "v2/api-docs", "v3/api-docs", "openapi.json",
    "openapi.yaml", "openapi/v1", "openapi/v3", "docs", "redoc", "rapidoc", "api/docs",
    "api/documentation", ".well-known/openapi",
]

GRAPHQL_PATHS = [
    "graphql", "graphiql", "api/graphql", "v1/graphql", "v2/graphql", "query",
    "api/query", "gql", "altair", "playground", "subscriptions", "graphql/console",
    "api/v1/graphql",
]

SAML_PATHS = [
    "/saml/metadata", "/FederationMetadata/2007-06/FederationMetadata.xml",
    "/federationmetadata/2007-06/federationmetadata.xml",
    "/simplesaml/saml2/idp/metadata.php", "/auth/saml2/metadata",
]

JS_GUESS = ["/main.js", "/app.js", "/bundle.js", "/runtime.js", "/index.js", "/vendor.js",
            "/_next/static/_buildManifest.js", "/_next/static/_ssgManifest.js",
            "/static/js/main.js", "/static/js/bundle.js", "/assets/index.js"]

RE_TIER1 = re.compile(r"""['"`](/[A-Za-z0-9_\-./{}\[\]?=&%:]+)['"`]""")
RE_TIER2 = re.compile(r"""['"`](/(?:api|graphql|gql|v\d+|swagger|openapi|rest|services|internal|admin|auth|oauth|user|users|account|accounts|search|export|upload|file|files|download|webhook|hooks|callback)[A-Za-z0-9_\-./{}\[\]?=&%:]*)['"`]""")
RE_TIER3 = re.compile(r"\bhttps?://[A-Za-z0-9.\-]+\.[A-Za-z]{2,}(?::\d+)?[/A-Za-z0-9_\-./{}\[\]?=&%:#]*")
RE_RFC1918 = re.compile(r"\b(?:10\.(?:\d{1,3}\.){2}\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.(?:\d{1,3})\.(?:\d{1,3})|192\.168\.(?:\d{1,3})\.(?:\d{1,3})|127\.(?:\d{1,3}\.){2}\d{1,3})\b")
RE_INTERNAL_DNS = re.compile(r"\b[A-Za-z0-9][A-Za-z0-9\-]{0,62}\.(?:internal|corp|lan|intranet|local|prod|staging|dev|qa)\b")
RE_K8S_SVC = re.compile(r"\b[A-Za-z0-9\-]+\.[A-Za-z0-9\-]+\.svc(?:\.cluster\.local)?\b")

VENDOR_PATHS = {
    "Citrix NetScaler": (["/vpn/index.html", "/logon/LogonPoint/tmindex.html", "/citrix/"], r"(?i)NetScaler|Citrix"),
    "F5 BIG-IP": (["/tmui/login.jsp", "/mgmt/tm/sys/"], r"(?i)BIG-IP|F5"),
    "Pulse/Ivanti": (["/dana-na/", "/dana-na/auth/url_default/welcome.cgi", "/api/v1/"], r"(?i)Pulse|Ivanti|dana-na"),
    "FortiGate": (["/remote/login", "/remote/info", "/api/v2/"], r"(?i)Forti(?:Gate|OS)"),
    "PaloAlto GlobalProtect": (["/global-protect/", "/global-protect/portal/css/login.css", "/api/?type=keygen"], r"(?i)GlobalProtect|PAN-OS|PaloAlto"),
    "VMware vCenter": (["/ui/", "/sdk", "/websso/SAML2/"], r"(?i)VMware vCenter|vSphere Client"),
    "VMware ESXi": (["/ui/", "/folder", "/sdk"], r"(?i)VMware ESXi|vSphere"),
    "Exchange OWA": (["/owa/", "/ews/exchange.asmx", "/ecp/"], r"(?i)Outlook Web App|Exchange"),
    "Confluence": (["/confluence/", "/login.action", "/rest/api/space"], r"(?i)Confluence"),
    "Jira": (["/secure/Dashboard.jspa", "/rest/api/2/serverInfo"], r"(?i)Jira"),
    "GitLab": (["/users/sign_in", "/-/oauth/applications", "/help"], r"(?i)GitLab"),
    "Jenkins": (["/login", "/asynchPeople/", "/api/json"], r"(?i)Jenkins"),
    "Grafana": (["/login", "/api/health"], r"(?i)Grafana"),
    "Kibana": (["/app/kibana", "/api/status"], r"(?i)Kibana"),
    "Zoho ManageEngine": (["/RestAPI/Login", "/api/json/v2/"], r"(?i)ManageEngine"),
    "SonarQube": (["/api/server/version", "/about"], r"(?i)SonarQube"),
    "TeamCity": (["/login.html", "/admin/admin.html"], r"(?i)TeamCity"),
    "Argo CD": (["/api/version", "/applications"], r"(?i)Argo CD"),
    "Keycloak": (["/realms/master", "/auth/realms/master"], r"(?i)Keycloak"),
    "WordPress": (["/wp-login.php", "/wp-json/"], r"(?i)WordPress"),
}

INTROSPECTION = ('{"operationName":"IntrospectionQuery","query":"query IntrospectionQuery { __schema { types { name kind fields { name type { name kind } } queryType { name } mutationType { name } subscriptionType { name } } } }"}')


def _norm_base(url):
    return url.rstrip("/")


def netloc_of(url):
    m = re.match(r"https?://([^/\s:]+)", url or "")
    return m.group(1) if m else ""


def always_on(url, findings: Findings, vpn=True, only_top=False, rps=None):
    """§16.5 always-on checks sobre un webapp vivo (paralelo, 1 batch por netns)."""
    base = _norm_base(url)
    hits = []
    paths = [(p, sev, cat, match_re, why) for p, sev, cat, match_re, why in ALWAYS_ON
             if not (only_top and sev in ("low", "info"))]
    reqs = [{"method": "GET", "url": base + p, "timeout": 8} for p, *_ in paths]
    results = netexec.batch_http(reqs, vpn=vpn, workers=16, rps=rps)
    for (path, sev, cat, match_re, why), res in zip(paths, results):
        st, body = res.get("status"), res.get("body") or ""
        if st == 0:
            continue
        full = base + path
        if st in (200, 204):
            matched = True
            if match_re:
                matched = bool(re.search(match_re, body, re.M))
            if matched:
                hits.append((full, sev, cat, body))
                findings.add(
                    module="always_on", category=cat.upper(), severity=sev,
                    confidence="firm", title=f"Exposicion: {path}",
                    description=why, asset_key=f"web:{base}",
                    url=full, raw=body[:1500],
                    remediation=("Sacar el archivo/endpoint de la raiz publica y restringir "
                                 "acceso."))
        elif path == "/manager/html" and st == 401:
            findings.add(
                module="always_on", category="TOMCAT", severity="medium",
                confidence="firm", title="Tomcat Manager presente (auth-gated)",
                description="Tomcat Manager existe pero pide credenciales (defaults comunes: "
                            "tomcat:tomcat).", asset_key=f"web:{base}", url=full)
    return hits


def swagger_find(url, findings: Findings, vpn=True, rps=None):
    """§16.1 swagger/openapi discovery + parse (paralelo, 1 batch)."""
    base = _norm_base(url)
    import yaml
    reqs = [{"method": "GET", "url": f"{base}/{p}", "timeout": 8} for p in SWAGGER_PATHS]
    results = netexec.batch_http(reqs, vpn=vpn, workers=12, rps=rps)
    for path, res in zip(SWAGGER_PATHS, results):
        st, body = res.get("status"), res.get("body") or ""
        if st != 200 or len(body) < 40:
            continue
        full = f"{base}/{path}"
        data = None
        if path.endswith((".json",)) or body.lstrip().startswith("{"):
            try:
                data = json.loads(body)
            except Exception:
                data = None
        else:
            try:
                data = yaml.safe_load(body)
            except Exception:
                data = None
        if data and isinstance(data, dict) and ("paths" in data or "swagger" in data or "openapi" in data):
            npaths = len(data.get("paths") or {})
            methods = []
            for p, ops in (data.get("paths") or {}).items():
                for m in ops:
                    if m.lower() in ("get", "post", "put", "delete", "patch", "head", "options"):
                        methods.append(f"{m.upper()} {p}")
            findings.add(
                module="swagger", category="LEAKY_API_SPEC", severity="high",
                confidence="confirmed", title=f"Spec OpenAPI/Swagger expuesta: {path}",
                description=(f"{npaths} endpoints documentados sin auth. La especificacion "
                             f"revela la superficie completa de la API."),
                asset_key=f"api_spec:{full}", url=full,
                raw="\n".join(methods[:15]), remediation="Sacar la spec del acceso publico.")
            return data
    return None


def graphql_probe(url, findings: Findings, vpn=True, rps=None):
    """§16.2 graphql discovery + introspection (batch: 1 GET por path + POST introspection)."""
    base = _norm_base(url)
    reqs = [{"method": "GET", "url": f"{base}/{p}", "timeout": 6} for p in GRAPHQL_PATHS]
    results = netexec.batch_http(reqs, vpn=vpn, workers=8, rps=rps)
    for path, res in zip(GRAPHQL_PATHS, results):
        st = res.get("status")
        if st in (0, 404, 405):
            continue
        full = f"{base}/{path}"
        # introspection
        st, headers, body = netexec.http_post(full, data=INTROSPECTION,
                                              headers={"Content-Type": "application/json"},
                                              vpn=vpn, timeout=12)
        if st == 200:
            try:
                d = json.loads(body)
                types = (d.get("data") or {}).get("__schema", {}).get("types") or []
                if types:
                    names = sorted({t.get("name") for t in types if t.get("name") and not t["name"].startswith("__")})
                    findings.add(
                        module="graphql", category="OPEN_GRAPHQL_API", severity="high",
                        confidence="confirmed", title=f"GraphQL con introspection abierta: {path}",
                        description=f"El schema de GraphQL esta expuesto sin auth: {len(names)} tipos.",
                        asset_key=f"graphql_schema:{full}", url=full,
                        raw=", ".join(names[:20]),
                        remediation="Desactivar introspection en produccion y agregar auth.")
                    return names
            except Exception:
                pass
    return None


def saml_probe(url, findings: Findings, vpn=True):
    base = _norm_base(url)
    for path in SAML_PATHS:
        full = base + path
        st, _, body = netexec.http_get(full, vpn=vpn, timeout=8)
        if st == 200 and "EntityDescriptor" in body:
            findings.add(
                module="saml", category="SAML_METADATA", severity="medium",
                confidence="firm", title=f"Metadata SAML accesible: {path}",
                description="La metadata SAML revela EntityID, certs de firma y URLs SSO. "
                            "Puede habilitar pivot de cert-reuse.", asset_key=f"web:{base}",
                url=full, remediation="Restringir acceso a la metadata SAML.")


def oidc_probe(url, findings: Findings, vpn=True):
    base = _norm_base(url)
    full = f"{base}/.well-known/openid-configuration"
    st, data, _ = netexec.http_get_json(full, vpn=vpn, timeout=10)
    if st == 200 and data and "issuer" in data:
        issuer = data.get("issuer", "")
        prod = "desconocido"
        if "auth0.com" in issuer: prod = "Auth0"
        elif "onelogin.com" in issuer: prod = "OneLogin"
        elif "pingone.com" in issuer or "pingidentity.com" in issuer: prod = "Ping"
        elif "duosecurity.com" in issuer: prod = "Duo"
        elif "/realms/" in issuer: prod = "Keycloak"
        elif "login.microsoftonline.com" in issuer: prod = "Microsoft Entra"
        elif "accounts.google.com" in issuer: prod = "Google Workspace"
        dev_endpoint = data.get("device_authorization_endpoint")
        findings.add(
            module="oidc", category="IDENTITY_FABRIC", severity="info",
            confidence="firm", title=f"OIDC discovery: {prod}",
            description=f"Endpoint OIDC en {full}. Issuer: {issuer}. "
                        f"{'Admite device-code flow (phishing viable)' if dev_endpoint else ''}",
            asset_key=f"idp:{issuer}", url=full,
            remediation=("Restringir device-code flow si no se usa.") if dev_endpoint else "")
        return data
    return None


def js_mine(url, findings: Findings, vpn=True, max_js=15):
    """§16.9-16.11: JS endpoint extraction + internal hosts + secrets + sourcemaps."""
    base = _norm_base(url)
    st, _, body = netexec.http_get(base + "/", vpn=vpn, timeout=12)
    if st == 0:
        return {}
    js_urls = set()
    for m in re.finditer(r'<script[^>]+src=["\']([^"\']+)["\']', body):
        src = m.group(1)
        if src.startswith("http"):
            js_urls.add(src)
        else:
            js_urls.add(urllib.parse.urljoin(base + "/", src))
    for gp in JS_GUESS:
        js_urls.add(base + gp)
    js_urls = [u for u in js_urls if u.startswith(("http://", "https://"))][:max_js]
    endpoints = set()
    internal = set()
    secret_hits = []
    for js in js_urls:
        st2, _, jbody = netexec.http_get(js, vpn=vpn, timeout=12)
        if st2 != 200 or len(jbody) > 1024 * 1024:
            continue
        for m in RE_TIER2.finditer(jbody):
            endpoints.add(m.group(1))
        for m in RE_TIER1.finditer(jbody):
            p = m.group(1)
            if len(p) > 3 and not p.endswith((".css", ".png", ".jpg", ".svg", ".woff", ".gif", ".ico")):
                endpoints.add(p)
        for m in RE_TIER3.finditer(jbody):
            endpoints.add(m.group(0))
        for m in RE_RFC1918.finditer(jbody):
            internal.add(f"IP:{m.group(0)}")
        for m in RE_INTERNAL_DNS.finditer(jbody):
            internal.add(f"DNS:{m.group(0)}")
        for m in RE_K8S_SVC.finditer(jbody):
            internal.add(f"K8S:{m.group(0)}")
        hits = secretlib.scan_text_all(jbody, source=js)
        for h in hits[:10]:
            secret_hits.append({**h, "url": js})
        # sourcemap
        if js.endswith(".js"):
            st3, _, mbody = netexec.http_get(js + ".map", vpn=vpn, timeout=10)
            if st3 == 200 and len(mbody) > 50:
                try:
                    mp = json.loads(mbody)
                    for src_content in (mp.get("sourcesContent") or [])[:20]:
                        if src_content:
                            for m2 in RE_TIER2.finditer(src_content):
                                endpoints.add(m2.group(1))
                            for h2 in secretlib.scan_text_all(src_content, source=js + ".map")[:5]:
                                secret_hits.append({**h2, "url": js + ".map"})
                except Exception:
                    pass
    api_endpoints = sorted({e for e in endpoints
                            if re.search(r"/api/|graphql|v\d+|auth|admin|user|token|upload|export", e)
                            and (e.startswith("/") or netloc_of(e) in base or "static/" in e)})[:60]
    if api_endpoints:
        findings.add(
            module="js_mine", category="API_ENDPOINT", severity="medium",
            confidence="firm", title=f"{len(api_endpoints)} endpoints API/JS descubiertos",
            description="Endpoints extraidos de JS (linkfinder tier2/3).",
            asset_key=f"web:{base}", url=base, raw="\n".join(api_endpoints[:30]))
    if internal:
        findings.add(
            module="js_mine", category="INFO_DISCLOSURE", severity="medium",
            confidence="firm", title=f"{len(internal)} hosts internos filtrados en JS",
            description="IPs/hostnames internos expuestos en JS: sirven como seed de recon interno.",
            asset_key=f"web:{base}", url=base, raw="\n".join(sorted(internal)[:20]))
    return {"endpoints": api_endpoints, "internal": sorted(internal), "secrets": secret_hits,
            "js_urls": list(js_urls)}


DOCKER_PROBES = [
    ("docker_api", 2375, "http", "/version", "critical", "Docker API sin auth: /version accesible"),
    ("docker_api", 2375, "http", "/containers/json?all=1", "critical", "Docker API: lista contenedores"),
    ("docker_api_tls", 2376, "https", "/version", "high", "Docker API TLS (validar cert)"),
    ("etcd", 2379, "http", "/version", "critical", "etcd accesible: estado del cluster + secretos"),
    ("etcd_v2", 2379, "http", "/v2/keys/", "critical", "etcd v2 keys accesible"),
    ("k8s_api", 6443, "https", "/api", "high", "Kubernetes API server"),
    ("k8s_api", 8443, "https", "/api", "high", "Kubernetes API server (8443)"),
    ("kubelet", 10250, "https", "/pods", "critical", "kubelet sin auth: pod exec/leak"),
    ("kubelet_ro", 10255, "http", "/pods", "high", "kubelet read-only"),
    ("registry", 5000, "http", "/v2/_catalog", "high", "Docker registry v2: catalogo de imagenes"),
    ("registry", 5000, "http", "/v2/", "high", "Docker registry v2"),
    ("tiller", 44134, "http", "/", "high", "Helm Tiller expuesto (cluster-admin)"),
]


def docker_probe(ip, findings: Findings, vpn=True, known_ports=None, rps=None):
    """§16.18 Container/K8s exposure: Docker API, etcd, kubelet, registry, k8s (batch)."""
    known_ports = known_ports or []
    results = []
    reqs = [{"method": "GET", "url": f"{scheme}://{ip}:{port}{path}", "timeout": 6}
            for name, port, scheme, path, sev, why in DOCKER_PROBES]
    res_all = netexec.batch_http(reqs, vpn=vpn, workers=10, rps=rps)
    for (name, port, scheme, path, sev, why), res in zip(DOCKER_PROBES, res_all):
        st, body = res.get("status"), res.get("body") or ""
        if st in (0,):
            continue
        url = f"{scheme}://{ip}:{port}{path}"
        interesting = False
        if st in (200, 401, 403):
            interesting = True
        if name == "docker_api" and path == "/version" and st == 200 and "ApiVersion" in body:
            findings.add(
                module="docker_probe", category="DOCKER_EXPOSED", severity="critical",
                confidence="confirmed", title=f"Docker API expuesta en {ip}:{port}",
                description=why + f" Respuesta: {body[:200]}",
                asset_key=f"ip:{ip}:{port}", url=url, raw=body[:500],
                remediation="No exponer el daemon Docker a la red; usar TLS + auth.")
            results.append(url)
            continue
        if name == "docker_api" and path.startswith("/containers") and st == 200:
            try:
                conts = json.loads(body)
                findings.add(
                    module="docker_probe", category="DOCKER_EXPOSED", severity="critical",
                    confidence="confirmed", title=f"Docker: {len(conts)} contenedores visibles",
                    description="Se puede listar contenedores sin auth: takeover total del host.",
                    asset_key=f"ip:{ip}:{port}", url=url, raw=body[:800],
                    remediation="Cerrar el socket Docker.")
                results.append(url)
                continue
            except Exception:
                pass
        if name == "etcd" and st == 200 and ("etcdserver" in res.get("headers", {}).get("server", "").lower() or "etcd" in body.lower()):
            findings.add(
                module="docker_probe", category="ETCD_EXPOSED", severity="critical",
                confidence="confirmed", title=f"etcd accesible en {ip}:{port}",
                description=why, asset_key=f"ip:{ip}:{port}", url=url, raw=body[:500],
                remediation="Restringir etcd con auth TLS + firewall.")
            results.append(url)
            continue
        if name == "kubelet" and st == 200 and "items" in body:
            findings.add(
                module="docker_probe", category="KUBELET_EXPOSED", severity="critical",
                confidence="confirmed", title=f"kubelet sin auth en {ip}:{port}",
                description=why, asset_key=f"ip:{ip}:{port}", url=url, raw=body[:500],
                remediation="Habilitar auth en kubelet.")
            results.append(url)
            continue
        if name == "registry" and st == 200 and "repositories" in body:
            findings.add(
                module="docker_probe", category="REGISTRY_EXPOSED", severity="high",
                confidence="confirmed", title=f"Docker registry abierto en {ip}:{port}",
                description="Se lista el catalogo de imagenes sin auth.",
                asset_key=f"ip:{ip}:{port}", url=url, raw=body[:500],
                remediation="Poner auth en el registry.")
            results.append(url)
            continue
        if name == "k8s_api" and st == 200:
            findings.add(
                module="docker_probe", category="K8S_EXPOSED", severity="high",
                confidence="confirmed", title=f"Kubernetes API accesible en {ip}:{port}",
                description="El API server responde 200 sin auth.",
                asset_key=f"ip:{ip}:{port}", url=url, raw=body[:300],
                remediation="Configurar RBAC + authn.")
            results.append(url)
    return results


def vendor_fingerprint(url, findings: Findings, vpn=True, rps=None):
    """Fingerprint de productos (batch). Solo declara producto si el body matchea
    el fingerprint real del vendor (evita falsos positivos de cualquier 200/401/302)."""
    base = _norm_base(url)
    reqs = []
    pairs = []
    for product, (paths, match_re) in VENDOR_PATHS.items():
        for path in paths[:2]:
            reqs.append({"method": "GET", "url": base + path, "timeout": 6})
            pairs.append((product, path, match_re))
    results = netexec.batch_http(reqs, vpn=vpn, workers=14, rps=rps)
    seen = set()
    for (product, path, match_re), res in zip(pairs, results):
        if product in seen:
            continue
        st, body = res.get("status"), res.get("body") or ""
        if st == 0:
            continue
        full = base + path
        mr = re.compile(match_re) if isinstance(match_re, str) else match_re
        matched = mr and bool(mr.search(body))
        if matched:
            findings.add(
                module="vendor", category="VENDOR_PRODUCT", severity="info",
                confidence="firm", title=f"Producto detectado: {product}",
                description=f"{product} responde en {path} (HTTP {st}). Revisar CVEs conocidos.",
                asset_key=f"web:{base}", url=full)
            seen.add(product)
            break


def ffuf_dirs(base_url, findings: Findings, vpn=True, wordlist="/opt/wordlists/onelistforallshort-24k.txt",
              maxtime=240, rate=300):
    from . import netexec as ne
    import os
    import tempfile
    wordlist = wordlist if os.path.exists(wordlist) else "/opt/wordlists/common.txt"
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tf:
        outfile = tf.name
    cmd = ["ffuf", "-u", f"{base_url}/FUZZ", "-w", wordlist, "-mc", "200,204,301,302,307,401,403",
           "-t", "40", "-maxtime", str(maxtime), "-rate", str(rate), "-o", outfile,
           "-of", "json", "-s"]
    try:
        rc, out, err = ne.run_cmd(cmd, vpn=vpn, timeout=maxtime + 40)
    finally:
        pass
    hits = []
    try:
        data = json.loads(open(outfile).read())
        for r in data.get("results", []):
            hits.append((r.get("url"), r.get("status"), r.get("length")))
    except Exception:
        pass
    finally:
        try:
            os.unlink(outfile)
        except Exception:
            pass
    for hurl, hst, hlen in hits[:50]:
        findings.add(
            module="ffuf", category="CONTENT_DISCOVERY", severity="info",
            confidence="firm", title=f"Path descubierto: {hurl}",
            description=f"ffuf: HTTP {hst} len={hlen}. Revisar contenido.",
            asset_key=f"web:{base_url}", url=hurl)
    return hits


def nuclei_scan(url, findings: Findings, vpn=True, tags=None, severity="high,critical"):
    from . import netexec as ne
    cmd = ["nuclei", "-u", url, "-severity", severity, "-silent", "-no-color",
           "-timeout", "8", "-stats", "-disable-update-check"]
    if tags and tags != "all":
        cmd += ["-tags", tags]
    rc, out, err = ne.run_cmd(cmd, vpn=vpn, timeout=280)
    hits = 0
    for line in out.splitlines():
        if "] [" in line:
            hits += 1
            findings.add(
                module="nuclei", category="NUCLEI", severity="high", confidence="firm",
                title=line[:200], description=line[:300],
                asset_key=f"web:{url}", url=url)
    return hits


def run(domain, ips, web_urls, findings: Findings, vpn=True, profile=None):
    pf = (profile or {})
    res = {}
    if pf.get("always_on", True):
        for u in (web_urls or [])[:5]:
            res["always_on"] = always_on(u, findings, vpn=vpn, only_top=(not pf.get("always_full", False)))
    if pf.get("swagger", False):
        for u in (web_urls or [])[:3]:
            res["swagger"] = swagger_find(u, findings, vpn=vpn)
    if pf.get("graphql", False):
        for u in (web_urls or [])[:3]:
            res["graphql"] = graphql_probe(u, findings, vpn=vpn)
            saml_probe(u, findings, vpn=vpn)
            oidc_probe(u, findings, vpn=vpn)
    if pf.get("js", False):
        for u in (web_urls or [])[:3]:
            res["js"] = js_mine(u, findings, vpn=vpn)
    if pf.get("docker", True):
        for ip in ips[:3]:
            res["docker"] = docker_probe(ip, findings, vpn=vpn)
    if pf.get("vendor", False):
        for u in (web_urls or [])[:2]:
            vendor_fingerprint(u, findings, vpn=vpn)
    if pf.get("ffuf", False) and web_urls:
        res["ffuf"] = ffuf_dirs(web_urls[0], findings, vpn=vpn)
    if pf.get("nuclei", False) and web_urls:
        res["nuclei"] = nuclei_scan(web_urls[0], findings, vpn=vpn)
    return res