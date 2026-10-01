"""Stage 3 — Enriquecimiento (Claude-OSINT §16.4, §16.23, §15.0.1, §16.3):
Shodan (host con cache 7d + InternetDB gratis), Wayback CDX, HudsonRock Cavalier
(infostealers, sin key), y auditoria de headers de seguridad."""
import json
import time

from . import netexec
from .findings import Findings

HIGH_RISK_PORTS = {
    21: ("ftp", "high", "FTP: anon read + creds en claro"),
    23: ("telnet", "high", "Telnet: protocolo en claro, nunca debe estar expuesto"),
    25: ("smtp", "low", "SMTP: banner/version, open relay"),
    53: ("dns", "low", "DNS: recursion = amplificador DDoS"),
    110: ("pop3", "low", "POP3 en claro sin STARTTLS"),
    111: ("rpcbind", "medium", "rpcbind: enumeracion NFS"),
    135: ("msrpc", "high", "MS RPC: enum via impacket"),
    139: ("netbios", "high", "NetBIOS-SSN: file/printer enum"),
    143: ("imap", "low", "IMAP en claro"),
    161: ("snmp", "high", "SNMP: community strings public/private"),
    389: ("ldap", "high", "LDAP: anonymous bind = dump del directorio"),
    445: ("smb", "critical", "SMB: EternalBlue, relay, shares anon"),
    631: ("ipp", "medium", "IPP/CUPS: enum + RCE en CUPS viejo"),
    873: ("rsync", "high", "rsync: modulos listables, backup exposure"),
    1433: ("mssql", "high", "MSSQL: brute + xp_cmdshell"),
    1521: ("oracle", "high", "Oracle TNS: brute + SID enum"),
    2049: ("nfs", "high", "NFS: exports world-readable"),
    2375: ("docker", "critical", "Docker API sin auth = takeover del host"),
    2376: ("docker_tls", "high", "Docker API TLS"),
    2379: ("etcd", "critical", "etcd: estado del cluster + secretos"),
    3000: ("dev", "medium", "Grafana/Express dev con creds default"),
    3306: ("mysql", "high", "MySQL: brute + root:''"),
    3389: ("rdp", "critical", "RDP: BlueKeep/DejaBlue/NLA bypass"),
    5432: ("postgres", "high", "PostgreSQL: brute + postgres:postgres"),
    5601: ("kibana", "high", "Kibana sin auth -> pivot Elasticsearch"),
    5900: ("vnc", "high", "VNC sin auth o password debil"),
    5984: ("couchdb", "high", "CouchDB default sin auth"),
    6379: ("redis", "critical", "Redis sin auth: escribir authorized_keys"),
    7001: ("weblogic", "high", "WebLogic: CVE-2020-14882 etc"),
    8000: ("dev", "medium", "Server de desarrollo"),
    8080: ("http_alt", "medium", "Tomcat/Jenkins/proxy"),
    8443: ("https_alt", "medium", "Tomcat/Jenkins"),
    8888: ("dev", "high", "Jupyter/Dashboard con shell interactivo"),
    9090: ("cockpit", "high", "Cockpit/Prometheus"),
    9200: ("elastic", "critical", "Elasticsearch sin auth"),
    9300: ("elastic_transport", "high", "Elasticsearch transport"),
    11211: ("memcached", "medium", "memcached UDP amp"),
    27017: ("mongodb", "critical", "MongoDB sin auth"),
    10250: ("kubelet", "critical", "kubelet sin auth = pod exec"),
    6443: ("k8s_api", "high", "Kubernetes API"),
    5000: ("registry", "high", "Docker registry / dev server"),
    50070: ("hadoop", "high", "Hadoop NameNode"),
}


def shodan_cache_get(cfg, ip):
    p = cfg.shodan_cache / f"{ip}.json"
    if p.exists():
        try:
            age = time.time() - p.stat().st_mtime
            if age < 7 * 86400:
                return json.loads(p.read_text())
        except Exception:
            pass
    return None


def shodan_cache_put(cfg, ip, data):
    p = cfg.shodan_cache / f"{ip}.json"
    try:
        p.write_text(json.dumps(data))
    except Exception:
        pass


def shodan_host(ip, cfg, findings: Findings, vpn=True):
    """Shodan host lookup (1 query credit, cache 7d)."""
    if not cfg.shodan_key:
        return None
    data = shodan_cache_get(cfg, ip)
    if data is None:
        st, data, _ = netexec.http_get_json(
            f"https://api.shodan.io/shodan/host/{ip}?key={cfg.shodan_key}", vpn=vpn, timeout=20)
        if st != 200 or not data or "error" in data:
            return None
        shodan_cache_put(cfg, ip, data)
    ports = [d.get("port") for d in data.get("data", [])]
    findings.add(
        module="shodan_host", category="ASSET_INFO", severity="info", confidence="firm",
        title=f"Shodan: {ip}",
        description=(f"Org: {data.get('org')} | ASN: {data.get('asn')} | OS: {data.get('os')} | "
                     f"Puertos historicos: {sorted(set(ports))} | Vulns: {list(data.get('vulns') or {})}"),
        asset_key=f"ip:{ip}")
    for port in sorted(set(ports)):
        if port in HIGH_RISK_PORTS:
            svc, sev, why = HIGH_RISK_PORTS[port]
            findings.add(
                module="shodan_host", category="HIGH_RISK_PORT", severity=sev,
                confidence="firm", title=f"Puerto riesgoso {port} ({svc})",
                description=f"Shodan reporta {port} abierto. {why}.",
                asset_key=f"ip:{ip}:{port}")
    return data


def shodan_internetdb(ip, findings: Findings, vpn=True):
    """Shodan InternetDB (gratis, sin credito)."""
    st, data, _ = netexec.http_get_json(f"https://internetdb.shodan.io/{ip}", vpn=vpn, timeout=15)
    if st == 200 and data:
        ports = data.get("ports") or []
        for port in ports:
            if port in HIGH_RISK_PORTS:
                svc, sev, why = HIGH_RISK_PORTS[port]
                findings.add(
                    module="internetdb", category="HIGH_RISK_PORT", severity=sev,
                    confidence="firm", title=f"Puerto riesgoso {port} ({svc})",
                    description=f"InternetDB: {port} abierto. {why}.",
                    asset_key=f"ip:{ip}:{port}")
        for cve in (data.get("vulns") or []):
            findings.add(
                module="internetdb", category="CVE", severity="high", confidence="firm",
                title=f"CVE detectado por Shodan: {cve}",
                description=f"InternetDB asocia {cve} al IP {ip}.",
                asset_key=f"ip:{ip}", references=[cve])
    return data


def wayback_cdx(domain, findings: Findings, vpn=True, max_urls=400, rps=None):
    """Wayback CDX (§16.23): URLs historicas con filtros por extension (batch paralelo)."""
    exts = ["js", "json", "yml", "yaml", "ini", "conf", "php", "asp", "aspx", "jsp",
            "zip", "tar", "gz", "sql", "bak", "env", "log", "txt", "xml"]
    urls = []
    reqs = [{"method": "GET",
             "url": (f"https://web.archive.org/cdx/search/cdx?url={domain}/*.{ext}"
                     f"&output=json&fl=timestamp,original&filter=statuscode:200&collapse=urlkey"
                     f"&limit=80"),
             "timeout": 25} for ext in exts]
    results = netexec.batch_http(reqs, vpn=vpn, workers=10, rps=rps)
    for res in results:
        if res.get("status") != 200:
            continue
        try:
            rows = json.loads(res.get("body") or "[]")
            for row in rows[1:]:
                orig = row[1]
                if orig not in urls:
                    urls.append(orig)
        except Exception:
            pass
        if len(urls) >= max_urls:
            break
    # broad sweep
    if len(urls) < max_urls:
        st, data, body = netexec.http_get(
            f"https://web.archive.org/cdx/search/cdx?url={domain}/*"
            f"&output=json&fl=timestamp,original&filter=statuscode:200&collapse=urlkey"
            f"&limit={max_urls}", vpn=vpn, timeout=30)
        if st == 200:
            try:
                rows = json.loads(body)
                for row in rows[1:]:
                    if row[1] not in urls:
                        urls.append(row[1])
            except Exception:
                pass
    interesting = [u for u in urls if any(k in u for k in
                   ("api", "admin", "config", "backup", "internal", "swagger", "graphql", "env", "token", "auth"))]
    if interesting:
        findings.add(
            module="wayback", category="WAYBACK_URLS", severity="info", confidence="firm",
            title=f"{len(interesting)} URLs historicas interesantes (Wayback)",
            description="\n".join(interesting[:20]),
            asset_key=f"domain:{domain}")
    return urls


def cavalier(domain, findings: Findings, vpn=True):
    """HudsonRock Cavalier (§15.0.1) — gratis, sin key. Severidad por #empleados (§15.1)."""
    st, data, _ = netexec.http_get_json(
        f"https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-domain?domain={domain}",
        vpn=vpn, timeout=30)
    if st != 200 or not data:
        return None
    total = data.get("total") or 0
    employees = data.get("employees") or 0
    users = data.get("users") or 0
    if employees >= 10:
        sev = "critical"
    elif employees >= 1:
        sev = "high"
    elif users >= 1:
        sev = "medium"
    else:
        sev = "info"
    url = data.get("url")
    if employees or users:
        findings.add(
            module="cavalier", category="BREACH_EXPOSURE", severity=sev,
            confidence="firm", title=f"{employees} empleados comprometidos en logs de infostealers",
            description=(f"HudsonRock Cavalier: {employees} cuentas <*>@{domain} y {users} "
                         f"usuarios/visitantes en logs de infostealers (total {total}). "
                         f"Esto alimenta credential-stuffing contra el SSO/correo."),
            asset_key=f"domain:{domain}",
            url=url or f"https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-domain?domain={domain}",
            remediation="Forzar rotacion de passwords + MFA + auditoria de acceso.")
    return data


MISSING_HEADERS = [
    ("Strict-Transport-Security", "medium", "Sin HSTS: las conexiones pueden degradar a HTTP."),
    ("Content-Security-Policy", "medium", "Sin CSP: no hay mitigacion de XSS."),
    ("X-Frame-Options", "low", "Sin X-Frame-Options: clickjacking."),
    ("X-Content-Type-Options", "low", "Sin X-Content-Type-Options: MIME-sniff XSS."),
    ("Referrer-Policy", "info", "Sin Referrer-Policy: fuga de referrer en links."),
    ("Permissions-Policy", "info", "Sin Permissions-Policy: no hay restriccion de features."),
]


def headers_check(url, findings: Findings, vpn=True):
    """Auditoria de headers de seguridad (§16.4)."""
    st, headers, _ = netexec.http_get(url, vpn=vpn, timeout=12)
    if st in (0,):
        return None
    sensitive = any(k in url.lower() for k in ("/login", "/signin", "/sso", "/admin", "/auth"))
    h = {k.lower(): v for k, v in headers.items()}
    for hname, base_sev, why in MISSING_HEADERS:
        if hname.lower() not in h:
            sev = base_sev
            if hname == "Strict-Transport-Security" and sensitive:
                sev = "high"
            findings.add(
                module="headers", category="MISSING_HEADER", severity=sev,
                confidence="firm", title=f"Falta header: {hname}",
                description=f"{url} no envia {hname}. {why}",
                asset_key=f"web:{url}", url=url)
    server = h.get("server")
    if server:
        findings.add(
            module="headers", category="SERVER_BANNER", severity="info", confidence="firm",
            title=f"Server: {server}",
            description=f"Banner del servidor: {server}. Usar para buscar CVEs de esa version.",
            asset_key=f"web:{url}", url=url)
    return headers


def run(domain, cfg, findings: Findings, vpn=True, profile=None, ips=None, web_urls=None):
    pf = (profile or {})
    res = {}
    ips = ips or []
    loopback = any(ip.startswith(("127.", "10.201.201.")) for ip in ips)
    if pf.get("shodan", True) and not loopback:
        for ip in ips[:3]:
            idb = shodan_internetdb(ip, findings, vpn=vpn)
            res["internetdb"] = True
            if cfg.shodan_key:
                shodan_host(ip, cfg, findings, vpn=vpn)
                res["shodan_host"] = True
    if pf.get("cavalier", True) and not loopback:
        cavalier(domain, findings, vpn=vpn)
    if pf.get("wayback", False) and not loopback:
        res["wayback"] = wayback_cdx(domain, findings, vpn=vpn)
    if pf.get("headers", True):
        for u in (web_urls or [])[:10]:
            headers_check(u, findings, vpn=vpn)
    return res