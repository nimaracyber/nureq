"""Pre-recon determinista: corre ANTES del agente, todo en batch/paralelo.
Registra findings y devuelve un resumen condensado que se inyecta al agente
como contexto inicial ("ya sabés esto, NO lo repitas").

Por perfil:
- rapido:   DNS+CT+email+RDAP+Shodan+Cavalier+always_on+swagger+graphql+headers
            +js_mine+docker+ffuf(common 60s)+nuclei(exposure,config)
- medio:    + prefix_sweep + wayback + ffuf(common 90s) + nuclei(+misconfig)
- profundo: + ffuf(24k 90s) + nuclei completo
"""
import json
import time
from concurrent.futures import ThreadPoolExecutor

from . import netexec
from . import stage1_seed, stage2_expand, stage3_enrich, stage4_expose

COMMON_WORDLIST = "/opt/wordlists/common.txt"
FULL_WORDLIST = "/opt/wordlists/onelistforallshort-24k.txt"

FFUF_WORDLISTS = {
    "common": COMMON_WORDLIST,
    "full": FULL_WORDLIST,
}


def _is_ip(t):
    import ipaddress
    try:
        ipaddress.ip_address(t)
        return True
    except ValueError:
        return False


def _split_hostport(t):
    if t.startswith(("http://", "https://")):
        return t.split("//")[1].split("/")[0], None
    if ":" in t and t.count(":") == 1:
        h, p = t.rsplit(":", 1)
        if p.isdigit():
            return h, int(p)
    return t, None


def probe_web(cfg, host, ips, port_hint=None):
    """Descubre webapps vivas (https/http) del target y sus IPs."""
    web_urls = []
    if port_hint:
        proto = "https" if port_hint in (443, 8443, 2376) else "http"
        u = f"{proto}://{host}:{port_hint}/" if ":" not in host else f"{proto}://{host}/"
        st, _, _ = netexec.http_get(u, vpn=cfg.vpn, timeout=8)
        if st:
            web_urls.append(u)
        return web_urls
    for h in [host] + (ips or [])[:2]:
        for proto in ("https", "http"):
            u = f"{proto}://{h}/"
            st, _, _ = netexec.http_get(u, vpn=cfg.vpn, timeout=8)
            if st:
                web_urls.append(u)
                break
    return list(dict.fromkeys(web_urls))


def run_prerecon(cfg, findings):
    """Corre el pre-recon completo. Devuelve resumen condensado (string)."""
    t0 = time.time()
    lines = []
    host, port_hint = _split_hostport(cfg.target)
    is_ip = _is_ip(host)

    # ---- DNS / CT / email / RDAP (si no es IP) ----
    subs = []
    ct_ips = {}
    if not is_ip:
        r1 = stage1_seed.run(host, findings, vpn=cfg.vpn)
        subs = r1.get("subs", [])
        ct_ips = r1.get("ips") or {}
        lines.append(f"- DNS catalog + email-security + RDAP + CT multi-fuente: {len(subs)} subdominios")
        if cfg.prefix_sweep_on:
            r2 = stage2_expand.run(host, findings, vpn=cfg.vpn,
                                   profile={"prefix": True, "buckets": False})
            lines.append(f"- Prefix sweep: {len(r2['subs'])} subdominios vivos, "
                         f"{len(r2['takeovers'])} takeovers posibles")
            for h, _ in r2["subs"]:
                subs.append(h)
        # bucket check solo en profundo (barato en paralelo)
        if cfg.perfil == "profundo":
            found = stage2_expand.bucket_permutations(host, findings, vpn=cfg.vpn,
                                                      max_checks=60, rps=cfg.rps)
            if found:
                lines.append(f"- Buckets expuestos: {len(found)}")
    else:
        r1 = {}

    # ---- IPs (DNS + las que trae el CT multi-fuente) ----
    ips = [host] if is_ip else (netexec.resolve(host, vpn=cfg.vpn, rtype="A") or [])
    for il in ct_ips.values():
        for ip in il:
            if ip not in ips:
                ips.append(ip)
    if not ips and not is_ip:
        lines.append("- (sin IPs resueltas)")
    loopback = any(ip.startswith(("127.", "10.201.201.")) for ip in ips)

    # ---- Shodan + Cavalier + Wayback (si no es loopback) ----
    if not loopback:
        for ip in ips[:2]:
            stage3_enrich.shodan_internetdb(ip, findings, vpn=cfg.vpn)
            if cfg.shodan_key:
                stage3_enrich.shodan_host(ip, cfg, findings, vpn=cfg.vpn)
        cav = stage3_enrich.cavalier(host, findings, vpn=cfg.vpn)
        if cav:
            lines.append(f"- Cavalier: {cav.get('employees', 0)} empleados comprometidos, "
                         f"{cav.get('users', 0)} usuarios")
        if cfg.wayback_on:
            n_urls = len(stage3_enrich.wayback_cdx(host, findings, vpn=cfg.vpn, rps=cfg.rps))
            lines.append(f"- Wayback: {n_urls} URLs historicas")

    # ---- webapps vivas ----
    web_urls = probe_web(cfg, host, ips, port_hint)
    if web_urls:
        lines.append(f"- Webapps vivas: {len(web_urls)}")

    # ---- exposicion web (batch) ----
    for u in web_urls[:3]:
        stage4_expose.always_on(u, findings, vpn=cfg.vpn, only_top=(cfg.perfil == "rapido"),
                                rps=cfg.rps)
        stage4_expose.swagger_find(u, findings, vpn=cfg.vpn, rps=cfg.rps)
        stage4_expose.graphql_probe(u, findings, vpn=cfg.vpn, rps=cfg.rps)
        stage4_expose.saml_probe(u, findings, vpn=cfg.vpn)
        stage4_expose.oidc_probe(u, findings, vpn=cfg.vpn)
        stage4_expose.js_mine(u, findings, vpn=cfg.vpn)
        stage4_expose.vendor_fingerprint(u, findings, vpn=cfg.vpn, rps=cfg.rps)
        stage3_enrich.headers_check(u, findings, vpn=cfg.vpn)
    for ip in ips[:2]:
        stage4_expose.docker_probe(ip, findings, vpn=cfg.vpn, rps=cfg.rps)

    # ---- fuzzers (en paralelo entre si) ----
    ffuf_hits = nuclei_hits = 0

    def _ffuf(u):
        wl = FFUF_WORDLISTS.get(cfg.ffuf_wordlist, COMMON_WORDLIST)
        return stage4_expose.ffuf_dirs(u, findings, vpn=cfg.vpn, wordlist=wl,
                                       maxtime=cfg.ffuf_maxtime, rate=cfg.ffuf_rate)

    def _nuclei(u):
        return stage4_expose.nuclei_scan(u, findings, vpn=cfg.vpn, tags=cfg.nuclei_tags)

    if web_urls:
        with ThreadPoolExecutor(max_workers=2) as ex:
            f1 = ex.submit(_ffuf, web_urls[0])
            f2 = ex.submit(_nuclei, web_urls[0])
            try:
                ffuf_hits = len(f1.result(timeout=600))
            except Exception:
                ffuf_hits = 0
            try:
                nuclei_hits = f2.result(timeout=900)
            except Exception:
                nuclei_hits = 0
        if ffuf_hits:
            lines.append(f"- ffuf: {ffuf_hits} paths descubiertos")
        if nuclei_hits:
            lines.append(f"- nuclei: {nuclei_hits} hallazgos")

    elapsed = round(time.time() - t0, 1)
    lines.append(f"- Pre-recon en {elapsed}s")
    summary = "\n".join(lines)
    return summary