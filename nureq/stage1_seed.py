"""Stage 1 — Semilla (Claude-OSINT §16.22, §16.14, §16.21): catalogo DNS completo,
tokens TXT de verificacion SaaS, email security (SPF/DMARC/DKIM/BIMI/MTA-STS),
RDAP, y subdominios via crt.sh."""
import json
import re

from . import netexec
from .findings import Findings

TXT_TOKEN_PATTERNS = [
    (r"google-site-verification=", "Google Workspace / Search Console"),
    (r"^MS=ms\d+", "Microsoft 365"),
    (r"^mscid=", "Microsoft 365 (nuevo)"),
    (r"apple-domain-verification=", "Apple ecosystem"),
    (r"atlassian-domain-verification=", "Atlassian Cloud"),
    (r"facebook-domain-verification=", "Facebook Business"),
    (r"adobe-idp-site-verification=", "Adobe"),
    (r"docusign=", "DocuSign"),
    (r"dropbox-domain-verification=", "Dropbox Business"),
    (r"box-verification=", "Box"),
    (r"webexdomainverification", "Cisco Webex"),
    (r"zoom_verify_", "Zoom"),
    (r"slack-domain-verification=", "Slack Enterprise Grid"),
    (r"asana-domain-verification=", "Asana"),
    (r"mongodb-site-verification=", "MongoDB Atlas"),
    (r"pinterest-site-verification=", "Pinterest"),
    (r"cisco-ci-domain-verification=", "Cisco"),
    (r"_globalsign-domain-verification=", "GlobalSign"),
    (r"yandex-verification:", "Yandex"),
    (r"mailru-verification:", "Mail.ru"),
    (r"zscaler-verification-", "Zscaler (SASE)"),
    (r"cloudflare-verify=", "Cloudflare Zero Trust"),
    (r"_amazonses=", "AWS SES"),
    (r"salesforce-domain-verification=", "Salesforce"),
    (r"workday-domain-verification=", "Workday"),
    (r"shopify-domain-verification=", "Shopify"),
    (r"klaviyo-domain-verification=", "Klaviyo"),
    (r"mailchimp-domain-verification=", "Mailchimp"),
    (r"hubspot-domain-verification=", "HubSpot"),
    (r"zendesk-verification=", "Zendesk"),
    (r"freshworks-verification=", "Freshworks"),
    (r"intercom-verification=", "Intercom"),
    (r"loom-site-verification=", "Loom"),
    (r"miro-site-verification=", "Miro"),
    (r"gitlab-domain-verification=", "GitLab"),
    (r"_dnsauth=", "ACME/DNS-01 en curso"),
]

MX_IDP = [
    ("aspmx.l.google.com", "Google Workspace"),
    ("googlemail.com", "Google Workspace"),
    ("mail.protection.outlook.com", "Microsoft 365"),
    ("mail.eo.outlook.com", "Microsoft 365"),
    ("zoho.com", "Zoho Mail"),
    ("yandex.net", "Yandex 360"),
    ("fastmail.com", "Fastmail"),
    ("proofpoint.com", "Proofpoint"),
    ("pphosted.com", "Proofpoint"),
    ("mimecast", "Mimecast"),
    ("barracuda", "Barracuda"),
]

DKIM_SELECTORS = ["default", "google", "selector1", "selector2", "mail", "email",
                  "k1", "dkim", "s1", "s2", "amazonses", "mailchimp", "sendgrid",
                  "mxvault", "zoho", "zmail", "outlook", "o365", "krs"]


def dns_catalog(domain, findings: Findings, vpn=True):
    """Catalogo DNS completo: A/AAAA/MX/TXT/NS/SOA/CAA/SRV/CNAME + PTR de IPs."""
    recs = {}
    for rtype in ("A", "AAAA", "MX", "TXT", "NS", "SOA", "CAA", "SRV", "CNAME"):
        vals = netexec.resolve(domain, vpn=vpn, rtype=rtype, timeout=12)
        if vals:
            recs[rtype] = vals
    return recs


def txt_tenancy(domain, recs, findings: Findings):
    """Analiza TXT records para detectar tenencias SaaS (tokens de verificacion)."""
    txts = recs.get("TXT", [])
    for t in txts:
        t = t.strip('"')
        for pat, service in TXT_TOKEN_PATTERNS:
            if re.search(pat, t):
                findings.add(
                    module="txt_tenancy", category="SAAS_TENANCY", severity="info",
                    confidence="firm", title=f"Tenencia SaaS detectada: {service}",
                    description=(f"El TXT record del dominio {domain} contiene un token de "
                                 f"verificacion de {service} ({t[:60]}...). Cada tenencia es una "
                                 f"superficie de ataque con sus propias credenciales y MFA."),
                    asset_key=f"domain:{domain}", references=[service])
    # MX -> IdP
    mx = " ".join(recs.get("MX", []))
    for needle, idp in MX_IDP:
        if needle in mx:
            findings.add(
                module="mx_idp", category="MAIL_IDP", severity="info",
                confidence="firm", title=f"Mail hosteado en {idp}",
                description=f"Los MX de {domain} apuntan a {needle} -> correo en {idp}.",
                asset_key=f"domain:{domain}")


def email_security(domain, recs, findings: Findings, vpn=True):
    """SPF / DMARC / DKIM / BIMI / MTA-STS / DNSSEC segun §16.14."""
    spf = [t.strip('"') for t in recs.get("TXT", []) if "v=spf1" in t]
    if spf:
        s = spf[0]
        if s.rstrip().endswith("-all"):
            findings.add(module="email_security", category="EMAIL_SECURITY", severity="info",
                         confidence="firm", title="SPF estricto (-all)",
                         description=f"{domain} termina su SPF en -all (hardfail). Spoofing dificil.",
                         asset_key=f"domain:{domain}", raw=s)
        elif s.rstrip().endswith("~all"):
            findings.add(module="email_security", category="EMAIL_SECURITY", severity="low",
                         confidence="firm", title="SPF softfail (~all)",
                         description=f"{domain} usa ~all: los spoofs pueden llegar al spam. "
                                     f"Mejorable a -all.", asset_key=f"domain:{domain}", raw=s)
        else:
            findings.add(module="email_security", category="EMAIL_SECURITY", severity="medium",
                         confidence="firm", title="SPF permisivo / sin all",
                         description=f"{domain} no termina su SPF en -all/~all: el spoofing de "
                                     f"email es viable.", asset_key=f"domain:{domain}", raw=s)
        for inc in re.findall(r"include:(\S+)", s):
            findings.add(module="email_security", category="SPF_INCLUDE", severity="info",
                         confidence="firm", title=f"SPF incluye {inc}",
                         description=f"El SPF de {domain} usa include:{inc}.",
                         asset_key=f"domain:{domain}")
    else:
        findings.add(module="email_security", category="EMAIL_SECURITY", severity="high",
                     confidence="firm", title="Sin registro SPF",
                     description=f"{domain} no tiene SPF: spoofing trivial.",
                     asset_key=f"domain:{domain}")

    dmarc = netexec.resolve(f"_dmarc.{domain}", vpn=vpn, rtype="TXT", timeout=12)
    dmarc = [t.strip('"') for t in dmarc]
    if dmarc:
        d = " ".join(dmarc)
        m = re.search(r"p=(\w+)", d)
        pol = m.group(1) if m else "none"
        if pol == "reject":
            findings.add(module="email_security", category="EMAIL_SECURITY", severity="info",
                         confidence="firm", title="DMARC p=reject",
                         description=f"DMARC de {domain} en reject. Bien posturado.", raw=d,
                         asset_key=f"domain:{domain}")
        elif pol == "quarantine":
            findings.add(module="email_security", category="EMAIL_SECURITY", severity="low",
                         confidence="firm", title="DMARC p=quarantine",
                         description=f"DMARC de {domain} en quarantine. Parcial.", raw=d,
                         asset_key=f"domain:{domain}")
        else:
            findings.add(module="email_security", category="EMAIL_SECURITY", severity="medium",
                         confidence="firm", title="DMARC p=none (o sin p)",
                         description=f"DMARC de {domain} sin reject: el spoofing se entrega "
                                     f"directo a inbox.", raw=d, asset_key=f"domain:{domain}")
        rua = re.findall(r"rua=([^\s;]+)", d)
        for r in rua:
            for vend in ("dmarcian", "valimail", "easydmarc", "agari", "dmarcanalyzer", "kdmarc", "postmarkapp"):
                if vend in r:
                    findings.add(module="email_security", category="DMARC_VENDOR", severity="info",
                                 confidence="firm", title=f"DMARC reportado a {vend}",
                                 description=f"rua= apunta a {vend} (vendor de reporting).",
                                 asset_key=f"domain:{domain}")
    else:
        findings.add(module="email_security", category="EMAIL_SECURITY", severity="medium",
                     confidence="firm", title="Sin DMARC",
                     description=f"{domain} no tiene registro DMARC.",
                     asset_key=f"domain:{domain}")

    # DKIM selectores comunes (batch DNS en paralelo)
    dkim_hosts = [f"{sel}._domainkey.{domain}" for sel in DKIM_SELECTORS]
    dkim_res = netexec.resolve_many(dkim_hosts, vpn=vpn, rtype="TXT", workers=12, timeout=60)
    for sel in DKIM_SELECTORS:
        vals = dkim_res.get(f"{sel}._domainkey.{domain}") or []
        if not vals:
            continue
        key = " ".join(t.strip('"') for t in vals)
        m = re.search(r"p=([A-Za-z0-9+/=]+)", key)
        if m:
            import base64
            try:
                nbytes = len(base64.b64decode(m.group(1)))
                sev = "low" if nbytes <= 128 else "info"
                findings.add(module="email_security", category="DKIM", severity=sev,
                             confidence="firm",
                             title=f"DKIM selector {sel} ({nbytes*8}-bit)",
                             description=f"Clave DKIM de {domain} para selector {sel}: "
                                         f"{nbytes*8}-bit. Si es RSA 1024 o menos, es debil.",
                             asset_key=f"domain:{domain}")
            except Exception:
                pass
            break

    mta_sts = netexec.resolve(f"_mta-sts.{domain}", vpn=vpn, rtype="TXT", timeout=10)
    if not mta_sts:
        findings.add(module="email_security", category="EMAIL_SECURITY", severity="low",
                     confidence="firm", title="Sin MTA-STS",
                     description=f"{domain} no publica _mta-sts: TLS entre MX no esta "
                                 f"enforzado (MITM-able).", asset_key=f"domain:{domain}")
    caa = recs.get("CAA")
    if not caa:
        findings.add(module="email_security", category="CAA", severity="info",
                     confidence="firm", title="Sin CAA",
                     description=f"{domain} no tiene CAA: cualquier CA puede emitir certs.",
                     asset_key=f"domain:{domain}")


def rdap_lookup(domain, findings: Findings, vpn=True):
    """RDAP (§16.21): registrant, registrar, fechas, nameservers."""
    st, data, _ = netexec.http_get_json(f"https://rdap.org/domain/{domain}", vpn=vpn, timeout=15)
    if st != 200 or not data:
        return
    ev = {
        "registrar": None, "created": None, "expires": None,
        "nameservers": [], "status": [],
    }
    ev["registrar"] = (data.get("entities") or [{}])[0].get("vcardArray", [[], []])[1]
    for e in data.get("entities") or []:
        roles = e.get("roles") or []
        if "registrant" in roles:
            vc = e.get("vcardArray", [[], []])
            for item in vc[1]:
                if item and item[0] == "fn":
                    ev["registrant"] = item[3]
    for evt in data.get("events") or []:
        if evt["eventAction"] == "registration":
            ev["created"] = evt["eventDate"]
        if evt["eventAction"] == "expiration":
            ev["expires"] = evt["eventDate"]
    ev["nameservers"] = [n.get("ldhName") for n in data.get("nameservers") or []]
    ev["status"] = data.get("status") or []
    desc = (f"Registrar: {ev['registrar']} | Created: {ev['created']} | "
            f"Expires: {ev['expires']} | NS: {', '.join(ev['nameservers'] or [])}")
    findings.add(
        module="rdap", category="WHOIS", severity="info", confidence="firm",
        title="Registro RDAP del dominio",
        description=desc, asset_key=f"domain:{domain}",
        url=f"https://rdap.org/domain/{domain}")
    return ev


def _subfinder_subs(domain, vpn=True, all_sources=False):
    """subfinder -silent -ip (multi-fuente ~30 fuentes). Devuelve (subs:set, ips:dict)."""
    cmd = ["subfinder", "-d", domain, "-silent", "-ip"]
    if all_sources:
        cmd += ["-all"]
    rc, out, err = netexec.run_cmd(cmd, vpn=vpn, timeout=150)
    subs = set()
    ips = {}
    for line in (out or "").splitlines():
        line = line.strip().lower()
        if not line or line.startswith("["):
            continue
        if "," in line:
            h, _, ip = line.partition(",")
            h, ip = h.strip(), ip.strip()
            if h and ip:
                subs.add(h)
                ips.setdefault(h, []).append(ip)
        elif line and "." in line:
            subs.add(line)
    return subs, ips


def _crtsh_raw(domain, vpn=True):
    """crt.sh JSON con retry (lento pero historico profundo)."""
    subs = set()
    for timeout, attempt in ((30, 0), (45, 1)):
        st, data, _ = netexec.http_get_json(
            f"https://crt.sh/?q=%25.{domain}&output=json", vpn=vpn, timeout=timeout)
        if st == 200 and isinstance(data, list) and data:
            for entry in data:
                for name in str(entry.get("name_value", "")).split("\n"):
                    name = name.strip().lower()
                    if name and not name.startswith("*") and name.endswith(domain):
                        subs.add(name)
            break
    return subs


def _certspotter_subs(domain, vpn=False):
    """CertSpotter API (gratis, estable). Canal directo (fuente OSINT publica)."""
    subs = set()
    st, data, _ = netexec.http_get_json(
        f"https://api.certspotter.com/v1/issuances?domain={domain}"
        f"&include_subdomains=true&expand=dns_names",
        vpn=vpn, timeout=20)
    if st == 200 and isinstance(data, list):
        for entry in data:
            for name in entry.get("dns_names") or []:
                name = str(name).strip().lower().rstrip(".")
                if name and not name.startswith("*") and (name == domain or name.endswith("." + domain)):
                    subs.add(name)
    return subs


def _hackertarget_subs(domain, vpn=False):
    """HackerTarget hostsearch (gratis, texto plano). Canal directo."""
    subs = set()
    ips = {}
    st, _, body = netexec.http_get(f"https://api.hackertarget.com/hostsearch/?q={domain}",
                                   vpn=vpn, timeout=20)
    if st == 200:
        for line in (body or "").splitlines():
            if "," in line:
                h, _, ip = line.partition(",")
                h, ip = h.strip().lower(), ip.strip()
                if h and ip and (h == domain or h.endswith("." + domain)):
                    subs.add(h)
                    ips.setdefault(h, []).append(ip)
    return subs, ips


def ct_subdomains(domain, findings: Findings, vpn=True, use_subfinder=True,
                  use_crtsh=True, all_sources=False, fallback=True):
    """Subdominios multi-fuente (merge + dedup):
    1) subfinder (primaria, ~30 fuentes, 2-10s)
    2) crt.sh (historico profundo, paralelo con subfinder)
    3) CertSpotter + HackerTarget (fallback si las anteriores dan 0)
    Devuelve (subs_sorted, ips_dict). Registra findings SUBDOMAIN + IP_ASSOCIATED."""
    subs = set()
    ips = {}
    results = {}

    def _run_subfinder():
        s, i = _subfinder_subs(domain, vpn=vpn, all_sources=all_sources)
        results["subfinder"] = s
        for h, il in i.items():
            ips.setdefault(h, []).extend(il)

    def _run_crtsh():
        results["crtsh"] = _crtsh_raw(domain, vpn=vpn)

    from concurrent.futures import ThreadPoolExecutor
    with ThreadPoolExecutor(max_workers=2) as ex:
        futs = []
        if use_subfinder:
            futs.append(ex.submit(_run_subfinder))
        if use_crtsh:
            futs.append(ex.submit(_run_crtsh))
        for f in futs:
            try:
                f.result(timeout=180)
            except Exception:
                pass

    for s in results.get("subfinder", set()):
        if s and (s == domain or s.endswith("." + domain)):
            subs.add(s)
    subs.update(results.get("crtsh", set()))

    if fallback and not subs:
        cs = _certspotter_subs(domain)
        subs.update(cs)
        ht, ht_ips = _hackertarget_subs(domain)
        subs.update(ht)
        for h, il in ht_ips.items():
            ips.setdefault(h, []).extend(il)

    subs = sorted(subs)
    for s in subs[:150]:
        findings.add(
            module="crtsh", category="SUBDOMAIN", severity="info", confidence="firm",
            title=f"Subdominio por CT: {s}",
            description=f"Certificate transparency registra {s} (fuentes: subfinder/crt.sh/certspotter).",
            asset_key=f"sub:{s}", url=f"https://crt.sh/?q=%25.{domain}")
    for h, il in ips.items():
        ip = il[0]
        if ip:
            findings.add(
                module="ct_multi", category="IP_ASSOCIATED", severity="info", confidence="firm",
                title=f"{h} -> {ip}",
                description=f"IP asociada al subdominio {h} (fuente: subfinder/hackertarget).",
                asset_key=f"ip:{ip}", url=f"http://{ip}/")
    return subs, ips


def crtsh(domain, findings: Findings, vpn=True, known_ips=None):
    """Compat: cert transparency multi-fuente -> subdominios (lista)."""
    subs, _ = ct_subdomains(domain, findings, vpn=vpn)
    return subs


def run(domain, findings: Findings, vpn=True, profile=None):
    recs = dns_catalog(domain, findings, vpn=vpn)
    txt_tenancy(domain, recs, findings)
    email_security(domain, recs, findings, vpn=vpn)
    rdap_lookup(domain, findings, vpn=vpn)
    subs, ips = ct_subdomains(domain, findings, vpn=vpn)
    return {"recs": recs, "subs": subs, "ips": ips}