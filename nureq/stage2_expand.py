"""Stage 2 — Expansion de superficie (Claude-OSINT §16.24, §16.12, §16.8):
prefix sweep de subdominios, deteccion de subdomain takeover (27 fingerprints)
y permutacion de cloud buckets (S3/GCS/Azure)."""
import re

from . import netexec
from .findings import Findings

PREFIXES = """www mail webmail smtp imap pop owa autodiscover ftp sftp vpn sslvpn gateway gp
globalprotect citrix fortinet anyconnect api app apps mobile m portal login sso idp iam
identity accounts oauth auth adfs admin manage console dashboard cp cpanel intranet
internal hr payroll finance sap erp crm helpdesk servicedesk support help kb status
monitoring grafana kibana prometheus docs wiki confluence jira bitbucket gitlab jenkins
sonar nexus git svn repo code dev test staging stg qa uat sandbox preprod preview demo
careers jobs vacancies recruit eapps shop store ecommerce checkout payments pay billing
old legacy archive backup beta v1 v2 classic cdn static assets media img files downloads
public ns ns1 ns2 dns mx mx1 mx2 zoom teams slack lync sip voice meet tender tenders
suppliers vendor vendors procurement purchase proxy secure ssl mail2 webmail2 web2 test2
intranet2 hr2 remote workspace cloud""".split()

TAKEOVER_FINGERPRINTS = [
    ("github.io", "github.io", "There isn't a GitHub Pages site here", "github"),
    ("herokuapp.com", "herokuapp.com", "No such app", "heroku"),
    ("s3.amazonaws.com", "amazonaws.com", "NoSuchBucket", "aws_s3"),
    ("cloudfront.net", "cloudfront.net", "Bad request", "aws_cloudfront"),
    ("azurewebsites.net", "azurewebsites.net", "404 Web Site not found", "azure"),
    ("azurefd.net", "azurefd.net", "404", "azure_frontdoor"),
    ("blob.core.windows.net", "blob.core.windows.net", "The specified container does not exist", "azure"),
    ("cloudapp.net", "cloudapp.net", "no web apps", "azure"),
    ("trafficmanager.net", "trafficmanager.net", "404", "azure"),
    ("myshopify.com", "myshopify.com", "Sorry, this shop is currently unavailable", "shopify"),
    ("squarespace.com", "squarespace.com", "No Such Account", "squarespace"),
    ("tumblr.com", "tumblr.com", "Whatever you were looking for doesn't currently exist", "tumblr"),
    ("wordpress.com", "wordpress.com", "Do you want to register", "wordpress"),
    ("pantheonsite.io", "pantheonsite.io", "The gods are wise", "pantheon"),
    ("surge.sh", "surge.sh", "project not found", "surge"),
    ("bitbucket.io", "bitbucket.io", "Repository not found", "bitbucket"),
    ("tilda.ws", "tilda.ws", "Please renew your subscription", "tilda"),
    ("s.strikinglydns.com", "strikinglydns.com", "PAGE NOT FOUND", "strikingly"),
    ("smartling.com", "smartling.com", "Domain is not configured", "smartling"),
    ("ngrok.io", "ngrok.io", "Tunnel not found", "ngrok"),
    ("webflow.io", "webflow.io", "Site not found", "webflow"),
    ("zendesk.com", "zendesk.com", "Help Center Closed", "zendesk"),
    ("statuspage.io", "statuspage.io", "Not found", "statuspage"),
    ("netlify.app", "netlify.app", "Not Found", "netlify"),
    ("vercel.app", "vercel.app", "404", "vercel"),
    ("pages.dev", "pages.dev", "404", "cloudflare_pages"),
    ("ghost.io", "ghost.io", "Domain is not configured", "ghost"),
]

BUCKET_PREFIXES = ["", "backup-", "assets-", "static-", "dev-", "prod-", "test-", "media-", "data-", "files-"]
BUCKET_SUFFIXES = ["", "-backup", "-assets", "-static", "-media", "-data", "-uploads", "-dev",
                   "-prod", "-staging", "-logs", "-private", "-public", "-dump", "-archive",
                   "-files", "-images", "-docs"]


def _dom_stems(domain):
    base = domain.split(".")[0]
    stems = [base, domain]
    for extra in ("prod", "dev", "staging", "test", "demo"):
        stems.append(f"{base}-{extra}")
    return stems


def prefix_sweep(domain, findings: Findings, vpn=True, rps=None):
    """Resuelve ~120 prefijos via DNS en paralelo (1 subprocess, §16.24)."""
    live = []
    hosts = [f"{p}.{domain}" for p in PREFIXES]
    res = netexec.resolve_many(hosts, vpn=vpn, rtype="A", workers=24, timeout=90)
    for host, ips in res.items():
        if ips:
            live.append((host, ips[0]))
            findings.add(
                module="prefix_sweep", category="SUBDOMAIN", severity="info",
                confidence="firm", title=f"Subdominio vivo: {host}",
                description=f"{host} -> {ips[0]}",
                asset_key=f"sub:{host}")
    return live


def takeover_check(subdomains, findings: Findings, vpn=True):
    """Para cada subdomain resuelto, chequea CNAME + signature del proveedor (§16.12)."""
    results = []
    for host, ip in subdomains:
        cnames = netexec.resolve(host, vpn=vpn, rtype="CNAME", timeout=8)
        cname = cnames[0] if cnames else ""
        for provider, needle, sig, brand in TAKEOVER_FINGERPRINTS:
            if needle in cname:
                st, h, body = netexec.http_get(f"http://{host}/", vpn=vpn, timeout=10)
                if sig.lower() in body.lower() or st in (404, 400):
                    results.append((host, provider))
                    findings.add(
                        module="takeover", category="SUBDOMAIN_TAKEOVER", severity="high",
                        confidence="firm",
                        title=f"Subdomain takeover posible: {host} ({brand})",
                        description=(f"{host} apunta via CNAME a {cname} y el proveedor devuelve "
                                     f"'{sig}' (signature de recurso sin reclamar). Se puede "
                                     f"tomar el host para phishing/credential harvesting."),
                        asset_key=f"sub:{host}",
                        url=f"http://{host}/", remediation="Reclamar o borrar el CNAME huerfano.")
    return results


def bucket_permutations(domain, findings: Findings, vpn=True, max_checks=90, rps=None):
    """S3/GCS/Azure: HEAD en paralelo -> existe -> GET listado (§16.8)."""
    stems = _dom_stems(domain)
    candidates = []
    for s in stems:
        for pre in BUCKET_PREFIXES:
            for suf in BUCKET_SUFFIXES:
                candidates.append(f"{pre}{s}{suf}")
    candidates = list(dict.fromkeys(candidates))[:max_checks]
    found = []
    targets = [("s3", lambda c: f"https://{c}.s3.amazonaws.com/"),
               ("gcs", lambda c: f"https://{c}.storage.googleapis.com/"),
               ("azure", lambda c: f"https://{c}.blob.core.windows.net/")]
    reqs = []
    meta = []
    for cand in candidates:
        for brand, urlf in targets:
            reqs.append({"method": "HEAD", "url": urlf(cand), "timeout": 8})
            meta.append((cand, brand, urlf(cand)))
    res_all = netexec.batch_http(reqs, vpn=vpn, workers=20, rps=rps)
    for (cand, brand, url), res in zip(meta, res_all):
        st = res.get("status")
        if st in (200, 301, 403):
            found.append((cand, brand, st, url))
            if st in (200, 301):
                st2, _, body = netexec.http_get(url, vpn=vpn, timeout=10)
                listable = False
                if brand == "s3" and ("<ListBucketResult" in body or "<Key>" in body):
                    listable = True
                if brand == "gcs" and ("<ListBucketResult" in body or "<Key>" in body):
                    listable = True
                if brand == "azure" and "<EnumerationResults" in body:
                    listable = True
                sev = "critical" if listable else "high"
                findings.add(
                    module="bucket", category="PUBLIC_CLOUD_BUCKET",
                    severity=sev, confidence="firm",
                    title=f"Bucket {brand} expuesto: {cand}",
                    description=(f"{cand}.{url.split('//')[1].split('/')[0]} devuelve "
                                 f"HTTP {st2}" + (" y permite LISTAR objetos (datos publicos)."
                                 if listable else " (existe, sin listado).")),
                    asset_key=f"bucket:{cand}", url=url,
                    remediation="Restringir acceso publico al bucket y rotar cualquier credencial expuesta.")
    return found


def run(domain, findings: Findings, vpn=True, profile=None):
    pf = (profile or {})
    res = {"subs": [], "takeovers": [], "buckets": []}
    if pf.get("prefix", True):
        res["subs"] = prefix_sweep(domain, findings, vpn=vpn)
        res["takeovers"] = takeover_check(res["subs"], findings, vpn=vpn)
    if pf.get("buckets", False):
        res["buckets"] = bucket_permutations(domain, findings, vpn=vpn)
    return res