"""Enriquecimiento de entidades (canal DIRECTO, sin VPN — regla del dueno):
- hunter.io (multi-key round-robin: HUNTER_API_KEY_1..N, free 50 verifs/mes c/u)
- emailrep.io (gratis sin key: reputacion + breach + dominios relacionados)
- dorks en DuckDuckGo HTML + Bing (nombres -> perfiles publicos/empresas)
Todo read-only, con rate limit. Los resultados alimentan EntityStore + findings.
"""
import base64
import html
import json
import re
import threading
import time
import urllib.parse

from . import netexec

_lock = threading.Lock()
_hunter_idx = [0]


def hunter_keys():
    import os
    keys = []
    i = 1
    while True:
        k = os.getenv(f"HUNTER_API_KEY_{i}") or ""
        if not k:
            break
        keys.append(k)
        i += 1
    if keys:
        return keys
    # fallback: cargar del .env directamente (robustez fuera de la API)
    try:
        from .config import load_env
        env = load_env()
        i = 1
        while True:
            k = env.get(f"HUNTER_API_KEY_{i}") or ""
            if not k:
                break
            keys.append(k)
            i += 1
    except Exception:
        pass
    return keys


def _hunter_key():
    """Round-robin entre las keys hunter cargadas."""
    keys = hunter_keys()
    if not keys:
        return None
    with _lock:
        k = keys[_hunter_idx[0] % len(keys)]
        _hunter_idx[0] += 1
    return k


def hunter_verify(email, timeout=15):
    """Verifica un email con hunter.io (1 verificacion del plan free).
    Fallback: si una key falla (error/rate limit/agotada), prueba con la siguiente."""
    keys = hunter_keys()
    if not keys:
        return None
    last_err = ""
    for _ in range(len(keys)):
        key = _hunter_key()
        st, data, _ = netexec.http_get_json(
            f"https://api.hunter.io/v2/email-verifier?email={urllib.parse.quote(email)}&api_key={key}",
            vpn=False, timeout=timeout)
        if st != 200:
            last_err = f"HTTP {st}"
            continue
        if not data or "error" in data:
            last_err = str((data or {}).get("error", "sin data"))
            continue
        d = data.get("data") or {}
        return {
            "status": d.get("status"),
            "result": d.get("result"),
            "score": d.get("score"),
            "disposable": d.get("disposable"),
            "webmail": d.get("webmail"),
            "mx_found": d.get("mx_found"),
            "smtp_check": d.get("smtp_check"),
            "accept_all": d.get("accept_all"),
            "first_name": d.get("first_name"),
            "last_name": d.get("last_name"),
            "position": d.get("position"),
            "company": (d.get("organization") or "").strip() or (d.get("company") or "").strip(),
        }
    return {"error": f"todas las keys hunter fallaron ({last_err})"}


def emailrep(email, timeout=15):
    """emailrep.io: reputacion + breach (gratis, sin key)."""
    st, data, _ = netexec.http_get_json(f"https://emailrep.io/{urllib.parse.quote(email)}",
                                        vpn=False, timeout=timeout,
                                        headers={"User-Agent": "nureq"})
    if st != 200 or not data:
        return None
    return {
        "reputation": data.get("reputation"),
        "breached": data.get("details", {}).get("breached"),
        "data_breach": data.get("details", {}).get("data_breach"),
        "malicious": data.get("details", {}).get("malicious_activity"),
        "domain": data.get("details", {}).get("domain"),
        "deliverable": data.get("details", {}).get("deliverable"),
        "sources": (data.get("details") or {}).get("sources") or [],
    }


def _ddg_html(query, timeout=15, max_results=8):
    """Busqueda en DuckDuckGo HTML (sin key). Devuelve [(title, url, snippet)]."""
    st, _, body = netexec.http_get(
        f"https://html.duckduckgo.com/html/?q={urllib.parse.quote(query)}",
        vpn=False, timeout=timeout, headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:130.0) Gecko/20100101 Firefox/130.0"})
    if st != 200:
        return []
    out = []
    # parse de resultados: <a class="result__a" href="...">title</a> + <a class="result__snippet">
    for m in re.finditer(r'<a[^>]+class="result__a"[^>]+href="([^"]+)"[^>]*>(.*?)</a>', body, re.S):
        url = m.group(1)
        title = re.sub(r"<[^>]+>", "", m.group(2)).strip()
        if url.startswith("//"):
            url = "https:" + url
        out.append({"title": title, "url": url, "snippet": ""})
        if len(out) >= max_results:
            break
    # snippets
    snips = re.findall(r'<a[^>]+class="result__snippet"[^>]*>(.*?)</a>', body, re.S)
    for i, s in enumerate(snips[:max_results]):
        if i < len(out):
            out[i]["snippet"] = re.sub(r"<[^>]+>", "", s).strip()[:200]
    return out


def _bing_html(query, timeout=15, max_results=8):
    """Busqueda en Bing (tolerante a IPs de datacenter).
    Nota: Bing ignora comillas y devuelve redirects /ck/a con el URL real
    en el param `u` (base64 url-safe, HTML-encoded) — se decodifican aca."""
    st, _, body = netexec.http_get(
        f"https://www.bing.com/search?q={urllib.parse.quote(query)}&count={max_results}",
        vpn=False, timeout=timeout, headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36"})
    if st != 200:
        return []
    out = []
    for m in re.finditer(r'<h2[^>]*><a[^>]+href="([^"]+)"[^>]*>(.*?)</a></h2>', body, re.S):
        raw_href = html.unescape(m.group(1))
        url = _bing_unredirect(raw_href)
        title = re.sub(r"<[^>]+>", "", m.group(2)).strip()
        out.append({"title": title, "url": url})
        if len(out) >= max_results:
            break
    return out


def _bing_unredirect(href):
    """Decodifica un redirect de Bing (/ck/a?...&u=<base64>) al URL real.
    El valor de u puede venir con un prefijo ofuscado (ej: a1aHR0cHM6...) —
    se busca el offset del b64 de 'https:' para decodificar desde ahi.
    Si no es redirect, devuelve el href tal cual."""
    if "/ck/a" not in href:
        return href
    m = re.search(r"[?&]u=([^&]+)", href)
    if not m:
        return href
    b64 = m.group(1)
    # Bing antepone basura al b64: buscar el offset donde empieza el URL real
    for start in re.finditer(r"aHR0cHM", b64):
        candidate = b64[start.start():]
        try:
            pad = candidate + "=" * (-len(candidate) % 4)
            dec = base64.urlsafe_b64decode(pad).decode("utf-8", "replace")
            if dec.startswith(("http://", "https://")):
                return dec
        except Exception:
            continue
    return href


def _relevant(results, terms, min_score=1):
    """Filtra resultados de dorks por relevancia: el termino debe aparecer
    en el URL o en el titulo (Bing ignora comillas -> resultados genericos).
    terms: lista de strings lowercase; min_score: cuantos deben matchear."""
    kept = []
    for r in results:
        hay = (r.get("url") or "").lower() + " " + (r.get("title") or "").lower()
        score = sum(1 for t in terms if t in hay)
        if score >= min_score:
            kept.append(r)
    return kept


def dork_search(query, max_results=8, timeout=20):
    """Busca en DDG + Bing, mergea por URL."""
    merged = {}
    for r in _ddg_html(query, timeout=timeout, max_results=max_results):
        if r["url"] and "uddg=" in r["url"]:
            m = re.search(r"uddg=([^&]+)", r["url"])
            r["url"] = urllib.parse.unquote(m.group(1)) if m else r["url"]
        merged[r["url"]] = r
    for r in _bing_html(query, timeout=timeout, max_results=max_results):
        merged.setdefault(r["url"], r)
    return list(merged.values())[:max_results]


def search_person(name, timeout=25):
    """Dorks para un nombre: perfiles publicos + empresa asociada.
    Sin comillas (Bing las ignora) + filtro de relevancia por apellido."""
    parts = [p for p in name.split() if len(p) >= 3]
    terms = [p.lower() for p in parts] + ["linkedin", "twitter", "x.com", "instagram", "facebook"]
    queries = [
        f"{name} linkedin",
        f"{name} perfil linkedin",
        f"{name}",
    ]
    seen = set()
    results = []
    for q in queries[:2]:
        for r in dork_search(q, max_results=8, timeout=timeout):
            if r["url"] in seen:
                continue
            seen.add(r["url"])
            results.append(r)
        if len(results) >= 12:
            break
    return _relevant(results, terms, min_score=2)


def search_email(email, timeout=25):
    """Dorks para un email: de donde sale, a que empresa pertenece."""
    local = email.split("@")[0].lower()
    dom = email.split("@")[-1].lower() if "@" in email else ""
    terms = [t for t in (local, dom) if t]
    results = dork_search(email, max_results=8, timeout=timeout)
    return _relevant(results, terms, min_score=1)


def search_company(company, timeout=25):
    """Dorks para una empresa: sitio, linkedin company, perfiles."""
    terms = [t.lower() for t in company.split() if len(t) >= 3] + ["linkedin"]
    results = dork_search(f'"{company}" (linkedin.com/company OR "sitio oficial" OR "empresa")',
                          max_results=8, timeout=timeout)
    return _relevant(results, terms, min_score=1)


def hunter_domain_search(domain, timeout=25):
    """Hunter Domain Search: emails de empleados del dominio (value + nombre/cargo).
    Multi-key round-robin como hunter_verify. Plan free: ~25 searches/mes por key,
    hasta 10 emails por resultado (limit=10; limit mayor da error de paginacion).
    Devuelve {emails: [...], pattern, org} o {"error": ...}."""
    keys = hunter_keys()
    if not keys:
        return {"error": "sin keys hunter"}
    last_err = ""
    for _ in range(len(keys)):
        key = _hunter_key()
        st, data, _ = netexec.http_get_json(
            f"https://api.hunter.io/v2/domain-search?domain={urllib.parse.quote(domain)}"
            f"&api_key={key}&limit=10",
            vpn=False, timeout=timeout)
        if st != 200:
            last_err = f"HTTP {st}"
            continue
        if not data or "error" in data or "errors" in data:
            last_err = str((data or {}).get("error") or (data or {}).get("errors", "sin data"))
            continue
        d = data.get("data") or {}
        emails = []
        for e in (d.get("emails") or [])[:10]:
            emails.append({
                "email": e.get("value"),
                "first_name": e.get("first_name"),
                "last_name": e.get("last_name"),
                "position": e.get("position"),
                "confidence": e.get("confidence"),
                "type": e.get("type"),
            })
        return {"emails": emails, "pattern": d.get("pattern"),
                "org": d.get("organization") or ""}
    return {"error": f"todas las keys hunter fallaron ({last_err})"}


def linkedin_company(slug, timeout=30):
    """Datos publicos de una pagina de LinkedIn company (fetch DIRECTO, sin VPN).
    La pagina principal responde 200 sin login (334KB tipico); el JSON-LD trae
    nombre/descripcion/empleados y el texto visible lo peina la aspiradora.
    Fallback: r.jina.ai si LinkedIn bloquea (999/403)."""
    ua = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                        "(KHTML, like Gecko) Chrome/126.0 Safari/537.36"}
    st, _, body = netexec.http_get(
        f"https://www.linkedin.com/company/{urllib.parse.quote(slug)}/",
        vpn=False, timeout=timeout, headers=ua)
    if st != 200:
        # fallback: r.jina.ai (proxy de texto publico)
        st2, _, body2 = netexec.http_get(
            f"https://r.jina.ai/https://www.linkedin.com/company/{urllib.parse.quote(slug)}/",
            vpn=False, timeout=timeout, headers=ua)
        if st2 != 200:
            return {"error": f"linkedin HTTP {st} / r.jina.ai HTTP {st2}"}
        body = body2
    # JSON-LD (Organization): nombre, descripcion, empleados, url
    meta = {}
    for m in re.finditer(r'<script[^>]+type="application/ld\+json"[^>]*>(.*?)</script>', body, re.S):
        try:
            data = json.loads(m.group(1))
        except Exception:
            continue
        if isinstance(data, dict) and data.get("@type") in ("Organization", "Corporation", "ProfessionalService"):
            meta = data
            break
    texto_plano = re.sub(r"<script.*?</script>|<style.*?</style>", " ", body, flags=re.S)
    texto_plano = re.sub(r"<[^>]+>", " ", texto_plano)
    texto_plano = html.unescape(re.sub(r"\s+", " ", texto_plano)).strip()[:6000]
    out = {"chars": len(body), "texto": texto_plano}
    if meta:
        out["nombre"] = meta.get("name")
        out["descripcion"] = (meta.get("description") or "")[:300]
        out["url"] = meta.get("url")
        out["empleados"] = meta.get("numberOfEmployees") or meta.get("interactionStatistic")
    return out