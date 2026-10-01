"""Aspiradora de entidades: extrae emails, nombres completos y empresas de
cualquier texto (outputs del agente, findings raw, bodies), con dedup y
fuente de cada aparicion. Entrega entities.json/csv + esquema de relaciones.

La extraccion es 100% local (sin red). El enriquecimiento (dorks/emailrep/
hunter/cavalier) lo hacen las tools del agente via canal directo.
"""
import json
import re
from datetime import datetime, timezone

# --- regex ---
RE_EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
RE_NAME_JSON = re.compile(r'"(?:name|nombre|full_name|display_name|owner|contact|responsable)"\s*:\s*"([A-Za-zÁ-Úá-úÑñ][A-Za-zÁ-Úá-úÑñ\' .-]{3,60})"', re.I)
RE_NAME_CONTEXT = re.compile(r"\b(?:nombre|name|senor|sr\.?|lic\.?|ing\.?|dr\.?|contacto)[:\s]*([A-Z][a-zÁ-Úá-ú]+(?:\s+[A-Z][a-zÁ-Úá-ú]+){1,3})")
RE_COMPANY_JSON = re.compile(r'"(?:company|empresa|organization|org|organization_name|company_name)"\s*:\s*"([A-Za-z0-9Á-Úá-úÑñ][A-Za-z0-9Á-Úá-úÑñ&.,\' -]{2,60})"', re.I)
RE_COMPANY_CONTEXT = re.compile(r"\b(?:empresa|compañia|compania|organization|company)\s*[:\-]\s*([A-Z][A-Za-z0-9Á-Úá-úÑñ&.,\' -]{2,50})")

# dominios falsos positivos / irrelevantes
SKIP_EMAIL_DOMAINS = {
    "example.com", "example.org", "example.net", "test.com", "domain.com",
    "yourdomain.com", "sentry.io", "local", "localhost", "2x", "png", "jpg",
    "gif", "svg", "css", "js", "wixpress.com", "wordpress.com", "gravatar.com",
}
SKIP_EMAIL_LOCALPARTS = {"no-reply", "noreply", "info", "admin", "support", "test",
                         "user", "mail", "contact", "webmaster", "postmaster",
                         "abuse", "email", "example", "root", "hostmaster"}

SKIP_NAMES = {"", "none", "null", "n/a", "na", "desconocido", "unknown", "test",
              "usuario", "user", "admin", "root", "contacto", "soporte", "info",
              "nombre", "name", "empresa", "company", "the", "de", "la", "el"}

# --- utilidades ---

def _now_utc():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _clean_email(e):
    e = e.strip().strip(".,;:()[]{}<>\"'").lower()
    if e.startswith(("mailto:", "tel:")):
        e = e.split(":", 1)[1]
    return e


def _is_good_email(e):
    m = RE_EMAIL.match(e)
    if not m:
        return False
    local, _, dom = e.partition("@")
    if dom in SKIP_EMAIL_DOMAINS:
        return False
    if local in SKIP_EMAIL_LOCALPARTS or local.startswith(("test", "example", "sample", "foo", "bar")):
        return False
    if len(e) > 90:
        return False
    return True


def _name_from_email(e):
    """juan.perez@x.com -> 'Juan Perez' (candidato, marcado como inferido)."""
    local = e.split("@", 1)[0]
    parts = re.split(r"[._\-+]+", local)
    parts = [p for p in parts if p and not p.isdigit() and len(p) > 1]
    if not parts:
        return None
    good = [p for p in parts if p not in SKIP_EMAIL_LOCALPARTS and not p.startswith(("test", "info"))]
    if len(good) < 2:
        return None
    name = " ".join(p.capitalize() for p in good[:3])
    if len(name) < 6:
        return None
    return name


def _clean_name(n):
    n = n.strip().strip('"\'.,;:')
    return re.sub(r"\s+", " ", n)


def _is_good_name(n):
    if not n or len(n) < 4 or len(n) > 60:
        return False
    if n.lower() in SKIP_NAMES:
        return False
    # requiere al menos 2 palabras con mayuscula inicial (nombre y apellido)
    words = n.split()
    if len(words) < 2:
        return False
    return True


def _is_good_company(c):
    c = c.strip()
    if not c or len(c) < 3 or len(c) > 60:
        return False
    if c.lower() in ("none", "null", "n/a", "unknown", "test", "empresa", "company"):
        return False
    return True


# --- extraccion ---

def extract_entities(text, source=""):
    """Extrae {emails, nombres, empresas} de un texto. Devuelve listas de dicts
    {value, inferred(bool), source}."""
    if not text or len(text) < 5:
        return {"emails": [], "nombres": [], "empresas": []}
    emails, nombres, empresas = [], [], []
    seen = set()
    for m in RE_EMAIL.finditer(text):
        e = _clean_email(m.group(0))
        if not _is_good_email(e) or e in seen:
            continue
        seen.add(e)
        emails.append({"value": e, "inferred": False, "source": source})
        # nombre inferido del email
        n = _name_from_email(e)
        if n and n.lower() not in {x["value"].lower() for x in nombres}:
            nombres.append({"value": n, "inferred": True, "source": source})
    seen_n = set()
    for pat in (RE_NAME_JSON, RE_NAME_CONTEXT):
        for m in pat.finditer(text):
            n = _clean_name(m.group(1))
            if not _is_good_name(n) or n.lower() in seen_n:
                continue
            seen_n.add(n.lower())
            nombres.append({"value": n, "inferred": False, "source": source})
    seen_c = set()
    for pat in (RE_COMPANY_JSON, RE_COMPANY_CONTEXT):
        for m in pat.finditer(text):
            c = _clean_name(m.group(1))
            if not _is_good_company(c) or c.lower() in seen_c:
                continue
            seen_c.add(c.lower())
            empresas.append({"value": c, "inferred": False, "source": source})
    return {"emails": emails[:200], "nombres": nombres[:100], "empresas": empresas[:100]}


# --- store ---

class EntityStore:
    """Dedup + fuentes + conteo. Serializa a JSON/CSV."""

    def __init__(self):
        self.emails = {}   # email -> {sources:set, count, inferred, first, last}
        self.nombres = {}
        self.empresas = {}

    def add(self, entities, source=""):
        for e in entities.get("emails", []):
            d = self.emails.setdefault(e["value"], {"sources": set(), "count": 0,
                                                    "inferred": False, "first": _now_utc(), "last": _now_utc()})
            d["count"] += 1
            if source:
                d["sources"].add(source)
            if e.get("inferred"):
                d["inferred"] = True
        for n in entities.get("nombres", []):
            d = self.nombres.setdefault(n["value"], {"sources": set(), "count": 0,
                                                     "inferred": False, "first": _now_utc(), "last": _now_utc()})
            d["count"] += 1
            if source:
                d["sources"].add(source)
            if n.get("inferred"):
                d["inferred"] = True
        for c in entities.get("empresas", []):
            d = self.empresas.setdefault(c["value"], {"sources": set(), "count": 0,
                                                      "inferred": False, "first": _now_utc(), "last": _now_utc()})
            d["count"] += 1
            if source:
                d["sources"].add(source)
            if c.get("inferred"):
                d["inferred"] = True

    def add_text(self, text, source=""):
        self.add(extract_entities(text, source), source=source)

    def totals(self):
        return {"emails": len(self.emails), "nombres": len(self.nombres),
                "empresas": len(self.empresas)}

    def to_dict(self):
        def rows(d):
            return [{"value": v, "count": i["count"],
                     "inferred": i["inferred"], "sources": sorted(i["sources"])[:10]}
                    for v, i in sorted(d.items(), key=lambda kv: -kv[1]["count"])]
        return {"emails": rows(self.emails), "nombres": rows(self.nombres),
                "empresas": rows(self.empresas)}

    def to_csv(self):
        import io
        buf = io.StringIO()
        buf.write("tipo,valor,apariciones,inferido,fuentes\n")
        for tipo, store in (("email", self.emails), ("nombre", self.nombres), ("empresa", self.empresas)):
            for v, i in sorted(store.items(), key=lambda kv: -kv[1]["count"]):
                buf.write(f'{tipo},"{v}",{i["count"]},{"si" if i["inferred"] else "no"},"{" | ".join(sorted(i["sources"])[:8])}"\n')
        return buf.getvalue()

    def save(self, base_dir, target):
        """Guarda entities.json + entities.csv en base_dir."""
        from pathlib import Path
        base = Path(base_dir)
        j = {"target": target, "ts": _now_utc(), "totales": self.totals(),
             "entidades": self.to_dict()}
        (base / "entities.json").write_text(json.dumps(j, ensure_ascii=False, indent=2))
        (base / "entities.csv").write_text(self.to_csv())
        return j


# --- esquema (relaciones) ---

def build_schema(store, target=""):
    """Arma el esquema de relaciones persona<->mail<->empresa basado en:
    - emails con nombre inferido (juan.perez@ -> Juan Perez)
    - co-ocurrencias dentro de las mismas fuentes (mismo source)
    Devuelve lista de aristas {from, to, type, source}."""
    edges = []
    # 1) email -> persona (nombre inferido de la parte local del email)
    for email, info in store.emails.items():
        nombre = _name_from_email(email)
        if nombre:
            edges.append({"from": nombre, "to": email, "tipo": "mail",
                          "source": "inferido del email"})
    # 2) co-ocurrencia por fuente: persona y empresa vistos en el mismo source
    for source in {s for st in (store.nombres, store.empresas) for i in st.values() for s in i["sources"]}:
        names = [n for n, i in store.nombres.items() if source in i["sources"]]
        comps = [c for c, i in store.empresas.items() if source in i["sources"]]
        for n in names[:4]:
            for c in comps[:4]:
                edges.append({"from": n, "to": c, "tipo": "trabaja_en", "source": source})
    # 3) co-ocurrencia email y empresa por fuente
    for source in {s for st in (store.emails, store.empresas) for i in st.values() for s in i["sources"]}:
        mails = [e for e, i in store.emails.items() if source in i["sources"]]
        comps = [c for c, i in store.empresas.items() if source in i["sources"]]
        for e in mails[:4]:
            for c in comps[:4]:
                edges.append({"from": e, "to": c, "tipo": "pertenece_a", "source": source})
    # dedup de aristas
    seen = set()
    out = []
    for e in edges:
        k = (e["from"].lower(), e["to"].lower(), e["tipo"])
        if k in seen:
            continue
        seen.add(k)
        out.append(e)
    return out[:120]


def schema_mermaid(edges, target=""):
    """Esquema en mermaid (para report.md)."""
    lines = ["```mermaid", "graph LR"]
    if target:
        lines.append(f'    T["{target[:40]}"]')
    nodes = {}
    for e in edges:
        for n in (e["from"], e["to"]):
            if n not in nodes:
                idx = len(nodes) + 1
                nodes[n] = f'N{idx}["{n[:30]}"]'
    for e in edges:
        f = nodes.get(e["from"], e["from"])
        t = nodes.get(e["to"], e["to"])
        lines.append(f"    {f} --{e['tipo']}--> {t}")
    lines.append("```")
    return "\n".join(lines)


def schema_ascii(edges, target=""):
    """Esquema en ASCII (para PDF/report.md si no hay mermaid renderer)."""
    lines = []
    if target:
        lines.append(f"  [TARGET] {target}")
    for e in edges[:40]:
        lines.append(f"  {e['from'][:35]} --{e['tipo']}--> {e['to'][:35]}  [{e['source'][:30]}]")
    return "\n".join(lines)