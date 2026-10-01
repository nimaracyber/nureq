"""Salida: consola con colores + reports/<target>_<ts>/ con report.md, findings.jsonl,
assets.json, run-log.jsonl y evidence/."""
import json
import os
import shutil
import time
from datetime import datetime, timezone
from pathlib import Path

C = {
    "reset": "\033[0m", "bold": "\033[1m", "dim": "\033[2m",
    "red": "\033[31m", "green": "\033[32m", "yellow": "\033[33m",
    "blue": "\033[34m", "magenta": "\033[35m", "cyan": "\033[36m", "white": "\033[37m",
}
SEV_COLOR = {"critical": "red", "high": "yellow", "medium": "cyan", "low": "blue", "info": "dim"}
SEV_TAG = {"critical": "CRIT", "high": "HIGH", "medium": "MED", "low": "LOW", "info": "INFO"}


def sev(c, s):
    return f"{C[SEV_COLOR.get(s, 'white')]}{SEV_TAG.get(s, '?')}{C['reset']}"


def banner():
    print(f"{C['bold']}{C['cyan']}  ┌─────────────────────────────────────────────┐")
    print(f"  │  NUREQ — Analizador OSINT inteligente (CLI)       │")
    print(f"  │  Claude-OSINT arsenal + Shodan + DeepSeek v4      │{C['reset']}")
    print(f"  └─────────────────────────────────────────────┘")


def phase(msg):
    print(f"\n{C['bold']}{C['magenta']}▶ {msg}{C['reset']}")


def info(msg):
    print(f"  {C['dim']}· {msg}{C['reset']}")


def ok(msg):
    print(f"  {C['green']}✓ {msg}{C['reset']}")


def warn(msg):
    print(f"  {C['yellow']}! {msg}{C['reset']}")


def result(msg):
    print(f"  {C['bold']}{msg}{C['reset']}")


def print_findings(findings, limit=40):
    items = findings.by_severity()
    if not items:
        info("Sin hallazgos (0).")
        return
    print(f"\n{C['bold']}{C['white']}═══ HALLAZGOS ({len(items)}) ═══{C['reset']}")
    counts = {}
    for f in findings.items:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
    print("  " + " | ".join(f"{SEV_TAG.get(s, s)}:{counts[s]}" for s in
                            ("critical", "high", "medium", "low", "info") if s in counts))
    for f in items[:limit]:
        print(f"  [{sev(f['severity'], f['severity'])}] {f['title']}  {C['dim']}{f['module']}/{f['category']}{C['reset']}")
        ev = f["evidence"]
        if ev.get("url"):
            print(f"      {C['dim']}→ {ev['url']}{C['reset']}")
    if len(items) > limit:
        warn(f"... y {len(items) - limit} hallazgos mas (ver report.md)")


def _safe(name):
    return "".join(c if c.isalnum() or c in "-._" else "_" for c in name)[:80]


def save_report(target, findings, assets, run_log, ai_report, ai_reasoning, out_dir, cfg,
                entities=None):
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%SZ")
    base = out_dir / f"{_safe(target)}_{ts}"
    base.mkdir(parents=True, exist_ok=True)
    evdir = base / "evidence"
    evdir.mkdir(parents=True, exist_ok=True)

    # evidence bodies
    saved = 0
    for f in findings.items:
        raw = f["evidence"].get("raw")
        if raw:
            p = evdir / f"{f['id']}.txt"
            p.write_text(raw[:4096])
            saved += 1

    (base / "findings.jsonl").write_text(findings.to_jsonl())
    (base / "assets.json").write_text(json.dumps(assets, indent=2, ensure_ascii=False))
    (base / "run-log.jsonl").write_text("\n".join(json.dumps(e, ensure_ascii=False) for e in run_log))
    meta = {
        "target": target, "perfil": cfg.perfil, "vpn": cfg.vpn, "ts": ts,
        "tool": "nureq", "findings": findings.count(),
    }
    (base / "meta.json").write_text(json.dumps(meta, indent=2))
    md = f"# Reporte OSINT — {target}\n\n"
    md += f"- Perfil: **{cfg.perfil}** · Fecha UTC: {ts}\n"
    md += f"- Hallazgos: {findings.count()} (evidencia en `findings.jsonl`)\n\n"

    # ---- entidades aspiradas (entregable) ----
    entities_block = ""
    if entities is not None:
        try:
            from .entities import build_schema, schema_mermaid, schema_ascii
            j = entities.save(base, target)
            tot = j["totales"]
            edges = build_schema(entities, target)
            md += ("## Entidades aspiradas\n\n"
                   f"**Emails: {tot['emails']} · Nombres: {tot['nombres']} · Empresas: {tot['empresas']}**\n\n"
                   f"Detalle completo en `entities.json` / `entities.csv`.\n\n")
            d = j["entidades"]
            if d["emails"]:
                md += "### Emails\n"
                for r in d["emails"][:40]:
                    md += f"- `{r['value']}` (x{r['count']}" + (" inferido" if r["inferred"] else "") + \
                          f", fuentes: {', '.join(r['sources'][:3])})\n"
            if d["nombres"]:
                md += "\n### Nombres\n"
                for r in d["nombres"][:40]:
                    md += f"- {r['value']} (x{r['count']}" + (" inferido" if r["inferred"] else "") + \
                          f", fuentes: {', '.join(r['sources'][:3])})\n"
            if d["empresas"]:
                md += "\n### Empresas\n"
                for r in d["empresas"][:30]:
                    md += f"- {r['value']} (x{r['count']}, fuentes: {', '.join(r['sources'][:3])})\n"
            if edges:
                md += "\n### Esquema de relaciones\n\n" + schema_mermaid(edges, target) + "\n"
                md += "\n<details><summary>Esquema ASCII</summary>\n\n```\n" + \
                      schema_ascii(edges, target) + "\n```\n</details>\n"
            entities_block = ("\n### ENTIDADES ASPIRADAS\n"
                              f"<p>Emails: {tot['emails']} · Nombres: {tot['nombres']} · "
                              f"Empresas: {tot['empresas']} (detalle en entities.csv)</p>\n")
        except Exception as e:
            md += f"*(error en entidades: {e})*\n"

    if ai_report:
        md += ai_report + "\n"
    else:
        md += "*(analisis IA desactivado — solo datos crudos)*\n"
    (base / "report.md").write_text(md)
    make_pdf(base, target, findings, md, cfg, meta, entities_block)
    return base


# ---------- PDF (wkhtmltopdf, patron CyberLab) ----------

def _md_to_html(md):
    """MD -> HTML con mini-conversor propio (nunca falla)."""
    import re as _re
    out, in_table, in_code = [], False, False
    esc = lambda s: s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    inl = lambda s: _re.sub(r"\*\*([^*]+)\*\*", r"<b>\1</b>", esc(s))
    for ln in (md or "").splitlines():
        if ln.strip().startswith("```"):
            out.append("</pre>" if in_code else "<pre>")
            in_code = not in_code
            continue
        if in_code:
            out.append(esc(ln))
            continue
        st = ln.strip()
        if st.startswith("|") and st.endswith("|"):
            cells = [inl(c.strip()) for c in st.strip("|").split("|")]
            if all(set(c) <= set(":- ") for c in cells):
                continue
            if not in_table:
                out.append("<table>")
                in_table = True
                out.append("<tr>" + "".join(f"<th>{c}</th>" for c in cells) + "</tr>")
            else:
                out.append("<tr>" + "".join(f"<td>{c}</td>" for c in cells) + "</tr>")
            continue
        if in_table:
            out.append("</table>")
            in_table = False
        m = _re.match(r"^(#{1,4})\s+(.*)$", st)
        if m:
            out.append(f"<h{len(m.group(1)) + 1}>{inl(m.group(2))}</h{len(m.group(1)) + 1}>")
        elif st.startswith(("- ", "* ")):
            out.append(f"<li>{inl(st[2:])}</li>")
        elif st:
            out.append(f"<p>{inl(st)}</p>")
    if in_table:
        out.append("</table>")
    if in_code:
        out.append("</pre>")
    return "\n".join(out)


def make_pdf(base, target, findings, md, cfg, meta, entities_block=""):
    """report.md + findings -> PDF presentable (portada + hallazgos + cadena de custodia)."""
    import subprocess
    base = Path(base)
    pdf_path = base / f"report_{target.replace('/', '_')}.pdf"
    html_path = base / "_report.html"
    sev = {"critical": ("#b91c1c", "CRITICAL"), "high": ("#c2410c", "HIGH"),
           "medium": ("#a16207", "MEDIUM"), "low": ("#2563eb", "LOW"), "info": ("#64748b", "INFO")}
    rows = []
    for f in findings.by_severity():
        col, tag = sev.get(f["severity"], ("#64748b", "INFO"))
        ev = f["evidence"]
        url = ev.get("url") or f.get("asset_key") or ""
        rows.append(
            f"<tr><td style='color:{col};font-weight:800'>{tag}</td>"
            f"<td>{f['title']}</td><td>{f['category']}</td>"
            f"<td>{url}</td><td>{ev.get('sha256','')[:12]}</td></tr>")
    ts = meta.get("ts", "")
    html = f"""<!DOCTYPE html><html><head><meta charset="utf-8"><style>
body{{font-family:'DejaVu Sans',sans-serif;font-size:11px;color:#1a2332;line-height:1.55;margin:40px}}
.cover{{text-align:center;padding-top:110px}}
.brand{{font-size:36px;font-weight:800;letter-spacing:8px;color:#0b3b5e}}
.sub{{font-size:12px;color:#4a5a72;margin-top:4px}}
.cover h1{{font-size:22px;margin:40px 0 24px;color:#111}}
table.meta{{margin:0 auto;border-collapse:collapse;font-size:12px;text-align:left}}
table.meta td{{border:1px solid #c3cede;padding:6px 14px}}
table.meta td:first-child{{background:#eef2f8;font-weight:700;width:170px}}
.conf{{margin-top:60px;display:inline-block;border:2px solid #b91c1c;color:#b91c1c;font-weight:800;
       padding:8px 22px;letter-spacing:2px;font-size:12px}}
.pb{{page-break-before:always}}
h1{{font-size:18px;color:#0b3b5e;border-bottom:2px solid #0b3b5e;padding-bottom:4px}}
h2{{font-size:15px;color:#0b3b5e;margin-top:22px}}
h3,h4{{font-size:12.5px;color:#23456b;margin-top:16px}}
table{{border-collapse:collapse;width:100%;margin:10px 0;font-size:10px}}
th{{background:#0b3b5e;color:#fff;padding:5px 8px;text-align:left}}
td{{border:1px solid #c3cede;padding:5px 8px;vertical-align:top}}
tr:nth-child(even) td{{background:#f4f7fb}}
pre{{background:#0d1526;color:#d7e3f8;padding:10px;border-radius:6px;font-size:9.5px;white-space:pre-wrap}}
li{{margin:3px 0}}
.cust{{margin-top:34px;border:1px solid #8aa0be;background:#f4f7fb;padding:10px 14px;font-size:9.5px;color:#3c4c64}}
</style></head><body>
<div class="cover">
  <div class="brand">NUREQ</div>
  <div class="sub">Investigador OSINT inteligente — Claude-OSINT arsenal + Shodan + DeepSeek v4</div>
  <h1>Reporte de Investigacion OSINT</h1>
  <table class="meta">
    <tr><td>Target</td><td>{target}</td></tr>
    <tr><td>Perfil</td><td>{cfg.perfil}</td></tr>
    <tr><td>Fecha UTC</td><td>{ts}</td></tr>
    <tr><td>Hallazgos</td><td>{findings.count()}</td></tr>
  </table>
  <div class="conf">CONFIDENCIAL — USO AUTORIZADO</div>
</div>
<div class="pb"></div>
<h1>Hallazgos estructurados</h1>
<table><tr><th>Severidad</th><th>Titulo</th><th>Categoria</th><th>Asset / URL</th><th>sha256</th></tr>
{''.join(rows)}
</table>
{entities_block}
<div class="pb"></div>
{_md_to_html(md)}
<div class="cust"><b>Cadena de custodia:</b> findings.jsonl (secretos completos, local) · run-log.jsonl
(todas las acciones del investigador) · evidence/ (bodies crudos con sha256). Generado por el
investigador IA de nureq (deepseek-v4-pro).</div>
</body></html>"""
    try:
        html_path.write_text(html)
        subprocess.run(["wkhtmltopdf", "--enable-local-file-access", "--quiet", "--encoding", "utf-8",
                        "--footer-center", "NUREQ — CONFIDENCIAL — pagina [page] de [topage]",
                        "--footer-font-size", "7", "--footer-spacing", "4",
                        str(html_path), str(pdf_path)],
                       timeout=120, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if pdf_path.exists() and pdf_path.stat().st_size > 2000:
            os.chmod(pdf_path, 0o600)
            try:
                html_path.unlink()
            except Exception:
                pass
            return pdf_path
    except Exception:
        pass
    return None