"""Salida: consola con colores + reports/<target>_<ts>/ con report.md, findings.jsonl,
assets.json, run-log.jsonl y evidence/."""
import json
import os
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
    return base
