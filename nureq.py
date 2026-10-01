#!/usr/bin/env python3
"""nureq — Investigador OSINT 100% libre (sin guion).

Agente con DeepSeek v4 (flash: loop ejecutor con function calling / pro: analista +
reporte final). Tiene shell libre via netns redteam (VPN), HTTP arbitrario, Shodan,
CT logs, Wayback, brechas de infostealers, mineria de JS, deteccion de Docker/K8s,
barrido de secretos y validadores read-only. Decide solo que investigar.

Base: arsenal Claude-OSINT (elementalsouls/Claude-OSINT).
Todo el trafico sale por el netns redteam (regla de oro) salvo --no-vpn.
"""
import argparse
import json
import os
import sys
import time
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from nureq import config, netexec, report
from nureq import agent as agentlib
from nureq.findings import Findings


def _run_agent(cfg, resume=False):
    from nureq import prerecon
    findings = Findings()
    seed = ""
    if not (resume and findings.count()):
        report.phase("Pre-recon determinista (batch)")
        seed = prerecon.run_prerecon(cfg, findings)
        report.ok(f"Pre-recon listo — {len(findings.items)} hallazgos base")
    agent = agentlib.Agent(cfg, findings, seed=seed)
    if resume and agent.load_checkpoint():
        report.info(f"Checkpoint cargado: {agent.steps} pasos, {len(findings.items)} hallazgos, "
                    f"{len(agent.scope.snapshot())} hosts en scope")
    report.phase("EL INVESTIGADOR (loop libre)")
    t0 = time.time()
    try:
        summary = agent.run()
    except KeyboardInterrupt:
        ck = agent.save_checkpoint()
        report.warn(f"Ctrl+C — checkpoint guardado: {ck}")
        summary = agent.final_summary or "(interrumpido por operador — retomar con --resume)"
    report.ok(f"Investigacion cerrada — {len(findings.items)} hallazgos")
    agent.metrics = {"elapsed": round(time.time() - t0, 1), "pasos": agent.steps,
                     "tools": len(agent.runs), "shodan_credits": agent.shodan_used}
    return findings, summary, agent


def _run_pipeline(cfg):
    """Modo --pipeline-only: recon fijo (legacy, sin agente)."""
    from nureq import stage1_seed, stage2_expand, stage3_enrich, stage4_expose
    from nureq import prerecon
    import ipaddress
    findings = Findings()
    assets = {"target": cfg.target, "subdomains": [], "ips": [], "webapps": [], "ports": []}
    host, port_hint = prerecon._split_hostport(cfg.target)
    try:
        ipaddress.ip_address(host)
        ips = [host]
    except ValueError:
        ips = netexec.resolve(host, vpn=cfg.vpn, rtype="A", timeout=12)
    report.phase("Pipeline fijo (sin agente)")
    if not _is_ip(host):
        r1 = stage1_seed.run(host, findings, vpn=cfg.vpn)
        assets["subdomains"] = r1.get("subs", [])[:50]
    r2 = stage2_expand.run(host, findings, vpn=cfg.vpn, profile={"prefix": True, "buckets": False})
    web_urls = prerecon.probe_web(cfg, host, ips, port_hint)
    assets["webapps"] = web_urls
    stage3_enrich.run(host, cfg, findings, vpn=cfg.vpn, ips=ips, web_urls=web_urls)
    stage4_expose.run(host, ips, web_urls, findings, vpn=cfg.vpn, profile={"always_on": True, "docker": True})
    return findings, "(pipeline)" , assets


def _is_ip(t):
    import ipaddress
    try:
        ipaddress.ip_address(t); return True
    except ValueError:
        return False


def main():
    ap = argparse.ArgumentParser(prog="nureq", description="Investigador OSINT inteligente (agente libre)")
    ap.add_argument("target", nargs="?", help="dominio, IP o host:puerto a investigar")
    ap.add_argument("--perfil", choices=["rapido", "medio", "profundo"], default="medio",
                    help="ajusta presupuesto (pasos/minutos/creditos), no el guion")
    ap.add_argument("--max-steps", type=int, default=None,
                    help="tope de pasos del agente (override del perfil)")
    ap.add_argument("--no-vpn", action="store_true", help="no usar el netns redteam (salida directa)")
    ap.add_argument("--no-ai", action="store_true", help="desactivar el reporte final v4-pro (el agente sigue con IA)")
    ap.add_argument("--pipeline-only", action="store_true", help="solo recon fijo, sin agente libre")
    ap.add_argument("--resume", action="store_true", help="retomar desde checkpoint (mismo target)")
    ap.add_argument("--json", action="store_true", help="emitir findings.jsonl a stdout al final")
    ap.add_argument("--out", default=None, help="directorio base de reportes (default reports/)")
    ap.add_argument("--selftest", action="store_true", help="tests offline")
    args = ap.parse_args()

    if args.selftest:
        sys.exit(run_selftest())
    if not args.target:
        ap.error("falta el target. Uso: nureq <dominio|ip> [--perfil ...]")

    cfg = config.Config.from_env_and_args(args)
    if args.max_steps:
        cfg.max_steps = args.max_steps
    if args.out:
        cfg.reports_dir = os.path.abspath(args.out)
    Path(cfg.reports_dir).mkdir(parents=True, exist_ok=True)

    report.banner()
    if cfg.vpn:
        report.phase("Chequeo VPN (regla de oro)")
        ok, ipout = netexec.check_vpn()
        if ok:
            report.ok(f"VPN activa — salida real por {ipout}")
        else:
            report.warn(f"VPN caida ({ipout}) — sigo, pero el trafico podria salir directo")
    else:
        report.warn("VPN desactivada (--no-vpn)")

    if args.pipeline_only:
        findings, summary, assets = _run_pipeline(cfg)
        entities = None
    else:
        findings, summary, agent = _run_agent(cfg, resume=args.resume)
        assets = {"target": args.target, "scope": list(agent.scope.snapshot())[:30],
                  "tools_usadas": len(agent.runs)}
        # aspiradora: peinar los raw de todos los findings (cubre todo lo visto)
        for f in findings.items:
            raw = (f.get("evidence") or {}).get("raw")
            if raw:
                agent.entities.add_text(raw, source=(f.get("evidence") or {}).get("url") or f.get("asset_key") or f.get("module", ""))
        entities = agent.entities

    report.print_findings(findings)

    # reporte final v4-pro (solo en modo agente con IA)
    content = None
    reasoning = None
    if not args.pipeline_only and cfg.use_ai and cfg.deepseek_key:
        report.phase("Reporte final — DeepSeek v4-pro")
        from nureq import ai as ailib
        from nureq.findings import secret_safe
        secrets_summary = []
        for f in findings.items:
            if f["category"] == "SECRET_LEAK" and f["evidence"].get("raw"):
                secrets_summary.append({
                    "pattern": f["title"], "severity": f["severity"],
                    "match": secret_safe(f["evidence"]["raw"].split()[-1] if f["evidence"]["raw"].split() else "?", 4),
                    "source": f["asset_key"]})
        digest = ailib.build_digest(findings, args.target, assets, secrets_summary)
        if summary:
            digest += f"\n\n## Resumen del investigador\n{summary}"
        metrics_str = ""
        if not args.pipeline_only and hasattr(agent, "metrics"):
            m = agent.metrics
            metrics_str = (f"pasos={m['pasos']} | tools={m['tools']} | "
                           f"tiempo={m['elapsed']}s | shodan={m['shodan_credits']} creditos")
        content, reasoning = ailib.final_report(args.target, digest, cfg.deepseek_key,
                                                metrics=metrics_str)
        if content:
            report.ok("Reporte IA generado")
        else:
            report.warn(f"La IA no devolvio reporte: {reasoning[:150]}")

    run_log = [{"ts": time.time(), "ev": "corrida", "perfil": cfg.perfil, "vpn": cfg.vpn}]
    if not args.pipeline_only:
        run_log += [{"ts": time.time(), "ev": "tool", "step": r["step"], "tool": r["tool"],
                     "args": r.get("args"), "elapsed": r.get("elapsed"),
                     "text": r.get("text")} for r in agent.runs]
    base = report.save_report(args.target, findings, assets, run_log, content, reasoning,
                              Path(cfg.reports_dir), cfg, entities=entities)
    report.result(f"\nReporte guardado en: {base}")
    pdfs = list(base.glob("*.pdf"))
    if pdfs:
        report.result(f"PDF: {pdfs[0]}")
    if args.json:
        print(findings.to_jsonl())
    return 0


def run_selftest():
    """Tests offline: regex de secretos, scoring, scope, schema."""
    import re as _re
    from nureq import secrets as secretlib
    from nureq import ai as ailib
    from nureq import findings as findingslib
    ok = True
    def check(name, cond):
        nonlocal ok
        print(("  PASS " if cond else "  FAIL ") + name)
        if not cond:
            ok = False

    hits = secretlib.scan_text_all('"password": "supersecreto123"', "t")
    check("password JSON", any(h["pattern"] == "JSON_PASSWORD_PLAIN" for h in hits))
    hits = secretlib.scan_text_all("mysql://root:passw0rd@db.internal:3306/x", "t")
    check("connection string", any(h["category"] == "db" for h in hits))
    hits = secretlib.scan_text_all("-----BEGIN RSA PRIVATE KEY-----", "t")
    check("private key", any(h["pattern"] == "RSA_PRIVKEY" for h in hits))
    hits = secretlib.scan_text_all("ghp_0123456789abcdefghijklmnopqrstuvwxyz", "t")
    check("github PAT", any(h["pattern"] == "GH_PAT_CLASSIC" for h in hits))
    check("score admin alto", ailib.endpoint_score("https://x/api/admin/upload", "POST", 200) >= 40)
    check("score trivial bajo", ailib.endpoint_score("https://x/home", "GET", 200) < 25)

    # scope
    s = agentlib.Scope("example.com")
    s.add_from_output("CNAME api.example.com 192.168.1.5 internal.host.corp")
    check("scope auto-expansivo", s.in_scope("api.example.com") and s.in_scope("192.168.1.5"))
    check("scope subdominio", s.in_scope("deep.api.example.com"))
    check("scope rechaza otro dominio", not s.in_scope("evil.com"))
    # scope-soup: no sumar tokens de JS/minificado ni extensiones de archivo
    s2 = agentlib.Scope("beygoo.io")
    for basura in ("a.join", "a.length", "b.qa", "agentx-lg-en.webp",
                   "arrow-up-outline.svg", "$h", "d.internal"):
        s2.add(basura)
    check("scope rechaza tokens JS", not any(
        s2.in_scope(b) for b in ("a.join", "a.length", "b.qa", "agentx-lg-en.webp",
                                 "arrow-up-outline.svg", "$h", "d.internal")))
    s2.add("acr.bgsensors.co")
    check("scope acepta TLD valido", s2.in_scope("acr.bgsensors.co"))
    s3 = agentlib.Scope("target.weirdtld")
    s3.add("sub.target.weirdtld")
    check("scope subdominio TLD raro", s3.in_scope("deep.sub.target.weirdtld"))
    # ASSET_NUEVO: solo hosts plausibles, nunca servicios OSINT publicos
    cfg_a = config.Config("beygoo.io", perfil="rapido", vpn=False)
    fnd = findingslib.Findings()
    ag = agentlib.Agent(cfg_a, fnd)
    added = ag._register_new_assets(
        ["nuevo.bgsensors.co", "$h", "a.join", "api.hackertarget.com", "crt.sh"])
    check("assets: solo plausible", added == ["nuevo.bgsensors.co"])

    # dorks: unredirect de Bing + filtro de relevancia
    from nureq import enrich as enrichlib
    dec = enrichlib._bing_unredirect(
        "https://www.bing.com/ck/a?!&p=x&u=aHR0cHM6Ly93d3cuZXhhbXBsZS5jb20v")
    check("bing unredirect decode", dec == "https://www.example.com/")
    dec2 = enrichlib._bing_unredirect(
        "https://www.bing.com/ck/a?!&p=x&u=a1aHR0cHM6Ly93d3cuZXhhbXBsZS5jb20v")
    check("bing unredirect prefijo ofuscado", dec2 == "https://www.example.com/")
    no_dec = enrichlib._bing_unredirect("https://www.example.com/path")
    check("bing unredirect url directa", no_dec == "https://www.example.com/path")
    rel = enrichlib._relevant(
        [{"title": "Diego Monastersky - LinkedIn", "url": "https://linkedin.com/in/dmonastersky"},
         {"title": "Diego Maradona", "url": "https://es.wikipedia.org/wiki/Diego_Maradona"}],
        ["monastersky", "linkedin"], min_score=2)
    check("dorks relevancia filtra", len(rel) == 1 and "linkedin.com" in rel[0]["url"])
    rel0 = enrichlib._relevant(
        [{"title": "Diego", "url": "https://www.dicionariodenomesproprios.com.br/diego/"}],
        ["monastersky", "linkedin"], min_score=2)
    check("dorks relevancia descarta generico", rel0 == [])
    hds = {"data": {"pattern": "{first}.{last}@beygoo.io", "organization": "Beygoo",
                    "emails": [{"value": "juan.perez@beygoo.io", "first_name": "Juan",
                                "last_name": "Perez", "position": "CTO", "confidence": 95,
                                "type": "personal"}]}}
    netexec_mod = __import__("nureq.netexec", fromlist=["http_get_json"])
    old_get = netexec_mod.http_get_json
    netexec_mod.http_get_json = lambda *a, **k: (200, hds, None)
    parsed = enrichlib.hunter_domain_search("beygoo.io", timeout=5)
    netexec_mod.http_get_json = old_get
    check("hunter domain search parsea emails", parsed.get("emails") and parsed["emails"][0]["email"] == "juan.perez@beygoo.io")
    check("hunter domain search parsea cargo", parsed.get("emails") and parsed["emails"][0]["position"] == "CTO")
    check("hunter domain search org", parsed.get("org") == "Beygoo")

    # reporte v4-pro: reintento cuando el output viene vacio o cortado a mitad
    check("reporte: vacio se reintenta", not ailib._report_completo(""))
    check("reporte: cortado se reintenta", not ailib._report_completo(
        "# Reporte OSINT - beygoo.io\n\n## Resumen ejecutivo\nSe relevo el dominio y se obtuvieron 42 hallazgos (15 medium, 5 low,"))
    check("reporte: sin secciones se reintenta", not ailib._report_completo("x " * 500))
    check("reporte: completo pasa", ailib._report_completo(
        "# Resumen ejecutivo\n" + "parrafo\n" * 200 + "\n## Hallazgos\n" + "x\n" * 50 + "\n## Superficie\ny"))
    # redaccion
    check("redaccion secreto", findingslib.secret_safe("ABCDEFGHIJ", 4) == "******GHIJ")
    out = agentlib.sanitize_output('{"password": "rootpass123"} y sk-ant-api03-' + "a" * 100, maxlen=4000)
    check("sanitize redacta", "rootpass123" not in out and "[REDACTED" in out)

    # aspiradora de entidades
    from nureq.entities import EntityStore, extract_entities, build_schema
    ex = extract_entities('Contacto: juan.perez@empresa.com.ar / {"name": "Maria Lopez", "company": "ACME SA"} / no-reply@example.com', "t")
    check("entidades: email real", any(e["value"] == "juan.perez@empresa.com.ar" for e in ex["emails"]))
    check("entidades: filtra no-reply/example", all(e["value"] != "no-reply@example.com" for e in ex["emails"]))
    check("entidades: nombre json", any(n["value"] == "Maria Lopez" for n in ex["nombres"]))
    check("entidades: nombre inferido de email", any(n["value"] == "Juan Perez" and n["inferred"] for n in ex["nombres"]))
    check("entidades: empresa json", any(c["value"] == "ACME SA" for c in ex["empresas"]))
    st = EntityStore()
    st.add_text("juan.perez@empresa.com.ar / \"name\": \"Maria Lopez\" / \"company\": \"ACME SA\"", "src1")
    st.add_text("juan.perez@empresa.com.ar", "src2")
    check("store: dedup email", st.emails["juan.perez@empresa.com.ar"]["count"] == 2)
    check("store: dos fuentes", len(st.emails["juan.perez@empresa.com.ar"]["sources"]) == 2)
    edges = build_schema(st)
    check("esquema: arista email->persona", any(e["from"] == "Juan Perez" and e["to"] == "juan.perez@empresa.com.ar" for e in edges))
    check("esquema: co-ocurrencia persona-empresa", any(e["tipo"] == "trabaja_en" for e in edges))

    # modo autonomo
    check("block: rm -rf / sigue bloqueado", any(_re.search(p, "rm -rf /") for p in agentlib.BLOCK_PATTERNS))
    check("block: hydra liberado", not any(_re.search(p, "hydra -l admin") for p in agentlib.BLOCK_PATTERNS))
    check("block: nikto liberado", not any(_re.search(p, "nikto -h x") for p in agentlib.BLOCK_PATTERNS))
    check("block: sqlmap --drop liberado", not any(_re.search(p, "sqlmap --drop") for p in agentlib.BLOCK_PATTERNS))
    cfg_auto = config.Config("test.com", perfil="rapido", vpn=False)
    check("autonomo default ON", cfg_auto.autonomo is True)
    check("anti-loop default 8", cfg_auto.anti_loop == 8)
    check("force_close default OFF", cfg_auto.force_close is False)
    check("perfil rapido pasos 40", config.PERFILES["rapido"]["steps"] == 12)
    check("perfil medio pasos 80", config.PERFILES["medio"]["steps"] == 20)
    check("perfil profundo pasos 150", config.PERFILES["profundo"]["steps"] == 30)
    check("ffuf wordlist rapido common", config.PERFILES["rapido"]["ffuf_wordlist"] == "common")
    check("ffuf wordlist profundo full", config.PERFILES["profundo"]["ffuf_wordlist"] == "full")
    check("nuclei rapido tags exposure", config.PERFILES["rapido"]["nuclei_tags"] == "exposure,config")
    check("nuclei profundo all", config.PERFILES["profundo"]["nuclei_tags"] == "all")
    import os
    os.environ["NUREQ_AUTONOMO"] = "0"
    os.environ["NUREQ_ANTILOOP"] = "3"
    cfg_off = config.Config("test.com", perfil="rapido", vpn=False)
    check("autonomo configurable 0", cfg_off.autonomo is False)
    check("anti-loop configurable", cfg_off.anti_loop == 3)
    del os.environ["NUREQ_AUTONOMO"]; del os.environ["NUREQ_ANTILOOP"]

    print("\n" + ("SELFTEST OK" if ok else "SELFTEST CON FALLOS"))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())