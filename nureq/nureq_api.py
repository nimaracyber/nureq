"""nureq-api — API REST de OSINT por URL (agente IA, una sola consulta por página).

Contrato (V4, 01/10/2026):
- IA OBLIGATORIA con key DEL CLIENTE: se configura una vez con PUT /api-key
  (se valida contra DeepSeek y queda guardada en disco 600). La key del .env
  del servidor NO se usa nunca en la API.
- POST /consulta {"target": "url|dominio|ip|host:puerto", "fresca": bool}
    -> 202 {job_id} (corrida en background, estado en /corridas/<id>)
    -> 400 si no hay key del cliente configurada
    -> SIEMPRE perfil profundo (único; rapido/medio se coer con aviso)
    -> SIEMPRE sin VPN (--no-vpn; la API no usa netns)
    -> ?sincrono=1: espera y devuelve el resultado completo en la misma llamada
    -> 429 si ya hay NUREQ_API_MAXJOBS corridas en paralelo
    -> si existe reporte profundo del mismo target < NUREQ_API_CACHE_TTL -> responde cache
- GET /corridas (últimas 20) · GET /corridas/<id> (estado + resultado completo)
- GET /corridas/<id>/report (markdown) · POST /corridas/<id>/link (link temporal sin Bearer)
- GET/PUT/DELETE /api-key (Bearer) — estado enmascarado / guardar validada / borrar
- SIN PDF: la API devuelve DATA (JSON + report.md); el PDF final lo arma el cliente.
- GET /health (sin auth)
- Auth: SOLO Authorization: Bearer <NUREQ_API_TOKEN> (nada de ?key=, queda en logs).
- Jobs persistidos en cache/api_jobs/<id>.json (sobrevivientes a restart).
- Levantar:  python3 -m nureq.nureq_api   (0.0.0.0:9998, NUREQ_API_PORT)
"""
import hashlib
import hmac
import json
import os
import re
import secrets
import subprocess
import sys
import threading
import time
import uuid
from pathlib import Path
from urllib.parse import urlparse

from flask import Flask, jsonify, request

from . import config

BASE_DIR = Path(__file__).resolve().parent.parent
app = Flask(__name__)

# --- env: cargar .env a os.environ (deepseek, etc.) ---
env = config.load_env()
for k, v in env.items():
    os.environ.setdefault(k, v)

PORT = int(os.getenv("NUREQ_API_PORT") or 9998)
RATE_LIMIT = int(os.getenv("NUREQ_API_RATE") or 20)          # consultas/min
MAX_JOBS = int(os.getenv("NUREQ_API_MAXJOBS") or 2)          # corridas simultáneas
CACHE_TTL = int(os.getenv("NUREQ_API_CACHE_TTL") or 86400)   # 24h
DL_TTL = int(os.getenv("NUREQ_API_DL_TTL") or 3600)          # links de descarga (s)

JOBS_DIR = BASE_DIR / "cache" / "api_jobs"
JOBS = {}
JOBS_LOCK = threading.Lock()
RL = []  # ventana de rate limit (separada de JOBS)


# --- token (autogenerado si no existe) ---
def _get_token():
    tok = os.getenv("NUREQ_API_TOKEN", "")
    if tok:
        return tok
    tok = secrets.token_urlsafe(32)
    try:
        with (BASE_DIR / ".env").open("a") as f:
            f.write(f"\nNUREQ_API_TOKEN={tok}\n")
        os.environ["NUREQ_API_TOKEN"] = tok
    except Exception:
        pass
    return tok


API_TOKEN = _get_token()

# --- key del cliente (BYOK): guardada aparte, nunca en el repo ni en logs ---
KEY_FILE = BASE_DIR / "cache" / "client_deepseek_key.json"
VALIDATE_URL = os.getenv("NUREQ_API_VALIDATE_URL") or "https://api.deepseek.com/models"


def _load_client_key():
    try:
        return json.loads(KEY_FILE.read_text()).get("api_key") or ""
    except Exception:
        return ""


def _save_client_key(key):
    KEY_FILE.parent.mkdir(parents=True, exist_ok=True)
    KEY_FILE.write_text(json.dumps({"api_key": key, "actualizada": time.time()}))
    os.chmod(KEY_FILE, 0o600)
    try:
        os.chmod(KEY_FILE.parent, 0o700)
    except Exception:
        pass


def _mask_key(k):
    return f"...{k[-4:]}" if k and len(k) >= 8 else ("(set)" if k else "")


def _validate_deepseek_key(key):
    """Valida la key del cliente contra DeepSeek (GET /models). True/False + error."""
    if not key or not key.startswith("sk-"):
        return False, "formato invalido: la key de DeepSeek empieza con 'sk-'"
    try:
        import requests
        r = requests.get(VALIDATE_URL, headers={"Authorization": f"Bearer {key}"},
                         timeout=15)
        if r.status_code == 200:
            return True, None
        if r.status_code == 401:
            return False, "DeepSeek rechazo la key (401): revisala"
        return False, f"DeepSeek respondio {r.status_code} al validar"
    except Exception as e:
        return False, f"no se pudo validar la key: {str(e)[:100]}"


# --- persistencia de jobs ---
def _save_job(job):
    try:
        JOBS_DIR.mkdir(parents=True, exist_ok=True)
        (JOBS_DIR / f"{job['id']}.json").write_text(
            json.dumps(job, ensure_ascii=False, indent=1))
    except Exception:
        pass


def _load_jobs():
    if not JOBS_DIR.exists():
        return
    for p in JOBS_DIR.glob("*.json"):
        try:
            job = json.loads(p.read_text())
        except Exception:
            continue
        if job.get("estado") == "running":
            job["estado"] = "interrumpido"
            job["error"] = "servicio reiniciado durante la corrida"
            _save_job(job)
        JOBS[job["id"]] = job


_load_jobs()


# --- auth + rate limit ---
def _check_auth():
    tok = request.headers.get("Authorization", "")
    if tok.startswith("Bearer "):
        tok = tok[7:]
    if not secrets.compare_digest(tok, API_TOKEN):
        return False
    now = time.time()
    with JOBS_LOCK:
        hits = [t for t in RL if now - t < 60]
        if len(hits) >= RATE_LIMIT:
            return False
        hits.append(now)
        RL[:] = hits
    return True


# --- tickets de descarga (link temporal sin Bearer para pdf/report) ---
def _dl_ticket(job_id, kind, ttl=None):
    exp = int(time.time()) + (ttl or DL_TTL)
    sig = hmac.new(API_TOKEN.encode(), f"{job_id}:{exp}:{kind}".encode(),
                   hashlib.sha256).hexdigest()
    return f"{exp}:{sig}"


def _check_dl_ticket(job_id, kind):
    tk = request.args.get("tk", "")
    if not tk or ":" not in tk:
        return False
    exp_s, sig = tk.split(":", 1)
    try:
        exp = int(exp_s)
    except ValueError:
        return False
    if time.time() > exp:
        return False
    good = hmac.new(API_TOKEN.encode(), f"{job_id}:{exp}:{kind}".encode(),
                    hashlib.sha256).hexdigest()
    return secrets.compare_digest(sig, good)


@app.before_request
def _auth_all():
    if request.path == "/health" or request.path == "/favicon.ico":
        return None
    parts = request.path.strip("/").split("/")
    if (len(parts) == 3 and parts[0] == "corridas"
            and parts[2] == "report" and _check_dl_ticket(parts[1], "report")):
        return None
    if not _check_auth():
        return jsonify({"error": "unauthorized"}), 401


# --- helpers ---
def _normalizar_target(t):
    """URL cruda -> host[:puerto]; dominio/IP/host:puerto pasan limpios."""
    t = (t or "").strip()
    if not t:
        return ""
    if "://" in t:
        p = urlparse(t)
        host = (p.hostname or "").strip().lower()
        if not host:
            return ""
        return f"{host}:{p.port}" if p.port else host
    t = t.rstrip("/")
    m = re.match(r"^([^/:]+):(\d{1,5})$", t)
    if m:
        return f"{m.group(1).lower()}:{m.group(2)}"
    return t.lower()


def _buscar_base(target, perfil, despues=None):
    """Reporte más nuevo de reports/ con meta.target==target y meta.perfil==perfil."""
    rep = BASE_DIR / "reports"
    if not rep.exists():
        return None
    cands = []
    for d in rep.iterdir():
        if not d.is_dir():
            continue
        mp = d / "meta.json"
        if not mp.exists():
            continue
        try:
            meta = json.loads(mp.read_text())
        except Exception:
            continue
        if meta.get("target") != target or meta.get("perfil") != perfil:
            continue
        mtime = mp.stat().st_mtime
        if despues is not None and mtime < despues:
            continue
        cands.append((mtime, d))
    if not cands:
        return None
    cands.sort(key=lambda x: x[0], reverse=True)
    return cands[0][1]


def _find_cached(target, perfil):
    b = _buscar_base(target, perfil)
    if not b:
        return None
    if time.time() - b.stat().st_mtime > CACHE_TTL:
        return None
    return b


def _resultado(job):
    """Payload completo del resultado: findings + entidades + resumen del investigador."""
    base = job.get("base")
    if isinstance(base, str):
        base = Path(base)
    if not base or not base.exists():
        base = _buscar_base(job["target"], job["perfil"])
    if not base:
        return None
    findings = []
    try:
        for line in (base / "findings.jsonl").read_text().splitlines():
            if line.strip():
                findings.append(json.loads(line))
    except Exception:
        pass
    counts = {"total": len(findings), "critical": 0, "high": 0,
              "medium": 0, "low": 0, "info": 0}
    for f in findings:
        sev = f.get("severity", "info")
        if sev in counts:
            counts[sev] += 1
    entidades = {}
    try:
        ej = json.loads((base / "entities.json").read_text())
        entidades = {
            "emails": ej.get("entidades", {}).get("emails", []),
            "personas": ej.get("entidades", {}).get("nombres", []),
            "empresas": ej.get("entidades", {}).get("empresas", []),
            "totales": ej.get("totales", {}),
        }
    except Exception:
        pass
    resumen_investigador = None
    try:
        for line in (base / "run-log.jsonl").read_text().splitlines():
            if not line.strip():
                continue
            e = json.loads(line)
            if e.get("tool") == "concluir":
                resumen_investigador = (e.get("args") or {}).get("resumen") or e.get("text")
    except Exception:
        pass
    if not resumen_investigador:
        try:
            safe = "".join(c if c.isalnum() or c in "-._" else "_"
                           for c in job["target"])[:80]
            ck = json.loads((BASE_DIR / "cache" / f"checkpoint_{safe}_{job['perfil']}.json").read_text())
            resumen_investigador = ck.get("final_summary") or None
        except Exception:
            pass
    return {
        "base": base.name,
        "resumen": counts,
        "findings": findings[:200],
        "entidades": entidades,
        "resumen_investigador": resumen_investigador,
        "reporte_md": f"/corridas/{job['id']}/report",
    }


def _job_public(job):
    out = {k: job[k] for k in ("id", "estado", "target", "perfil", "creado",
                               "terminado", "error") if k in job}
    if job.get("terminado") and job.get("creado"):
        out["tiempo_s"] = round(job["terminado"] - job["creado"], 1)
    for k in ("cached", "duplicado"):
        if job.get(k):
            out[k] = job[k]
    return out


# --- endpoints ---
@app.get("/health")
def health():
    return jsonify({"ok": True, "service": "nureq-api", "ts": time.time()})


@app.get("/favicon.ico")
def favicon():
    return "", 404


@app.get("/api-key")
def get_api_key():
    """Estado de la key del cliente (enmascarada)."""
    k = _load_client_key()
    return jsonify({"guardada": bool(k), "masked": _mask_key(k)})


@app.put("/api-key")
def put_api_key():
    """Guarda la key de DeepSeek del cliente (validada). Body: {"api_key": "sk-..."}"""
    body = request.get_json(silent=True) or {}
    key = (body.get("api_key") or "").strip()
    ok, err = _validate_deepseek_key(key)
    if not ok:
        return jsonify({"error": err}), 400
    _save_client_key(key)
    return jsonify({"ok": True, "guardada": True, "masked": _mask_key(key)})


@app.delete("/api-key")
def del_api_key():
    try:
        KEY_FILE.unlink(missing_ok=True)
    except Exception:
        pass
    return jsonify({"ok": True, "guardada": False})


@app.get("/corridas")
def list_corridas():
    with JOBS_LOCK:
        jobs = sorted(JOBS.values(), key=lambda j: j.get("creado", 0), reverse=True)[:20]
    if jobs:
        return jsonify({"corridas": [_job_public(j) for j in jobs]})
    # fallback: reportes históricos en disco (pre-jobs)
    rep = BASE_DIR / "reports"
    out = []
    if rep.exists():
        for d in sorted(rep.iterdir(), reverse=True)[:20]:
            if d.is_dir():
                md = d / "report.md"
                out.append({
                    "dir": d.name,
                    "report": md.exists(),
                    "target": (d.name.rsplit("_", 2)[0] if "_" in d.name else d.name),
                })
    return jsonify({"corridas": out})


@app.get("/corridas/<job_id>")
def job_status(job_id):
    with JOBS_LOCK:
        job = JOBS.get(job_id)
    if not job:
        return jsonify({"error": "job no existe"}), 404
    out = _job_public(job)
    if job.get("estado") in ("done", "cached", "interrumpido"):
        out["resultado"] = _resultado(job)
    return jsonify(out)


@app.post("/corridas/<job_id>/link")
def job_link(job_id):
    """Links de descarga temporales (sin Bearer, expiran en DL_TTL s).
    Uso: POST /corridas/<id>/link con Bearer -> {pdf, report, expira}."""
    with JOBS_LOCK:
        job = JOBS.get(job_id)
    if not job:
        return jsonify({"error": "job no existe"}), 404
    base = job.get("base")
    if isinstance(base, str):
        base = Path(base)
    if not base or not base.exists():
        base = _buscar_base(job["target"], job["perfil"])
    if not base:
        return jsonify({"error": "sin reporte"}), 404
    host = request.host
    try:
        ttl = min(int(request.args.get("ttl") or DL_TTL), 43200)
    except ValueError:
        ttl = DL_TTL
    return jsonify({
        "report": f"http://{host}/corridas/{job_id}/report?tk={_dl_ticket(job_id, 'report', ttl)}",
        "expira": int(time.time()) + ttl,
    })


@app.get("/corridas/<job_id>/report")
def job_report(job_id):
    with JOBS_LOCK:
        job = JOBS.get(job_id)
    if not job:
        return jsonify({"error": "job no existe"}), 404
    base = job.get("base")
    if isinstance(base, str):
        base = Path(base)
    if not base or not base.exists():
        base = _buscar_base(job["target"], job["perfil"])
    if not base or not (base / "report.md").exists():
        return jsonify({"error": "sin reporte"}), 404
    return (base / "report.md").read_text(errors="replace"), 200, {
        "Content-Type": "text/markdown; charset=utf-8"}


@app.get("/corridas/<job_id>/pdf")
def job_pdf(job_id):
    """PDF deshabilitado: nureq devuelve DATA (JSON + report.md)."""
    return jsonify({"error": "PDF deshabilitado en nureq: usar /corridas/<id> (data) "
                             "o /corridas/<id>/report (markdown)"}), 404


@app.post("/consulta")
def consulta():
    """Una sola consulta por URL. Lanza la investigación completa (con IA) en background.
    Body: {"target": "https://ejemplo.com/path|dominio|ip|host:puerto", "fresca": bool}
    ?sincrono=1: espera y devuelve el resultado en la misma llamada."""
    body = request.get_json(silent=True) or {}
    target = _normalizar_target(body.get("target"))
    perfil_pedido = str(body.get("perfil") or "").strip()
    perfil = "profundo"  # perfil unico: la API corre todo en profundo
    fresca = body.get("fresca") in (True, "true", "1", 1)
    sincrono = request.args.get("sincrono") in ("1", "true")
    if not target:
        return jsonify({"error": "target requerido (URL|dominio|ip|host:puerto)"}), 400
    client_key = _load_client_key()
    if not client_key:
        return jsonify({"error": "sin API key de DeepSeek configurada: cargala una vez "
                                 "con PUT /api-key (sk-...). La API no usa la key del servidor."}), 400
    aviso = None
    if perfil_pedido and perfil_pedido != "profundo":
        aviso = f"perfil '{perfil_pedido}' ya no existe: la API corre todo en profundo"

    with JOBS_LOCK:
        # dedup: misma investigacion ya corriendo -> mismo job
        for j in JOBS.values():
            if (j.get("estado") == "running" and j.get("target") == target
                    and j.get("perfil") == perfil):
                out = _job_public(j)
                out["duplicado"] = True
                if aviso:
                    out["aviso"] = aviso
                return jsonify(out), 202
        # cache: reporte fresco del mismo target+perfil -> respuesta instantanea
        # (fresca: true saltea el cache — corrida nueva a proposito)
        cached_base = None if fresca else _find_cached(target, perfil)
        if cached_base:
            job = {"id": uuid.uuid4().hex[:12], "estado": "cached", "target": target,
                   "perfil": perfil, "base": str(cached_base),
                   "creado": time.time(), "terminado": time.time(), "error": None,
                   "cached": True}
            JOBS[job["id"]] = job
            _save_job(job)
            out = _job_public(job)
            out["resultado"] = _resultado(job)
            if aviso:
                out["aviso"] = aviso
            return jsonify(out), 200
        # semaforo: max N corridas en paralelo
        running = sum(1 for j in JOBS.values() if j.get("estado") == "running")
        if running >= MAX_JOBS:
            return jsonify({"error": f"ocupado: ya hay {MAX_JOBS} corridas en paralelo, reintentar en un rato"}), 429

        job = {"id": uuid.uuid4().hex[:12], "estado": "running", "target": target,
               "perfil": perfil, "base": None,
               "creado": time.time(), "terminado": None, "error": None}
        JOBS[job["id"]] = job
    _save_job(job)

    def _run(job):
        try:
            cmd = [sys.executable, str(BASE_DIR / "nureq.py"), job["target"],
                   "--perfil", job["perfil"], "--no-vpn"]
            timeout = config.PERFILES[job["perfil"]]["minutes"] * 60 + 1200
            # env explicito: la key del CLIENTE pisa cualquier key heredada del .env
            env = os.environ.copy()
            env["DEEPSEEK_API_KEY"] = client_key
            proc = subprocess.run(cmd, cwd=str(BASE_DIR), capture_output=True,
                                  text=True, timeout=timeout, env=env)
            job["estado"] = "done" if proc.returncode == 0 else "error"
            job["error"] = proc.stderr[-500:] if proc.returncode != 0 else None
            base = _buscar_base(job["target"], job["perfil"], despues=job["creado"] - 5)
            if base:
                job["base"] = str(base)
        except Exception as e:
            job["estado"] = "error"
            job["error"] = str(e)[:500]
        finally:
            job["terminado"] = time.time()
            _save_job(job)

    threading.Thread(target=_run, args=(job,), daemon=True).start()

    if sincrono:
        deadline = time.time() + config.PERFILES[perfil]["minutes"] * 60 + 1200
        while time.time() < deadline:
            if job.get("estado") in ("done", "error"):
                break
            time.sleep(2)
        if job.get("estado") == "done":
            out = _job_public(job)
            out["resultado"] = _resultado(job)
            if aviso:
                out["aviso"] = aviso
            return jsonify(out), 200
        if job.get("estado") == "error":
            return jsonify(_job_public(job)), 500
        return jsonify({"job_id": job["id"], "estado": "running", "aviso": "expiro el espera sincrona, seguir por /corridas",
                        "seguimiento": f"/corridas/{job['id']}"}), 202

    out = {"job_id": job["id"], "estado": "running",
           "seguimiento": f"/corridas/{job['id']}"}
    if aviso:
        out["aviso"] = aviso
    return jsonify(out), 202


if __name__ == "__main__":
    print(f"nureq-api en 0.0.0.0:{PORT} | token: ...{API_TOKEN[-6:]} | "
          f"max jobs: {MAX_JOBS} | cache: {CACHE_TTL}s")
    print(f"ej: curl -H 'Authorization: Bearer {API_TOKEN}' http://127.0.0.1:{PORT}/health")
    app.run(host="0.0.0.0", port=PORT, threaded=True)