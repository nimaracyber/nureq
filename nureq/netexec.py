"""Ejecucion de comandos y HTTP por el netns redteam (regla de oro) o directo.

Canales:
- Canal A (API DeepSeek): directo por host con Session keep-alive (si NUREQ_API_DIRECT).
- Canal B (target): por netns redteam. Regla de oro.
- Canal C (OSINT publico): shodan/crt.sh/wayback/cavalier/rdap. Directo si
  NUREQ_OSINT_DIRECT, sino por netns.
"""
import json
import os
import shlex
import subprocess
import tempfile
import threading
import time
from pathlib import Path

NETNS = "redteam"

import requests

try:
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except Exception:
    pass

_session_direct = None
_session_lock = threading.Lock()

# DNS cache (memoria + disco)
_DNS_CACHE = {}
_dns_lock = threading.Lock()

# HTTP cache (disco 7d) — para respuestas de fuentes OSINT publicas
_HTTP_CACHE_DIR = None


def _direct_session():
    """Session con keep-alive para llamadas directas (API/OSINT). Reusa TLS."""
    global _session_direct
    if _session_direct is None:
        with _session_lock:
            if _session_direct is None:
                s = requests.Session()
                s.headers.update({"User-Agent": "nureq/2.0"})
                _session_direct = s
    return _session_direct


def check_vpn():
    """Verifica que el netns redteam exista y tenga salida real."""
    out = subprocess.run(["ip", "netns", "list"], capture_output=True, text=True).stdout
    if NETNS not in out:
        return False, "netns redteam no existe"
    for probe in ("https://api.ipify.org", "https://icanhazip.com", "https://api64.ipify.org"):
        try:
            status, _, body = _curl(probe, vpn=True, timeout=10)
            if status == 200 and body.strip():
                return True, body.strip()
        except Exception:
            continue
    return False, "sin salida real via netns"


# ---------------- comandos ----------------

def run_cmd(cmd, vpn=True, timeout=60):
    """Corre un comando (lista de args); antepone ip netns exec redteam si vpn."""
    full = list(cmd)
    if vpn:
        full = ["ip", "netns", "exec", NETNS] + full
    try:
        p = subprocess.run(full, capture_output=True, text=True, timeout=timeout)
        return p.returncode, p.stdout, p.stderr
    except subprocess.TimeoutExpired:
        return 124, "", "timeout"
    except FileNotFoundError:
        return 127, "", "binario no encontrado"


def run_cmd_stream(cmd, vpn=True, timeout=300, idle_timeout=90, on_line=None):
    """Corre un comando streameando lineas. Si no hay output en idle_timeout
    segundos, mata el proceso y devuelve lo acumulado. on_line(line) opcional."""
    full = list(cmd)
    if vpn:
        full = ["ip", "netns", "exec", NETNS] + full
    import select
    try:
        p = subprocess.Popen(full, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                             text=True, bufsize=1)
    except FileNotFoundError:
        return 127, "", "binario no encontrado"
    out_lines = []
    t0 = time.time()
    last = t0
    try:
        fd = p.stdout.fileno()
        while True:
            r, _, _ = select.select([fd], [], [], 1.0)
            now = time.time()
            if r:
                line = p.stdout.readline()
                if not line:
                    break
                last = now
                line = line.rstrip("\n")
                out_lines.append(line)
                if on_line:
                    try:
                        on_line(line)
                    except Exception:
                        pass
                continue
            if p.poll() is not None:
                break
            if (now - t0) > timeout:
                p.kill()
                out_lines.append(f"[!] TIMEOUT global ({timeout}s) — proceso cortado")
                break
            if (now - last) > idle_timeout:
                p.kill()
                out_lines.append(f"[!] Sin output en {idle_timeout}s — seguí con otra técnica")
                break
        try:
            p.wait(timeout=3)
        except Exception:
            p.kill()
    finally:
        rc = p.returncode if p.returncode is not None else 124
    return rc, "\n".join(out_lines), ""


# ---------------- DNS ----------------

def _dns_cache_path():
    from . import config
    return config.BASE_DIR / "cache" / "dns.json"


def _dns_cache_get(key, ttl=3600):
    with _dns_lock:
        if key in _DNS_CACHE:
            ts, vals = _DNS_CACHE[key]
            if time.time() - ts < ttl:
                return vals
    try:
        p = _dns_cache_path()
        if p.exists():
            data = json.loads(p.read_text())
            if key in data and time.time() - data[key]["ts"] < ttl:
                with _dns_lock:
                    _DNS_CACHE[key] = (data[key]["ts"], data[key]["vals"])
                return data[key]["vals"]
    except Exception:
        pass
    return None


def _dns_cache_put(key, vals):
    with _dns_lock:
        _DNS_CACHE[key] = (time.time(), vals)
    try:
        p = _dns_cache_path()
        p.parent.mkdir(parents=True, exist_ok=True)
        data = {}
        if p.exists():
            data = json.loads(p.read_text())
        data[key] = {"ts": time.time(), "vals": vals}
        p.write_text(json.dumps(data))
    except Exception:
        pass


def resolve(host, vpn=True, rtype="A", timeout=15):
    """Resuelve un host. Usa cache (TTL 1h). Devuelve lista de respuestas cortas."""
    host = host.rstrip(".").lower()
    cached = _dns_cache_get(f"{rtype}:{host}")
    if cached is not None:
        return cached
    rc, out, err = run_cmd(["dig", "+short", rtype, host], vpn=vpn, timeout=timeout)
    vals = [l.strip() for l in out.splitlines() if l.strip() and not l.strip().startswith(";")]
    if rc == 0:
        _dns_cache_put(f"{rtype}:{host}", vals)
    return vals


def resolve_full(host, vpn=True, rtype="A", timeout=20):
    """Resuelve sin +short (para TXT multilinea). Devuelve stdout crudo."""
    rc, out, err = run_cmd(["dig", rtype, host], vpn=vpn, timeout=timeout)
    return out


def resolve_many(hosts, vpn=True, rtype="A", workers=24, timeout=90):
    """Resuelve una lista de hosts en paralelo. Devuelve dict host->[vals].
    rtype=A/AAAA usa getaddrinfo en 1 subprocess (dentro del netns si vpn);
    otros tipos (TXT/MX/CNAME) usan dig en hilos."""
    hosts = [h for h in hosts if h]
    out = {}
    missing = []
    for h in hosts:
        cached = _dns_cache_get(f"{rtype}:{h.rstrip('.').lower()}")
        if cached is not None:
            out[h] = cached
        else:
            missing.append(h)
    if not missing:
        return out
    if rtype not in ("A", "AAAA"):
        from concurrent.futures import ThreadPoolExecutor, as_completed

        def dig_one(h):
            rc, o, e = run_cmd(["dig", "+short", rtype, h], vpn=vpn, timeout=8)
            vals = [l.strip() for l in o.splitlines() if l.strip() and not l.strip().startswith(";")]
            return h, vals

        with ThreadPoolExecutor(max_workers=max(1, min(workers, len(missing)))) as ex:
            futs = [ex.submit(dig_one, h) for h in missing]
            for f in as_completed(futs):
                try:
                    h, vals = f.result()
                    out[h] = vals
                except Exception:
                    pass
        for h, vals in out.items():
            _dns_cache_put(f"{rtype}:{h.rstrip('.').lower()}", vals)
        return out
    script = r'''
import json, socket, sys
from concurrent.futures import ThreadPoolExecutor
hosts = json.loads(sys.stdin.read() or "[]")
def r(h):
    try:
        socket.setdefaulttimeout(4)
        return sorted({i[4][0] for i in socket.getaddrinfo(h, None)})
    except Exception:
        return []
with ThreadPoolExecutor(max_workers=32) as ex:
    res = dict(zip(hosts, ex.map(r, hosts)))
print(json.dumps(res))
'''
    full = ["python3", "-c", script]
    if vpn:
        full = ["ip", "netns", "exec", NETNS] + full
    try:
        p = subprocess.run(full, input=json.dumps(missing), capture_output=True,
                           text=True, timeout=timeout)
        data = json.loads(p.stdout or "{}")
    except Exception:
        data = {}
    for h, ips in data.items():
        out[h] = ips
        _dns_cache_put(f"{rtype}:{h.rstrip('.').lower()}", ips)
    return out


# ---------------- HTTP ----------------

def _norm_reqs(reqs):
    """Asegura formato id/method/url/headers/body/timeout."""
    out = []
    for i, r in enumerate(reqs):
        out.append({
            "id": r.get("id", i),
            "method": (r.get("method") or "GET").upper(),
            "url": r["url"],
            "headers": r.get("headers") or {},
            "body": r.get("body"),
            "timeout": float(r.get("timeout") or 10),
        })
    return out


def batch_http(reqs, vpn=True, workers=14, rps=None, timeout=120):
    """Corre una lista de requests HTTP en paralelo.
    - vpn=True: un unico subprocess python DENTRO del netns (canal target).
    - vpn=False: directo con Session del host (canal API/OSINT publico).
    Devuelve lista de dicts en el mismo orden: {id, status, headers, body, err}."""
    reqs = _norm_reqs(reqs)
    if not reqs:
        return []
    if not vpn:
        return _batch_direct(reqs, workers=workers, rps=rps)
    script = (Path(__file__).parent / "_netbatch.py").resolve()
    payload = json.dumps({"requests": reqs, "workers": workers, "rps": rps or 0})
    full = ["ip", "netns", "exec", NETNS, "python3", str(script)]
    try:
        p = subprocess.run(full, input=payload, capture_output=True, text=True,
                           timeout=timeout)
        data = json.loads(p.stdout or "{}")
    except Exception as e:
        return [{"id": r["id"], "status": 0, "headers": {}, "body": "",
                 "err": f"batch netns: {e}"[:200]} for r in reqs]
    results = data.get("results") or []
    by_id = {r.get("id"): r for r in results}
    return [by_id.get(r["id"], {"id": r["id"], "status": 0, "headers": {},
                                "body": "", "err": "sin resultado"}) for r in reqs]


def _batch_direct(reqs, workers=14, rps=None):
    """Batch directo (canal API/OSINT): Session del host con keep-alive."""
    from concurrent.futures import ThreadPoolExecutor, as_completed
    sess = _direct_session()
    rlock = threading.Lock()
    rlast = [0.0]

    def wait_rate():
        if not rps:
            return
        min_gap = 1.0 / rps
        with rlock:
            now = time.time()
            gap = min_gap - (now - rlast[0])
            if gap > 0:
                time.sleep(gap)
                now = time.time()
            rlast[0] = now

    def one(req):
        try:
            wait_rate()
            t = req.get("timeout") or 10
            if req["method"] == "POST":
                r = sess.post(req["url"], data=req.get("body"), headers=req["headers"],
                              timeout=t, verify=False)
            elif req["method"] == "HEAD":
                r = sess.head(req["url"], headers=req["headers"], timeout=t,
                              verify=False, allow_redirects=True)
            else:
                r = sess.get(req["url"], headers=req["headers"], timeout=t,
                             verify=False, allow_redirects=True)
            return {"id": req["id"], "status": r.status_code, "headers": dict(r.headers),
                    "body": r.text[:16384]}
        except Exception as e:
            return {"id": req["id"], "status": 0, "headers": {}, "body": "",
                    "err": str(e)[:200]}

    out = [None] * len(reqs)
    with ThreadPoolExecutor(max_workers=max(1, min(workers, len(reqs)))) as ex:
        futs = {ex.submit(one, r): i for i, r in enumerate(reqs)}
        for f in as_completed(futs):
            out[futs[f]] = f.result()
    return out


# ---------------- helpers curl (compatibilidad) ----------------

def _curl(url, method="GET", headers=None, data=None, vpn=True, timeout=15, follow=True):
    """HTTP via curl. Si vpn=True sale por el netns. Devuelve (status, headers, body)."""
    hdr = []
    for k, v in (headers or {}).items():
        hdr += ["-H", f"{k}: {v}"]
    tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".body")
    tmpd = tempfile.NamedTemporaryFile(delete=False, suffix=".hdr")
    tmp.close(); tmpd.close()
    cmd = ["curl", "-sk", "-m", str(timeout), "-D", tmpd.name, "-o", tmp.name,
           "-w", "%{http_code}"]
    if follow:
        cmd.append("-L")
    for h in hdr:
        cmd.append(h)
    if method == "POST":
        cmd += ["-X", "POST"]
        if data is not None:
            cmd += ["--data-binary", data]
    elif method == "HEAD":
        cmd += ["-I"]
    elif method not in ("GET",):
        cmd += ["-X", method]
    cmd.append(url)
    full = (["ip", "netns", "exec", NETNS] + cmd) if vpn else cmd
    status = 0
    headers = {}
    body = ""
    try:
        p = subprocess.run(full, capture_output=True, text=True, timeout=timeout + 5)
        raw = ""
        try:
            raw = Path(tmpd.name).read_text(errors="replace")
        except Exception:
            pass
        for line in raw.splitlines():
            if ":" in line and not line.startswith(("HTTP/", "{")):
                k, _, v = line.partition(":")
                headers[k.strip()] = v.strip()
        try:
            body = Path(tmp.name).read_text(errors="replace")
        except Exception:
            pass
        for line in (p.stdout or "").splitlines():
            line = line.strip()
            if line.isdigit():
                status = int(line)
        if not status:
            for line in (p.stderr or "").splitlines():
                if line.startswith("HTTP/") and " " in line:
                    try:
                        status = int(line.split()[1]); break
                    except Exception:
                        pass
    except subprocess.TimeoutExpired:
        status, headers, body = 0, {}, ""
    finally:
        for f in (tmp.name, tmpd.name):
            try:
                Path(f).unlink(missing_ok=True)
            except Exception:
                pass
    return status, headers, body


def http_get(url, vpn=True, timeout=15, headers=None, follow=True):
    """GET HTTP. Devuelve (status, headers_dict, body)."""
    if vpn:
        return _curl(url, method="GET", headers=headers, vpn=True, timeout=timeout, follow=follow)
    try:
        r = _direct_session().get(url, headers=headers, timeout=timeout, verify=False,
                                  allow_redirects=follow)
        return r.status_code, dict(r.headers), r.text
    except Exception:
        return 0, {}, ""


def http_post(url, data=None, headers=None, vpn=True, timeout=15):
    """POST HTTP. Si vpn sale por netns; si no, directo con Session."""
    if vpn:
        return _curl(url, method="POST", headers=headers, data=data, vpn=True, timeout=timeout)
    try:
        r = _direct_session().post(url, data=data, headers=headers, timeout=timeout, verify=False)
        return r.status_code, dict(r.headers), r.text
    except Exception:
        return 0, {}, ""


def http_head(url, vpn=True, timeout=10):
    if vpn:
        return _curl(url, method="HEAD", vpn=vpn, timeout=timeout)
    try:
        r = _direct_session().head(url, timeout=timeout, verify=False, allow_redirects=True)
        return r.status_code, dict(r.headers), ""
    except Exception:
        return 0, {}, ""


def http_get_json(url, vpn=True, timeout=15, headers=None):
    """GET y parsea JSON. Devuelve (status, data_or_None, raw_body)."""
    st, h, body = http_get(url, vpn=vpn, timeout=timeout, headers=headers)
    try:
        return st, json.loads(body), body
    except Exception:
        return st, None, body
