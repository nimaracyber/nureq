#!/usr/bin/env python3
"""Worker de batch HTTP. Recibe por stdin una lista JSON de requests y devuelve
por stdout un JSON con los resultados. Corre DENTRO del netns (canal target) o
directo (canal API/OSINT). Usa Session con keep-alive + hilos + rate limiter.

Formato in : {"requests": [{"id":N, "method":"GET","url":"...","headers":{...},
                            "body":"...","timeout":10}]}
Formato out: {"results": [{"id":N,"status":200,"headers":{...},"body":"..."}]}
"""
import json
import sys
import threading
import time

try:
    import requests
except Exception:
    print(json.dumps({"error": "requests no disponible en este runtime"}))
    sys.exit(2)

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

try:
    import os
    # rate limit (requests por segundo) por env
    _RPS = float(os.environ.get("NUREQ_BATCH_RPS") or 0)
except Exception:
    _RPS = 0

_sem = threading.BoundedSemaphore(32)
_rlock = threading.Lock()
_rlast = [0.0]


def _wait_rate(rps):
    if not rps:
        return
    min_gap = 1.0 / rps
    with _rlock:
        now = time.time()
        wait = min_gap - (now - _rlast[0])
        if wait > 0:
            time.sleep(wait)
            now = time.time()
        _rlast[0] = now


def _do_one(sess, req, rps):
    url = req.get("url")
    method = (req.get("method") or "GET").upper()
    timeout = float(req.get("timeout") or 10)
    try:
        _wait_rate(rps)
        with _sem:
            if method == "POST":
                r = sess.post(url, data=req.get("body"), timeout=timeout,
                              verify=False, allow_redirects=True)
            elif method == "HEAD":
                r = sess.head(url, timeout=timeout, verify=False, allow_redirects=True)
            else:
                r = sess.get(url, timeout=timeout, verify=False, allow_redirects=True)
        body = r.text[:16384]
        return {"id": req.get("id"), "status": r.status_code,
                "headers": dict(r.headers), "body": body}
    except Exception as e:
        return {"id": req.get("id"), "status": 0, "headers": {}, "body": "",
                "err": str(e)[:200]}


def main():
    raw = sys.stdin.read()
    try:
        payload = json.loads(raw)
    except Exception as e:
        print(json.dumps({"error": f"stdin json: {e}"}))
        sys.exit(2)
    reqs = payload.get("requests") or []
    workers = int(payload.get("workers") or 12)
    rps = float(payload.get("rps") or _RPS or 0)
    headers = payload.get("headers") or {}
    sess = requests.Session()
    for k, v in headers.items():
        sess.headers[k] = v
    from concurrent.futures import ThreadPoolExecutor
    out = [None] * len(reqs)
    with ThreadPoolExecutor(max_workers=max(1, min(workers, len(reqs) or 1))) as ex:
        futs = {ex.submit(_do_one, sess, req, rps): i for i, req in enumerate(reqs)}
        from concurrent.futures import as_completed
        for f in as_completed(futs):
            i = futs[f]
            try:
                out[i] = f.result()
            except Exception as e:
                out[i] = {"id": reqs[i].get("id"), "status": 0, "headers": {},
                          "body": "", "err": str(e)[:200]}
    print(json.dumps({"results": out}))


if __name__ == "__main__":
    main()
