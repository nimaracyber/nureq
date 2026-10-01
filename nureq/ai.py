"""Cerebro IA: DeepSeek v4-flash (triage/clasificacion) + v4-pro (reporte final).
Regla del Claude-OSINT: NUNCA pegar secretos literales a LLMs cloud — el digest va
REDACTADO (solo ultimos 4 chars). Por defecto la API sale DIRECTA (canal A, sin VPN)
con Session keep-alive; NUREQ_API_DIRECT=0 para volver por netns."""
import json
import re
import time

from . import netexec
from .config import MODEL_FLASH, MODEL_PRO

API_URL = "https://api.deepseek.com/chat/completions"


def deepseek_call(messages, model=MODEL_FLASH, max_tokens=2000, temperature=0.7,
                  thinking=False, reasoning_effort=None, timeout=120, key=None,
                  direct=None):
    """Llamada a la API DeepSeek (sin tools). Devuelve (content, reasoning)."""
    msg, err = deepseek_raw(messages, model=model, max_tokens=max_tokens,
                            temperature=temperature, thinking=thinking,
                            reasoning_effort=reasoning_effort, timeout=timeout, key=key,
                            direct=direct)
    if err:
        return None, err
    content = msg.get("content") or ""
    reasoning = msg.get("reasoning_content") or ""
    return content, reasoning


def deepseek_raw(messages, model=MODEL_FLASH, max_tokens=2000, temperature=0.7,
                 thinking=False, reasoning_effort=None, timeout=120, key=None,
                 tools=None, tool_choice=None, direct=None):
    """Llamada cruda con soporte de function calling. Devuelve (message_dict, error).
    message_dict: {content, reasoning_content, tool_calls, ...} del primer choice."""
    payload = {
        "model": model,
        "messages": messages,
        "max_tokens": max_tokens,
        "stream": False,
    }
    if thinking:
        payload["thinking"] = {"type": "enabled"}
        if reasoning_effort:
            payload["reasoning_effort"] = reasoning_effort
    else:
        payload["temperature"] = temperature
    if tools:
        payload["tools"] = tools
    if tool_choice:
        payload["tool_choice"] = tool_choice
    headers = {
        "Authorization": f"Bearer {key}" if key else None,
        "Content-Type": "application/json",
    }
    if not headers["Authorization"]:
        headers.pop("Authorization")
    if direct is None:
        direct = _default_api_direct()
    if direct:
        st, resp_headers, body = netexec.http_post(API_URL, data=json.dumps(payload),
                                                   headers=headers, vpn=False, timeout=timeout)
    else:
        st, resp_headers, body = netexec.http_post(API_URL, data=json.dumps(payload),
                                                   headers=headers, vpn=True, timeout=timeout)
    if st != 200:
        return None, f"API error {st}: {body[:300]}"
    try:
        data = json.loads(body)
        return data["choices"][0]["message"], None
    except Exception as e:
        return None, f"parse error: {e} :: {body[:300]}"


def deepseek_raw_stream(messages, model=MODEL_FLASH, max_tokens=2000, temperature=0.7,
                        timeout=90, first_token_timeout=30, key=None,
                        tools=None, tool_choice=None):
    """Llamada STREAMING a DeepSeek (canal directo, Session del host).
    Corta si el primer token tarda > first_token_timeout (paso colgado).
    Devuelve (message_dict, error) — acumula content + tool_calls desde el SSE."""
    payload = {
        "model": model,
        "messages": messages,
        "max_tokens": max_tokens,
        "stream": True,
    }
    if not (any(isinstance(m, dict) and m.get("role") == "system" and
                "thinking" in m.get("content", "") for m in messages) or False):
        payload["temperature"] = temperature
    if tools:
        payload["tools"] = tools
    if tool_choice:
        payload["tool_choice"] = tool_choice
    headers = {"Authorization": f"Bearer {key}" if key else None,
               "Content-Type": "application/json"}
    if not headers["Authorization"]:
        headers.pop("Authorization")
    try:
        import requests
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        sess = netexec._direct_session()
        r = sess.post(API_URL, data=json.dumps(payload), headers=headers,
                      timeout=timeout, stream=True, verify=False)
    except Exception as e:
        return None, f"stream init error: {e}"
    if r.status_code != 200:
        return None, f"API error {r.status_code}: {r.text[:300]}"
    msg = {"content": "", "tool_calls": {}}
    t0 = time.time()
    got_first = False
    try:
        for line in r.iter_lines(decode_unicode=True):
            if not line or not line.startswith("data:"):
                continue
            data = line[5:].strip()
            if data == "[DONE]":
                break
            try:
                chunk = json.loads(data)
            except Exception:
                continue
            choice = (chunk.get("choices") or [{}])[0]
            delta = choice.get("delta") or {}
            if delta.get("reasoning_content"):
                msg["reasoning_content"] = msg.get("reasoning_content", "") + delta["reasoning_content"]
            if delta.get("content"):
                if not got_first:
                    got_first = True
                msg["content"] += delta["content"]
            for tc in delta.get("tool_calls") or []:
                idx = tc.get("index", 0)
                slot = msg["tool_calls"].setdefault(idx, {"function": {"name": "", "arguments": ""}})
                if tc.get("id"):
                    slot["id"] = tc["id"]
                if tc.get("type"):
                    slot["type"] = tc["type"]
                fn = tc.get("function") or {}
                if fn.get("name"):
                    slot["function"]["name"] += fn["name"]
                if fn.get("arguments"):
                    slot["function"]["arguments"] += fn["arguments"]
            if not got_first and choice.get("finish_reason"):
                got_first = True
            if not got_first and time.time() - t0 > first_token_timeout:
                r.close()
                return None, f"primer token tardo > {first_token_timeout}s (paso colgado)"
    except Exception as e:
        return None, f"stream parse error: {e}"
    if msg["tool_calls"]:
        msg["tool_calls"] = list(msg["tool_calls"].values())
    if not msg["content"] and not msg["tool_calls"] and not msg.get("reasoning_content"):
        return None, "respuesta vacia del streaming"
    return msg, None


def _default_api_direct():
    from .config import _flag, load_env
    return _flag(load_env().get("NUREQ_API_DIRECT"), default=True)


def endpoint_score(url, method="GET", status=0):
    """Rubric de interes de endpoint (§20 del arsenal) — deterministico, sin API."""
    score = 0
    low = url.lower()
    if method in ("POST", "PUT", "DELETE", "PATCH") and status in (200, 201, 202, 204):
        score += 40
    if "graphql" in low or "gql" in low:
        score += 35
    if "admin" in low or "internal" in low or "debug" in low or "user" in low or "password" in low:
        score += 20
    if "token" in low or "key" in low or "secret" in low or "export" in low or "upload" in low:
        score += 20
    if "backup" in low or "config" in low or "private" in low or "delete" in low or "purge" in low:
        score += 20
    if re.search(r"(api_key|apikey|token|access_token)=", low):
        score += 15
    if "swagger" in low or "openapi" in low or "api-docs" in low:
        score += 20
    return score


def _sev_int(s):
    return {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}.get(s, 0)


def triage_candidates(candidates, key, vpn=None):
    """v4-flash: clasifica candidatos (URLs/endpoints) en interesantes/no. Batch barato."""
    if not candidates:
        return []
    scored = [(c, endpoint_score(c)) for c in candidates]
    interesting = [c for c, s in scored if s >= 25]
    if len(interesting) >= 3:
        sample = interesting[:15]
        sys = ("Eres un analista OSINT. Clasifica estas URLs candidatas de un target "
               "autorizado. Devolve SOLO un JSON list de las que valen la pena investigar "
               "(paneles admin, endpoints de API, archivos de config, backups, swagger, "
               "graphql), con razon de 1 linea cada una. Respuesta estricta JSON: "
               '[{"url": "...", "porque": "..."}]')
        content, reasoning = deepseek_call(
            [{"role": "system", "content": sys},
             {"role": "user", "content": json.dumps(sample)}],
            model=MODEL_FLASH, max_tokens=1500, timeout=90, key=key, direct=True)
        if content:
            try:
                m = re.search(r"\[.*\]", content, re.S)
                if m:
                    return json.loads(m.group(0))
            except Exception:
                pass
    return [{"url": c, "porque": "score local"} for c in interesting]


def build_digest(findings, target, asset_counts=None, secrets_summary=None):
    """Digest REDACTADO para la IA (metodo §12 / source hygiene)."""
    lines = []
    lines.append(f"Target analizado: {target}")
    lines.append(f"Hallazgos: {findings.count()}")
    bysev = {}
    for f in findings.items:
        bysev.setdefault(f["severity"], []).append(f)
    for sev in ("critical", "high", "medium", "low", "info"):
        if bysev.get(sev):
            lines.append(f"\n## {sev.upper()} ({len(bysev[sev])})")
            for f in sorted(bysev[sev], key=lambda x: x["title"])[:25]:
                lines.append(f"- [{f['category']}] {f['title']}  url={f['evidence'].get('url')}")
    if asset_counts:
        lines.append("\n## Assets")
        for k, v in asset_counts.items():
            lines.append(f"- {k}: {v}")
    if secrets_summary:
        lines.append("\n## Secretos encontrados (REDACTADOS)")
        for s in secrets_summary[:30]:
            lines.append(f"- {s['pattern']} ({s['severity']}): {s['match']}  en {s['source']}")
    return "\n".join(lines)


def final_report(target, digest, key, metrics=None):
    """v4-pro: reporte ejecutivo/tecnico en espanol rioplatense, solo hechos del digest."""
    sys = """Sos un analista senior de OSINT/seguridad (estilo rioplatense, tecnico y directo).
Te paso un digest REDACTADO de un analisis OSINT contra un target autorizado.
Escribi un reporte en Markdown, en español, con:
# Resumen ejecutivo (3-5 lineas)
## Hallazgos por severidad (los mas importantes con evidencia concreta)
## Superficie de ataque mapeada (subdominios, puertos, servicios, dockers, APIs)
## Contraseñas/secretos (solo si el digest trae hallazgos de secretos, con patrón y severidad, NUNCA el valor completo)
## Empleados y personas (solo si el digest trae emails/personas/empresas aspiradas o enriquecidas)
## Recomendaciones priorizadas (acciones concretas del dueño del asset)
## Próximos pasos sugeridos para el equipo de auditoría
Reglas: SOLO usar datos del digest. Si una categoría no aparece en el digest, OMITÍ la sección
entera: jamás escribas 'no aplica', 'no hay', 'no se encontró' ni inventes ausencias. No inventar.
Severidad honesta."""
    if metrics:
        sys += f"\n\nMetricas de corrida (NO inventar): {metrics}"
    msgs = [{"role": "system", "content": sys},
            {"role": "user", "content": digest}]
    content, reasoning = deepseek_call(msgs, model=MODEL_PRO, max_tokens=6000,
                                       thinking=True, reasoning_effort="high",
                                       timeout=300, key=key, direct=True)
    if not _report_completo(content):
        # el thinking se comio el presupuesto (output vacio o cortado a mitad) ->
        # reintentar sin thinking para asegurar un reporte completo
        content, reasoning2 = deepseek_call(msgs, model=MODEL_PRO, max_tokens=6000,
                                            temperature=0.4, timeout=300, key=key, direct=True)
        if not content and not reasoning:
            reasoning = reasoning2
    return content, reasoning


def _report_completo(content):
    """True si el reporte v4-pro vino usable: no vacio, razonablemente largo
    y con las secciones clave. El thinking puede cortar el output a la mitad
    del resumen (ej: 3 lineas) — eso se reintenta."""
    if not content or len(content) < 600:
        return False
    low = content.lower()
    for seccion in ("resumen", "hallazgos", "superficie"):
        if seccion not in low:
            return False
    return True
