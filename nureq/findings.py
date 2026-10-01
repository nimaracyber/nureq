"""Schema de findings del Claude-OSINT (methodology §3): id, module, asset_key,
category, severity, confidence, title, description, evidence, references, remediation."""
import hashlib
import json
import uuid
from datetime import datetime, timezone

SEV_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
CONF_ORDER = {"tentative": 0, "firm": 1, "confirmed": 2}


def _now_utc():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class Findings:
    """Coleccion de findings con el schema del methodology."""
    def __init__(self):
        self.items = []
        self._keys = set()

    def add(self, module, category, severity, confidence, title, description,
            asset_key=None, url=None, raw=None, raw_bytes=None, references=None,
            remediation=None):
        if raw_bytes is not None:
            digest = sha256_bytes(raw_bytes)
            raw_snippet = raw_bytes[:2048].decode(errors="replace")
        elif raw is not None:
            digest = sha256_bytes(raw.encode(errors="replace"))
            raw_snippet = raw[:2048]
        else:
            digest = ""
            raw_snippet = ""
        dedup_key = (module, category, asset_key or "", url or "", title)
        if dedup_key in self._keys:
            return None
        self._keys.add(dedup_key)
        f = {
            "id": uuid.uuid4().hex[:12],
            "module": module,
            "asset_key": asset_key,
            "category": category,
            "severity": severity,
            "confidence": confidence,
            "title": title,
            "description": description,
            "evidence": {
                "url": url,
                "timestamp": _now_utc(),
                "sha256": digest,
                "raw": raw_snippet,
            },
            "references": references or [],
            "remediation": remediation or "",
        }
        self.items.append(f)
        return f

    def by_severity(self):
        return sorted(self.items, key=lambda f: SEV_ORDER.get(f["severity"], 0), reverse=True)

    def count(self, sev=None):
        if sev:
            return sum(1 for f in self.items if f["severity"] == sev)
        return len(self.items)

    def to_jsonl(self):
        return "\n".join(json.dumps(f, ensure_ascii=False) for f in self.items)

    def digest(self, max_secrets=200):
        """Digest para la IA: secretos TRUNCADOS (solo ultimos 4 chars)."""
        out = []
        for f in self.by_severity():
            ev = f["evidence"]
            out.append({
                "sev": f["severity"], "cat": f["category"], "module": f["module"],
                "asset": f["asset_key"], "title": f["title"],
                "url": ev.get("url"), "sha": ev.get("sha256"),
            })
        return out


def secret_safe(secret: str, keep=4):
    """Redacta un secreto para contextos de IA: solo los ultimos `keep` chars."""
    if not secret:
        return ""
    if len(secret) <= keep + 4:
        return "*" * len(secret)
    return "*" * (len(secret) - keep) + secret[-keep:]