"""Ledger 'ya consultado': registro persistente de consultas hechas por target
(DNS/crtsh/wayback/shodan). Evita re-consultar fuentes en corridas repetidas.
Se inyecta al system prompt del agente para que no repita trabajo."""
import json
import time
from pathlib import Path


class Ledger:
    def __init__(self, base_dir, target):
        self.path = Path(base_dir) / "cache" / f"ledger_{_safe(target)}.json"
        self.data = {}
        if self.path.exists():
            try:
                self.data = json.loads(self.path.read_text())
            except Exception:
                self.data = {}

    def done(self, key, ttl=0):
        """True si la consulta key ya se hizo (y no expiró si ttl>0 en horas)."""
        hit = self.data.get(key)
        if not hit:
            return False
        if ttl and time.time() - hit.get("ts", 0) > ttl * 3600:
            return False
        return True

    def mark(self, key, note=""):
        self.data[key] = {"ts": time.time(), "note": note}
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self.path.write_text(json.dumps(self.data, ensure_ascii=False, indent=2))
        except Exception:
            pass

    def summary(self, limit=30):
        """Lineas 'ya consultado' para inyectar al modelo."""
        items = sorted(self.data.items(), key=lambda kv: kv[1].get("ts", 0), reverse=True)
        if not items:
            return ""
        lines = []
        for k, v in items[:limit]:
            lines.append(f"- {k} ({v.get('note', '')})")
        return "YA CONSULTADO en corridas anteriores (no repetir sin motivo):\n" + "\n".join(lines)


def _safe(name):
    return "".join(c if c.isalnum() or c in "-._" else "_" for c in name)[:60]