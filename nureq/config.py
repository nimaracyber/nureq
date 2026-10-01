"""Configuracion de nureq: carga .env, flags de CLI, perfiles."""
import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
ENV_FILE = BASE_DIR / ".env"

MODEL_FLASH = "deepseek-v4-flash"
MODEL_PRO = "deepseek-v4-pro"

PERFILES = {
    "rapido": {
        "desc": "Triage ~3 min: pre-recon batch + agente corto",
        "steps": 12, "minutes": 15, "shodan": 4, "rps": 10,
        "ffuf_wordlist": "common", "ffuf_maxtime": 60, "ffuf_rate": 400,
        "nuclei_tags": "exposure,config", "prefix": False, "wayback": False,
    },
    "medio": {
        "desc": "Default ~7 min: pre-recon completo + agente",
        "steps": 20, "minutes": 25, "shodan": 8, "rps": 25,
        "ffuf_wordlist": "common", "ffuf_maxtime": 90, "ffuf_rate": 400,
        "nuclei_tags": "exposure,config,misconfig", "prefix": True, "wayback": True,
    },
    "profundo": {
        "desc": "Full ~10 min: + ffuf 24k + nuclei completo",
        "steps": 30, "minutes": 45, "shodan": 12, "rps": 40,
        "ffuf_wordlist": "full", "ffuf_maxtime": 90, "ffuf_rate": 400,
        "nuclei_tags": "all", "prefix": True, "wayback": True,
    },
}


class Config:
    def __init__(self, target, perfil="medio", vpn=True, use_ai=True, out=None, json_out=False):
        self.target = target.strip().rstrip("/")
        self.perfil = perfil
        self.vpn = vpn
        self.use_ai = use_ai
        self.out = out
        self.json_out = json_out
        self.deepseek_key = os.getenv("DEEPSEEK_API_KEY", "")
        self.shodan_key = os.getenv("SHODAN_API_KEY", "")
        self.reports_dir = BASE_DIR / "reports"
        self.cache_dir = BASE_DIR / "cache"
        self.shodan_cache = self.cache_dir / "shodan"
        self.api_direct = _flag(os.getenv("NUREQ_API_DIRECT"), default=True)
        self.osint_direct = _flag(os.getenv("NUREQ_OSINT_DIRECT"), default=True)
        self.autonomo = _flag(os.getenv("NUREQ_AUTONOMO"), default=True)
        self.allow_metadata = _flag(os.getenv("NUREQ_ALLOW_METADATA"), default=False)
        self.anti_loop = int(os.getenv("NUREQ_ANTILOOP") or 8)
        self.force_close = _flag(os.getenv("NUREQ_FORCE_CLOSE"), default=False)
        pf = PERFILES.get(perfil, PERFILES["medio"])
        self.max_steps = pf["steps"]
        self.max_minutes = pf["minutes"]
        self.shodan_budget = pf["shodan"]
        self.rps = int(os.getenv("NUREQ_RPS") or pf["rps"])
        self.ffuf_wordlist = pf.get("ffuf_wordlist", "common")
        self.ffuf_maxtime = pf.get("ffuf_maxtime", 90)
        self.ffuf_rate = pf.get("ffuf_rate", 400)
        self.nuclei_tags = pf.get("nuclei_tags", "all")
        self.prefix_sweep_on = pf.get("prefix", False)
        self.wayback_on = pf.get("wayback", False)

    @classmethod
    def from_env_and_args(cls, args):
        env = load_env()
        for k in ("DEEPSEEK_API_KEY", "SHODAN_API_KEY", "NUREQ_API_DIRECT",
                  "NUREQ_OSINT_DIRECT", "NUREQ_RPS", "NUREQ_AUTONOMO",
                  "NUREQ_ALLOW_METADATA", "NUREQ_ANTILOOP", "NUREQ_FORCE_CLOSE"):
            if k in env:
                os.environ.setdefault(k, env[k])
        for k, v in env.items():
            if k.startswith("HUNTER_API_KEY_"):
                os.environ.setdefault(k, v)
        vpn = not args.no_vpn
        if "NUREQ_VPN" in env and not args.no_vpn:
            vpn = env.get("NUREQ_VPN", "1") not in ("0", "false", "no")
        cfg = cls(args.target, args.perfil, vpn=vpn, use_ai=not args.no_ai,
                  out=args.out, json_out=args.json)
        cfg.shodan_cache.mkdir(parents=True, exist_ok=True)
        return cfg

    def profile(self):
        return PERFILES.get(self.perfil, PERFILES["medio"])


def _flag(val, default=True):
    if val is None:
        return default
    return str(val).lower() not in ("0", "false", "no")


def load_env():
    env = {}
    if ENV_FILE.exists():
        for line in ENV_FILE.read_text().splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, _, v = line.partition("=")
            env[k.strip()] = v.strip().strip('"').strip("'")
    return env
