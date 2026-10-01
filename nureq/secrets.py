"""Deteccion de secretos. Port del secret_scan.py del Claude-OSINT (catalogo §17,
48 patrones) + extras para 'contrasenas filtradas en JSON' y connection strings."""
import re

SEV_CRITICAL = "critical"
SEV_HIGH = "high"
SEV_MEDIUM = "medium"
SEV_LOW = "low"

# Orden importa: los patrones mas especificos primero.
PATTERNS = [
    # AWS
    ("AWS_ACCESS_KEY",       SEV_CRITICAL, "aws",          r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"),
    ("AWS_SECRET_TYPED",     SEV_CRITICAL, "aws",          r"(?i)aws[_\-]?secret[_\-]?access[_\-]?key['\"\s:=]+([A-Za-z0-9/+=]{40})"),
    ("AWS_SECRET_LOOSE",     SEV_HIGH,     "aws",          r"(?i)aws(.{0,20})?(secret|sk)[\"'=: ]+([0-9a-z/+=]{40})"),

    # Google Cloud
    ("GCP_SERVICE_ACCOUNT",  SEV_CRITICAL, "gcp",          r'"type"\s*:\s*"service_account"'),
    ("GOOGLE_API_KEY",       SEV_HIGH,     "gcp",          r"\bAIza[0-9A-Za-z_\-]{35}\b"),

    # GitHub
    ("GH_PAT_CLASSIC",       SEV_CRITICAL, "github",       r"\bghp_[A-Za-z0-9]{36}\b"),
    ("GH_PAT_FINEGRAINED",   SEV_CRITICAL, "github",       r"\bgithub_pat_[A-Za-z0-9_]{82}\b"),
    ("GH_OAUTH",             SEV_HIGH,     "github",       r"\bgho_[A-Za-z0-9]{36}\b"),
    ("GH_S2S",               SEV_HIGH,     "github",       r"\bgh[usr]_[A-Za-z0-9]{36,}\b"),

    # Stripe
    ("STRIPE_LIVE",          SEV_CRITICAL, "stripe",       r"\bsk_live_[0-9A-Za-z]{24,}\b"),
    ("STRIPE_TEST",          SEV_LOW,      "stripe",       r"\bsk_test_[0-9A-Za-z]{24,}\b"),

    # Slack
    ("SLACK_TOKEN",          SEV_HIGH,     "slack",        r"\bxox[abpors]-[0-9A-Za-z\-]{10,48}\b"),
    ("SLACK_WEBHOOK",        SEV_MEDIUM,   "slack",        r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+"),

    # Email services
    ("SENDGRID",             SEV_HIGH,     "email_svc",    r"\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b"),
    ("MAILGUN_V1",           SEV_HIGH,     "email_svc",    r"\bkey-[0-9a-zA-Z]{32}\b"),
    ("MAILGUN_LOOSE",        SEV_HIGH,     "email_svc",    r"\bkey-[0-9a-f]{32}\b"),

    # Twilio
    ("TWILIO_API",           SEV_HIGH,     "twilio",       r"\bSK[0-9a-fA-F]{32}\b"),
    ("TWILIO_SID",           SEV_MEDIUM,   "twilio",       r"\bAC[a-f0-9]{32}\b"),
    ("TWILIO_AUTH",          SEV_HIGH,     "twilio",       r"(?i)twilio(.{0,20})?(auth|token)[\"'=: ]+([a-f0-9]{32})"),

    # PaaS
    ("HEROKU_API",           SEV_MEDIUM,   "paas",         r"(?i)heroku(.{0,20})?api[\"'=: ]+([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})"),

    # Firebase
    ("FIREBASE_URL",         SEV_LOW,      "firebase",     r"\bhttps?://[a-z0-9\-]+\.firebaseio\.com\b"),

    # Tokens / auth
    ("JWT",                  SEV_MEDIUM,   "jwt",          r"\beyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b"),
    ("BEARER_AUTH",          SEV_MEDIUM,   "bearer",       r"(?i)authorization[\"'=: ]+bearer\s+[A-Za-z0-9._\-]{20,}"),
    ("BASIC_AUTH_URL",       SEV_MEDIUM,   "basic_auth",   r"https?://[^/\s:@]+:[^/\s:@]+@[^/\s]+"),
    ("BASIC_AUTH_HEADER",    SEV_MEDIUM,   "basic_auth",   r"(?i)authorization[\"'=: ]+basic\s+[A-Za-z0-9+/=]{20,}"),

    # Private keys
    ("RSA_PRIVKEY",          SEV_CRITICAL, "private_key",  r"-----BEGIN RSA PRIVATE KEY-----"),
    ("EC_PRIVKEY",           SEV_CRITICAL, "private_key",  r"-----BEGIN EC PRIVATE KEY-----"),
    ("OPENSSH_PRIVKEY",      SEV_CRITICAL, "private_key",  r"-----BEGIN OPENSSH PRIVATE KEY-----"),
    ("PKCS8_PRIVKEY",        SEV_CRITICAL, "private_key",  r"-----BEGIN PRIVATE KEY-----"),
    ("GENERIC_PRIVKEY",      SEV_CRITICAL, "private_key",  r"-----BEGIN (DSA |PGP |)PRIVATE KEY-----"),

    # Generic API keys
    ("GENERIC_API_KEY",      SEV_MEDIUM,   "generic",      r"(?i)(?:api[_\-]?key|apikey|api_secret|access_token|secret[_\-]?token)['\"\s:=]+[\"']([A-Za-z0-9+/=_\-]{24,})[\"']"),

    # Modern AI APIs
    ("ANTHROPIC_API",        SEV_CRITICAL, "ai_api",       r"\bsk-ant-(?:api03|admin01)-[A-Za-z0-9_\-]{93,}\b"),
    ("OPENAI_LEGACY",        SEV_CRITICAL, "ai_api",       r"\bsk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}\b"),
    ("OPENAI_PROJECT",       SEV_CRITICAL, "ai_api",       r"\bsk-proj-[A-Za-z0-9_\-]{40,}T3BlbkFJ[A-Za-z0-9_\-]{40,}\b"),
    ("OPENAI_SESSION",       SEV_HIGH,     "ai_api",       r"\bsess-[A-Za-z0-9]{40}\b"),
    ("HUGGINGFACE",          SEV_HIGH,     "ai_api",       r"\bhf_[A-Za-z0-9]{30,}\b"),
    ("DEEPSEEK_API",         SEV_CRITICAL, "ai_api",       r"\bsk-[a-f0-9]{32,}\b"),

    # Cloud infra
    ("CLOUDFLARE_API",       SEV_CRITICAL, "infra_api",    r"(?i)cf[_\-]?api[_\-]?key['\"\s:=]+([a-f0-9]{37})"),
    ("DIGITALOCEAN",         SEV_HIGH,     "infra_api",    r"\bdop_v1_[a-f0-9]{64}\b"),

    # Package registries
    ("NPM_TOKEN",            SEV_HIGH,     "package_registry", r"\bnpm_[A-Za-z0-9]{36}\b"),
    ("PYPI_TOKEN",           SEV_HIGH,     "package_registry", r"\bpypi-AgENdGV[A-Za-z0-9_\-]+\b"),
    ("DOCKER_HUB_PAT",       SEV_HIGH,     "package_registry", r"\bdckr_pat_[A-Za-z0-9_\-]{27,}\b"),

    # SaaS
    ("ATLASSIAN_TOKEN",      SEV_HIGH,     "saas_api",     r"\bATATT3xFfGF0[A-Za-z0-9_\-]{180,}\b"),
    ("LINEAR_API",           SEV_MEDIUM,   "saas_api",     r"\blin_api_[A-Za-z0-9]{40}\b"),

    # Observability
    ("NEWRELIC_LICENSE",     SEV_MEDIUM,   "observability", r"\b(?:NRAA|NRAK|NRBR)-[A-F0-9]{27}\b"),
    ("DATADOG_API",          SEV_HIGH,     "observability", r"(?i)dd[_\-]?api[_\-]?key['\"\s:=]+([a-f0-9]{32})"),
    ("SENTRY_DSN",           SEV_LOW,      "observability", r"https://[a-f0-9]+@o[0-9]+\.ingest\.sentry\.io/[0-9]+"),

    # Tunneling
    ("NGROK_AUTH",           SEV_MEDIUM,   "tunneling",    r"\b[12][A-Za-z0-9]{26}_[A-Za-z0-9]{32,}\b"),

    # Bot tokens
    ("DISCORD_BOT",          SEV_HIGH,     "bot_token",    r"\b[MN][A-Za-z\d]{23}\.[\w\-]{6}\.[\w\-]{27}\b"),
    ("TELEGRAM_BOT",         SEV_HIGH,     "bot_token",    r"\b\d{8,10}:[A-Za-z0-9_\-]{35}\b"),

    # --- Extras nureq: contrasenas y connection strings en JSON/config ---
    ("JSON_PASSWORD_PLAIN",  SEV_HIGH,     "password",     r'(?i)["\']?(?:password|passwd|pwd|passphrase|db_password|user_password)["\']?\s*[:=]\s*["\']([^"\'\s]{4,})["\']'),
    ("CONN_STRING_DSN",      SEV_HIGH,     "db",           r"\b(?:mysql|postgres(?:ql)?|mongodb(?:\+srv)?|redis|amqp|rabbitmq|mssql|sqlserver)://[^\s\"']+:[^\s\"']+@[^\s\"']+"),
    ("JDBC_DSN",             SEV_MEDIUM,   "db",           r"\bjdbc:[a-z0-9]+://[^\s\"']+:[^\s\"']+@[^\s\"']+"),
    ("AWS_CREDS_INI",        SEV_HIGH,     "aws",          r"(?i)aws_access_key_id\s*=\s*[A-Z0-9]{16,}"),
    ("GIT_CREDENTIALS",      SEV_CRITICAL, "git",          r"https?://[^\s/@]+@(?:github|gitlab|bitbucket)[^\s]*"),
    ("SMTP_CREDS",           SEV_HIGH,     "email_svc",    r"(?i)(?:smtp|imap|pop3)\.?password[\"'=: ]+([^\s\"']{4,})"),
    ("FTP_CREDS",            SEV_HIGH,     "ftp",          r"(?i)(?:ftp|sftp)[\"'=: ]+(?:password|pass|pwd)[\"'=: ]+([^\s\"']{4,})"),
    ("ENV_EXPORT",           SEV_MEDIUM,   "env",          r"(?m)^\s*export\s+[A-Z][A-Z0-9_]{2,}\s*=\s*[\"']?[^\s\"']+[\"']?"),
    ("HASH_LOOKALIKE",       SEV_LOW,      "password",     r'(?i)["\']?(?:password|passwd|pwd|hash|hashed_password)["\']?\s*[:=]\s*["\'](\$2[aby]\$[^\s"\']+|\$1\$[^\s"\']+|sha(?:256|512)\$[^\s"\']+|[a-f0-9]{40,64})["\']'),
]

COMPILED = [(n, s, c, re.compile(p)) for (n, s, c, p) in PATTERNS]


def scan_text(text: str, source: str = "<text>"):
    """Escanea un texto; yield un dict por match."""
    for line_no, line in enumerate(text.splitlines(), start=1):
        for name, sev, cat, rx in COMPILED:
            for m in rx.finditer(line):
                yield {
                    "pattern": name,
                    "severity": sev,
                    "category": cat,
                    "match": m.group(0)[:120],
                    "source": source,
                    "line": line_no,
                }


def scan_bytes(data: bytes, source: str = "<bytes>"):
    text = data.decode(errors="replace")
    yield from scan_text(text, source=source)


def scan_text_all(text: str, source: str = "<text>"):
    """Devuelve lista de hits sin duplicados del mismo patron+match en la misma fuente."""
    seen = set()
    out = []
    for hit in scan_text(text, source=source):
        key = (hit["pattern"], hit["match"])
        if key in seen:
            continue
        seen.add(key)
        out.append(hit)
    return out


def is_hash(value: str) -> bool:
    return bool(re.match(r"^\$2[aby]\$|^\$1\$|^[a-f0-9]{40,64}$", value.strip()))
