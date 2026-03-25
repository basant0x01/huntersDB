"""
SUBMIND PRO — Centralized configuration.
All tunable constants live here. Workers and API read from this module.
"""
import os
from pathlib import Path

# ── Paths ─────────────────────────────────────────────────────────────────────
BASE_DIR   = Path.home() / ".submind-pro"
CHAOS_DIR  = BASE_DIR / "chaos"
LOGS_DIR   = BASE_DIR / "logs"
SETTINGS_F = BASE_DIR / "settings.json"
for _d in [BASE_DIR, CHAOS_DIR, LOGS_DIR]:
    _d.mkdir(parents=True, exist_ok=True)

# ── Authentication ─────────────────────────────────────────────────────────────
# BUG-01 FIX: SECRET_KEY was regenerated on every process restart (os.urandom),
# invalidating all existing session cookies. Now persists to disk so sessions
# survive worker restarts. Env var still takes precedence.
def _load_or_create_secret_key() -> str:
    """Load SECRET_KEY from env, or persist a stable random key to disk."""
    env_key = os.environ.get("SUBMIND_SECRET_KEY")
    if env_key:
        return env_key
    key_file = BASE_DIR / ".secret_key"
    try:
        if key_file.exists():
            return key_file.read_text().strip()
        key = os.urandom(32).hex()
        key_file.write_text(key)
        key_file.chmod(0o600)
        return key
    except Exception:
        # If disk write fails fall back to random — sessions won't survive restart
        return os.urandom(32).hex()

SECRET_KEY    = _load_or_create_secret_key()
AUTH_USERNAME = os.environ.get("SUBMIND_USER", "submind")
AUTH_PASSWORD = os.environ.get("SUBMIND_PASS", "submind")

# ── PostgreSQL ─────────────────────────────────────────────────────────────────
DATABASE_URL = os.environ.get(
    "DATABASE_URL",
    "postgresql://submind:submind@localhost:5432/submind"
)
DB_POOL_MIN  = int(os.environ.get("DB_POOL_MIN", "5"))
DB_POOL_MAX  = int(os.environ.get("DB_POOL_MAX", "20"))

# ── Redis ──────────────────────────────────────────────────────────────────────
REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379/0")

# ── Hard resource limits (MANDATORY — these are enforced at enqueue time) ─────
MAX_CONCURRENT_TASKS = int(os.environ.get("MAX_CONCURRENT_TASKS", "50"))
MAX_QUEUE_SIZE       = int(os.environ.get("MAX_QUEUE_SIZE",       "10000"))
MAX_SUBPROCESSES     = int(os.environ.get("MAX_SUBPROCESSES",     "4"))  # max parallel tool subprocesses
MAX_BATCH_SIZE       = int(os.environ.get("MAX_BATCH_SIZE",       "3000"))  # 3k subs/batch

# ── Phase concurrency (same universal limits as original) ─────────────────────
PHASE_A_CONCURRENT = int(os.environ.get("PHASE_A_CONCURRENT", "3"))  # projects scanning alive check in parallel
PHASE_C_CONCURRENT = int(os.environ.get("PHASE_C_CONCURRENT", "2"))  # projects in deep httpx in parallel
PHASE_D_CONCURRENT = int(os.environ.get("PHASE_D_CONCURRENT", "5"))
NUCLEI_MAX_CONCURRENT = PHASE_D_CONCURRENT

# ── Subprocess timeouts ───────────────────────────────────────────────────────
HTTPX_ALIVE_TIMEOUT_SECS  = int(os.environ.get("HTTPX_ALIVE_TIMEOUT_SECS", "7200"))   # 2h
HTTPX_DEEP_TIMEOUT_SECS   = int(os.environ.get("HTTPX_DEEP_TIMEOUT_SECS",  "7200"))   # 2h
NUCLEI_TIMEOUT_SECS       = int(os.environ.get("NUCLEI_TIMEOUT_SECS",      "7200"))   # 2h
SUBFINDER_TIMEOUT_SECS    = int(os.environ.get("SUBFINDER_TIMEOUT_SECS",   "600"))    # 10m

# ── Subprocess poll interval ──────────────────────────────────────────────────
PROC_POLL_INTERVAL = float(os.environ.get("PROC_POLL_INTERVAL", "5.0"))

# ── Worker settings ────────────────────────────────────────────────────────────
WORKER_BATCH_SIZE       = int(os.environ.get("WORKER_BATCH_SIZE",       "500"))
JOB_RETRY_MAX           = int(os.environ.get("JOB_RETRY_MAX",           "3"))
JOB_RETRY_DELAY_SECS    = int(os.environ.get("JOB_RETRY_DELAY_SECS",    "60"))
DLQ_KEY                 = "submind:dlq"

# ── Redis queue keys ──────────────────────────────────────────────────────────
QUEUE_SCAN    = "submind:queue:scan"     # priority 0 = new_sub, 1 = sweep, 2 = monitor, 3 = rescan
QUEUE_STATUS  = "submind:job_status"     # hash: job_id → JSON status

# ── Log settings ──────────────────────────────────────────────────────────────
LOG_BUFFER_MAX  = int(os.environ.get("LOG_BUFFER_MAX",  "5000"))
LOG_DB_BATCH    = int(os.environ.get("LOG_DB_BATCH",    "200"))
LOG_MAX_MSG_LEN = int(os.environ.get("LOG_MAX_MSG_LEN", "2000"))
LOG_MAX_DETAIL  = int(os.environ.get("LOG_MAX_DETAIL",  "5000"))

# ── Default scan settings (merged with DB settings.json at runtime) ───────────
DEFAULT_SETTINGS = {
    "auto_sync_enabled": False,
    "sync_interval_hours": 24,
    "auto_sync_platform": None,
    "auto_sync_bounty_only": True,
    "httpx_threads": 50,  # Phase A uses 2x = 100 threads
    "httpx_timeout": 10,   # Phase C timeout (Phase A uses 5s)
    "httpx_rate_limit": 300,  # Phase C rate (Phase A uses 2x = 600/s)
    "httpx_batch_size": 3000,  # subs per httpx invocation
    "httpx_ports": "80,443,8080,8443,8000,8888",
    "nuclei_threads": 25,
    "subfinder_threads": 10,
    "import_limit": 0,
    "skip_existing": True,
    "theme": "dark",
    "max_concurrent_scans": 5,
    "h1_username": "",
    "h1_token": "",
    "ywh_token": "",
    "bbscope_hackerone_username": "",
    "bbscope_hackerone_token": "",
    "bbscope_yeswehack_token": "",
    "monitor_enabled": True,
    "monitor_interval_min": 120,
    "template_update_interval_hours": 6,
    "auto_template_update": True,
    "auto_nuclei_update": True,
    "remove_dead_subdomains": True,
    "httpx_screenshot": True,
    "discord_webhook_url": "",
    "slack_webhook_url": "",
    "telegram_bot_token": "",
    "telegram_chat_id": "",
    "auto_nuclei_on_new_subs": True,
    # ── Auto Recon Intelligence (zero-touch pipeline) ──────────────────────
    # These default to True so recon runs automatically after every scan
    "auto_recon_after_scan":  True,
    # ── Adaptive Thread Controller ──────────────────────────────────────────
    "atc_cpu_target":         70.0,  # keep CPU below this % (default 70)
    "atc_enabled":            True,  # enable/disable the brain
    "auto_leak_after_scan":   True,
    "auto_recon_concurrency": 2,
    # ── Recon Intelligence API Keys ────────────────────────────────────────
    "censys_api_id":      "",
    "censys_api_secret":  "",
    "dehashed_email":     "",
    "dehashed_api_key":   "",
    "leakcheck_api_key":  "",
    "hibp_api_key":       "",
    "github_token":       "",

    "nuclei_skip_info": True,
    "nuclei_rate_limit": 100,
}

# ── Chaos ──────────────────────────────────────────────────────────────────────
CHAOS_INDEX = "https://chaos-data.projectdiscovery.io/index.json"
CHAOS_CACHE_TTL = 300  # 5 minutes

# ── CPU ────────────────────────────────────────────────────────────────────────
CPU_COUNT = os.cpu_count() or 4
