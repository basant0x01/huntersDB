"""
utils/settings.py — Async-safe settings loader.
Thread/task safe via asyncio lock + mtime cache.

═══════════════════════════════════════════════
  DEPLOY THIS FILE TO:  utils/settings.py
  cp this_file.py utils/settings.py
═══════════════════════════════════════════════
"""
import asyncio
import json
import logging
from pathlib import Path
from typing import Dict, Optional

from config.settings import SETTINGS_F, DEFAULT_SETTINGS

logger = logging.getLogger("utils.settings")

_cache: Dict = {}
_cache_mtime: float = 0.0
_cache_lock: Optional[asyncio.Lock] = None

_CAPS = {
    "httpx_threads":        (1,   500),
    "httpx_rate_limit":     (5,   2000),
    "httpx_batch_size":     (100, 10000),
    "httpx_timeout":        (3,   60),
    "max_concurrent_scans": (1,   20),
    "nuclei_threads":       (1,   200),
    "subfinder_threads":    (1,   30),
    "nuclei_rate_limit":    (5,   500),
}


def _get_cache_lock() -> asyncio.Lock:
    global _cache_lock
    if _cache_lock is None:
        _cache_lock = asyncio.Lock()
    return _cache_lock


def load_settings() -> Dict:
    """Load settings from disk with mtime cache. Synchronous — safe from threads."""
    global _cache_mtime
    try:
        mtime = SETTINGS_F.stat().st_mtime if SETTINGS_F.exists() else 0.0
    except OSError:
        mtime = 0.0

    if _cache and mtime == _cache_mtime:
        return dict(_cache)

    if SETTINGS_F.exists():
        try:
            s = json.loads(SETTINGS_F.read_text())
            for k, v in DEFAULT_SETTINGS.items():
                s.setdefault(k, v)
            # Force-upgrade: always enable screenshot (was False in older versions)
            if not s.get("httpx_screenshot"):
                s["httpx_screenshot"] = True
            for k, (lo, hi) in _CAPS.items():
                if k in s:
                    try:
                        s[k] = max(lo, min(hi, int(s[k])))
                    except (ValueError, TypeError):
                        s[k] = DEFAULT_SETTINGS.get(k, lo)
            _cache.clear()
            _cache.update(s)
            _cache_mtime = mtime
            return dict(s)
        except Exception:
            pass
    return DEFAULT_SETTINGS.copy()


def save_settings(s: Dict) -> None:
    """Atomic settings write — tmp + rename. Invalidates cache."""
    global _cache_mtime
    tmp = Path(str(SETTINGS_F) + ".tmp")
    tmp.write_text(json.dumps(s, indent=2))
    tmp.replace(SETTINGS_F)
    _cache.clear()
    _cache_mtime = 0.0
