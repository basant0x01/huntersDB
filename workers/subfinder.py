"""
workers/subfinder.py — Async subfinder wrapper.
"""
import asyncio
import logging
import uuid
from pathlib import Path
from typing import List, Optional

from config.settings import CHAOS_DIR, SUBFINDER_TIMEOUT_SECS
from process_manager.manager import manager
from utils.settings import load_settings

logger = logging.getLogger("workers.subfinder")


async def run_subfinder(domain: str, job_id: Optional[str] = None) -> List[str]:
    """Run subfinder for a domain. Returns list of discovered subdomains."""
    s = load_settings()
    threads = s.get("subfinder_threads", 200)
    uid = uuid.uuid4().hex
    out_file = CHAOS_DIR / f"sf_out_{uid}.txt"

    cmd = [
        "subfinder",
        "-d", domain,
        "-o", str(out_file),
        "-silent",
        "-t", str(threads),
        "-timeout", "30",
    ]

    try:
        rc, stdout, stderr = await manager.run(
            name=f"subfinder_{domain[:20]}",
            cmd=cmd,
            timeout_secs=SUBFINDER_TIMEOUT_SECS,
        )
        if rc != 0 and rc != -127:
            logger.warning("subfinder exited %d for %s", rc, domain)

        subs = []
        if out_file.exists():
            content = await asyncio.to_thread(out_file.read_text, errors="ignore")
            subs = [l.strip().lower() for l in content.splitlines() if l.strip()]

        logger.debug("subfinder: %s → %d subs", domain, len(subs))
        return subs

    except Exception as e:
        logger.error("subfinder error for %s: %s", domain, e)
        return []
    finally:
        try:
            await asyncio.to_thread(out_file.unlink, missing_ok=True)
        except Exception:
            pass
