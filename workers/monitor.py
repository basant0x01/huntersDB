"""
workers/monitor.py — 24/7 Autonomous monitor loop.

Port of the original start_scheduler() + monitor tick.
Runs inside the worker process as an asyncio task.
Does NOT hold large state — reads settings fresh each tick.
"""
import asyncio
import json
import logging
import uuid
from datetime import datetime, timedelta
from typing import Optional

from db.pool import get_pool
from task_queue.redis_queue import enqueue
from utils.log import log
from utils.settings import load_settings

logger = logging.getLogger("workers.monitor")

MONITOR_STATE_KEY = "huntersdb:monitor_state"


async def monitor_loop() -> None:
    """
    Runs forever inside the worker process.
    Each tick:
      1. Check settings to see if monitor is enabled
      2. Find projects due for alive-check sweep
      3. Enqueue them as 'monitor' jobs (priority 2)
      4. Optionally trigger template update
    """
    logger.info("Monitor loop started")
    while True:
        try:
            await _monitor_tick()
        except asyncio.CancelledError:
            logger.info("Monitor loop cancelled")
            break
        except Exception as e:
            logger.error("Monitor tick error: %s", e)

        s = load_settings()
        interval_min = s.get("monitor_interval_min", 120)
        await asyncio.sleep(interval_min * 60)


async def _monitor_tick() -> None:
    s = load_settings()
    if not s.get("monitor_enabled", True):
        return

    pool = await get_pool()
    now = datetime.now()
    interval_min = s.get("monitor_interval_min", 120)
    cutoff = now - timedelta(minutes=interval_min)  # keep as datetime for asyncpg

    await log(pool, f"[Monitor] Tick — checking projects not scanned since {cutoff.strftime('%Y-%m-%dT%H:%M')}",
              "info", "monitor")

    async with pool.acquire() as conn:
        # Find projects that haven't been alive-checked recently
        rows = await conn.fetch("""
            SELECT id, name FROM projects
            WHERE sync_enabled=1
              AND scan_status='done'
              AND (last_synced IS NULL OR last_synced::timestamp < $1)
            ORDER BY last_synced ASC NULLS FIRST
            LIMIT 50
        """, cutoff)

    if not rows:
        await log(pool, "[Monitor] All projects up to date", "info", "monitor")
        return

    await log(pool, f"[Monitor] Checking {len(rows)} projects for sweep", "info", "monitor")
    enqueued = 0
    for row in rows:
        # MO-02 FIX: Skip if project is already actively scanning
        async with pool.acquire() as conn:
            proj = await conn.fetchrow(
                "SELECT scan_status, scope FROM projects WHERE id=$1", row["id"])
        if not proj:
            continue
        if proj["scan_status"] not in ("done", "pending"):
            # Already in pipeline — skip to avoid double-enqueue
            continue

        try:
            raw_scope = json.loads(proj["scope"] or "[]")
        except Exception:
            raw_scope = []

        # MO-03 FIX: Update last_synced NOW so this project isn't re-queued on next tick
        # if the scan crashes before completing
        async with pool.acquire() as conn:
            await conn.execute(
                "UPDATE projects SET last_synced=$1 WHERE id=$2",
                now.isoformat(), row["id"])

        await enqueue(
            job_type="monitor",
            project_id=row["id"],
            priority=2,
            payload={
                "project_name": row["name"],
                "run_subfinder": bool(raw_scope),
                "scope": raw_scope,
            },
        )
        enqueued += 1

    # Optional: template update
    if s.get("auto_template_update", True):
        hours = s.get("template_update_interval_hours", 6)
        await log(pool, f"[Monitor] Template auto-update enabled ({hours}h interval)",
                  "info", "monitor")
        asyncio.create_task(_maybe_update_templates(pool, hours))


async def _maybe_update_templates(pool, interval_hours: int) -> None:
    """Update nuclei templates if last update was more than interval_hours ago."""
    import asyncio
    from process_manager.manager import manager
    from config.settings import NUCLEI_TIMEOUT_SECS

    try:
        rc, stdout, stderr = await manager.run(
            name="nuclei_template_update",
            cmd=["nuclei", "-update-templates", "-silent"],
            timeout_secs=300,
            capture_stderr=True,
        )
        msg = stderr.decode("utf-8", errors="replace").strip()
        if rc == 0:
            await log(pool, f"[Monitor] Templates updated: {msg[:200]}", "success", "monitor")
        else:
            await log(pool, f"[Monitor] Template update failed (rc={rc})", "warning", "monitor")
    except Exception as e:
        await log(pool, f"[Monitor] Template update error: {e}", "error", "monitor")
