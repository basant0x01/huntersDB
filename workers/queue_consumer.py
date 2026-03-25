"""
workers/queue_consumer.py — The worker process.

FIX-QC-01: Auto-nuclei trigger using is_new=1 query removed from here.
           Phase C resets is_new=0 before this code ran, so it always
           found 0 new subs and never triggered nuclei. The trigger
           is now correctly placed inside run_all_phases_ordered()
           in scanning.py, using the newly_discovered count returned
           by Phase B (resurrected + brand-new alive hosts).

Run this in a SEPARATE PROCESS from the API server:
  python -m workers.queue_consumer
"""
import asyncio
import json
import logging
import os
import signal
import sys
import uuid
from datetime import datetime
from pathlib import Path
from typing import Optional

sys.path.insert(0, str(Path(__file__).parent.parent))

from config.settings import MAX_CONCURRENT_TASKS
from db.migrations import run_migrations, startup_recovery
from db.pool import get_pool, close_pool
from db.queries import set_phase, upsert_subdomains, get_project
from process_manager.manager import manager
from task_queue.redis_queue import (
    dequeue, requeue_with_retry, set_job_status,
    get_queue_depth, enqueue, close_redis,
)
from workers.scanning import run_all_phases_ordered, scan_project_recon, scan_project_nuclei
from workers.sync_worker import run_chaos_sync, run_bbscope_sync
from utils.log import log, flush_log_buffer
from utils.settings import load_settings

logger = logging.getLogger("worker.consumer")

# BUG-03 FIX: _shutdown created inside worker_main() after the event loop starts
_shutdown: asyncio.Event


async def process_job(pool, job: dict) -> None:
    """Dispatch a single job to the appropriate handler."""
    jid   = job.get("job_id", str(uuid.uuid4()))
    jtype = job.get("job_type", "")
    pid   = job.get("project_id")
    payload = job.get("payload", {})

    await set_job_status(jid, "running", meta={"started_at": datetime.now().isoformat()})
    await log(pool, f"Worker: starting job {jid} type={jtype} project={pid}",
              "info", "worker", jid)

    try:
        if jtype in ("scan", "new_sub", "sweep", "rescan"):
            if not pid:
                raise ValueError("scan job requires project_id")
            run_subfinder_flag = payload.get("run_subfinder", False)
            scope_list = payload.get("scope", [])
            is_resume  = payload.get("auto_resumed", False)
            resume_from = payload.get("resume_from", "")
            if is_resume:
                await log(pool,
                    f"[AUTO-RESUME] Continuing {payload.get('project_name', pid)} "
                    f"from {resume_from} (interrupted by server restart)",
                    "info", "worker", jid)
            await run_all_phases_ordered(
                pool=pool,
                projects=[{
                    "id": pid,
                    "name": payload.get("project_name", pid),
                    "run_subfinder": run_subfinder_flag,
                    "scope": scope_list,
                }],
                job_id=jid,
                label="RESUME" if is_resume else "SCAN",
            )

        elif jtype == "scan_bulk":
            projects_raw = payload.get("projects", [])
            if not projects_raw:
                raise ValueError("scan_bulk requires payload.projects")
            projects = []
            async with pool.acquire() as conn:
                for p in projects_raw:
                    row = await conn.fetchrow(
                        "SELECT id, name, scope FROM projects WHERE id=$1", p["id"])
                    if row:
                        try:
                            scope = json.loads(row["scope"] or "[]")
                        except Exception:
                            scope = []
                        projects.append({
                            "id": row["id"],
                            "name": row["name"],
                            "run_subfinder": bool(scope),
                            "scope": scope,
                        })
            await run_all_phases_ordered(
                pool=pool, projects=projects, job_id=jid, label="BULK")

        elif jtype == "monitor":
            if not pid:
                raise ValueError("monitor job requires project_id")
            await scan_project_recon(
                pool, pid, jid,
                run_subfinder=payload.get("run_subfinder", False),
                scope=payload.get("scope", []),
            )

        elif jtype == "chaos_sync":
            bounty_only = payload.get("bounty_only", True)
            platform    = payload.get("platform")
            await run_chaos_sync(pool, jid, bounty_only=bounty_only, platform=platform)

        elif jtype == "h1_sync":
            from utils.settings import load_settings as _ls
            _s = _ls()
            _h1u = payload.get("username") or _s.get("h1_username","") or _s.get("bbscope_hackerone_username","")
            _h1t = payload.get("token")    or _s.get("h1_token","")    or _s.get("bbscope_hackerone_token","")
            await run_bbscope_sync(pool, jid, platform="hackerone",
                                   username=_h1u, token=_h1t)

        elif jtype == "ywh_sync":
            from utils.settings import load_settings as _ls
            _s = _ls()
            _ywht = payload.get("token") or _s.get("ywh_token","") or _s.get("bbscope_yeswehack_token","")
            await run_bbscope_sync(pool, jid, platform="yeswehack", token=_ywht)

        elif jtype == "nuclei_only":
            if not pid:
                raise ValueError("nuclei_only job requires project_id")
            await scan_project_nuclei(
                pool, pid, jid,
                templates=payload.get("templates"),
                severity=payload.get("severity"),
            )

        elif jtype == "templates_update":
            await log(pool, "Updating nuclei templates...", "info", "nuclei", jid)
            rc, _, stderr = await manager.run(
                "nuclei-update", ["nuclei", "-update-templates"],
                timeout_secs=300, capture_stderr=True)
            if rc == 0:
                await log(pool, "Nuclei templates updated successfully", "success", "nuclei", jid)
            else:
                raise RuntimeError(f"nuclei -update-templates failed rc={rc}: {stderr.decode()[:200]}")

        elif jtype == "nuclei_sweep":
            templates = payload.get("templates")
            severity  = payload.get("severity")
            await log(pool, "Starting nuclei sweep across all alive hosts...", "info", "nuclei", jid)
            async with pool.acquire() as conn:
                rows = await conn.fetch(
                    "SELECT DISTINCT project_id FROM subdomains WHERE is_alive=1")
            project_ids = [r["project_id"] for r in rows]
            for sweep_pid in project_ids:
                if _shutdown.is_set():
                    break
                await scan_project_nuclei(pool, str(sweep_pid), jid)
            await log(pool, f"Nuclei sweep done ({len(project_ids)} projects)", "success", "nuclei", jid)

        elif jtype == "backup_restore":
            path = payload.get("path", "")
            await log(pool, f"Backup restore requested (path={path!r}) — not implemented",
                      "warning", "worker", jid)

        elif jtype == "recon_intel":
            if not pid:
                raise ValueError("recon_intel job requires project_id")
            from workers.recon_worker import run_recon_intel_job
            mode = payload.get("mode", "full")
            await run_recon_intel_job(pool, pid, jid, mode=mode)

        else:
            raise ValueError(f"Unknown job type: {jtype!r}")

        await set_job_status(jid, "done", meta={"ended_at": datetime.now().isoformat()})
        await log(pool, f"Worker: job {jid} completed", "success", "worker", jid)
        await asyncio.sleep(0.2)

        # FIX-QC-01: Auto-nuclei trigger REMOVED from here.
        # It is now handled inside run_all_phases_ordered() in scanning.py
        # using the newly_discovered count from Phase B (correct) instead of
        # querying is_new=1 after Phase C resets it (broken — always 0).

    except Exception as e:
        error_msg = f"{type(e).__name__}: {e}"
        await log(pool, f"Worker: job {jid} FAILED — {error_msg}", "error", "worker", jid)
        requeued = await requeue_with_retry(job, error_msg)
        if not requeued:
            await log(pool, f"Worker: job {jid} sent to DLQ", "warning", "worker", jid)
        raise


async def worker_main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(name)s] %(levelname)s %(message)s",
    )
    logger.info("SUBMIND PRO Worker starting...")

    global _shutdown
    _shutdown = asyncio.Event()

    loop = asyncio.get_running_loop()
    def _handle_signal_safe(sig, frame=None):
        logger.warning("Worker received signal %s — initiating graceful shutdown", sig)
        loop.call_soon_threadsafe(_shutdown.set)

    signal.signal(signal.SIGTERM, _handle_signal_safe)
    signal.signal(signal.SIGINT,  _handle_signal_safe)

    pool = await get_pool()
    await run_migrations()

    try:
        await startup_recovery(pool)
    except Exception as _rec_err:
        logger.error("startup_recovery failed (worker will still start): %s", _rec_err)

    watchdog_task = asyncio.create_task(manager.watchdog_loop())

    from workers.monitor import monitor_loop
    monitor_task = asyncio.create_task(monitor_loop())

    sem = asyncio.Semaphore(MAX_CONCURRENT_TASKS)
    active_tasks = set()
    _job_count = [0]

    logger.info("Worker ready. Listening on task_queue... (MAX_CONCURRENT_TASKS=%d)", MAX_CONCURRENT_TASKS)

    try:
        while not _shutdown.is_set():
            try:
                job = await asyncio.wait_for(_poll_with_backoff(), timeout=2.0)
            except asyncio.TimeoutError:
                continue

            if job is None:
                continue

            await sem.acquire()

            async def _run(j):
                try:
                    await process_job(pool, j)
                except Exception:
                    pass
                finally:
                    sem.release()
                    _job_count[0] += 1
                    if _job_count[0] % 50 == 0:
                        import gc
                        gc.collect()

            task = asyncio.create_task(_run(job))
            active_tasks.add(task)
            task.add_done_callback(active_tasks.discard)

    finally:
        logger.info("Worker shutting down — waiting for %d active tasks...", len(active_tasks))
        if active_tasks:
            await asyncio.gather(*active_tasks, return_exceptions=True)

        watchdog_task.cancel()
        monitor_task.cancel()
        await manager.kill_all()
        await flush_log_buffer(pool)
        await close_pool()
        await close_redis()
        logger.info("Worker shutdown complete")


def _make_poll_with_backoff():
    backoff = [0.1]
    async def _poll() -> Optional[dict]:
        job = await dequeue()
        if job is None:
            backoff[0] = min(backoff[0] * 1.5, 5.0)
            await asyncio.sleep(backoff[0])
        else:
            backoff[0] = 0.1
        return job
    return _poll

_poll_with_backoff = _make_poll_with_backoff()


if __name__ == "__main__":
    asyncio.run(worker_main())
