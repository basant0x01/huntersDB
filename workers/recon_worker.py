"""
workers/recon_worker.py — Recon Intelligence job handler.

Handles job_type='recon_intel' dispatched by queue_consumer.py.

Modes:
  "full"       — parallel recon tools (naabu/katana/etc.) + HackedList leak check
  "recon_only" — only tool-based recon (ports, crawl, secrets, dirs, etc.)
  "leak_only"  — only HackedList leak check (fast, 1 API call per root domain)

Performance:
  - RECON_CONCURRENT = 1  # 1 sub at a time — each runs 8+ tools
  - Leak check groups subs by root domain → 1 HackedList call covers all subs
  - Phase 1 (naabu/crawl/gau/wayback/subzy/s3/censys/screenshot) parallel
  - Phase 2 (linkfinder/trufflehog/retirejs/ffuf/broken-links) parallel on Phase 1 data
"""
import asyncio
import logging
from datetime import datetime
from typing import Dict, List, Optional

from config.settings import PHASE_C_CONCURRENT
from db.recon_schema import (
    run_recon_migrations,
    upsert_recon_result,
    upsert_leak_intel,
)
from utils.log import log
from workers.leak_intelligence import (
    check_project_leaks,
    check_subdomain_leaks,
    correlate_findings,
)
from workers.recon_intelligence import run_full_recon, calculate_risk_score

logger = logging.getLogger("workers.recon_worker")

# 5 parallel subdomains — balanced for speed vs resource use
RECON_CONCURRENT = 1  # process 1 sub at a time — each sub already runs 8+ tools


async def run_recon_intel_job(
    pool,
    project_id: str,
    job_id: Optional[str],
    mode: str = "full",
) -> Dict:
    """Run recon intelligence for all live subdomains of a project."""
    await run_recon_migrations(pool)

    async with pool.acquire() as conn:
        proj_row = await conn.fetchrow(
            "SELECT id, name FROM projects WHERE id=$1", project_id
        )
        if not proj_row:
            logger.error("Project %s not found", project_id)
            return {"error": "Project not found"}

        live_rows = await conn.fetch(
            """SELECT subdomain, url FROM subdomains
               WHERE project_id=$1 AND is_alive=1
               ORDER BY last_seen DESC""",
            project_id,
        )

    project_name = proj_row["name"]
    total = len(live_rows)

    await log(pool, f"[ReconIntel] {mode} | {project_name} | {total} live subs",
              "info", "recon_intel", job_id)

    if total == 0:
        await log(pool, f"[ReconIntel] No live subdomains for {project_name}",
                  "warning", "recon_intel", job_id)
        return {"scanned": 0, "project_name": project_name}

    # ── LEAK ONLY ──────────────────────────────────────────────────────────
    if mode == "leak_only":
        await log(pool, f"[LeakIntel] Starting for {project_name}…", "info", "leaks", job_id)
        result = await check_project_leaks(pool, project_id, job_id)
        await log(
            pool,
            f"[LeakIntel] ✓ {project_name}: {result['checked']} checked, "
            f"{result['compromised']} compromised",
            "success", "leaks", job_id,
        )
        return {"scanned": result["checked"], "leaks_found": result["compromised"],
                "project_name": project_name}

    # ── RECON ONLY ─────────────────────────────────────────────────────────
    if mode == "recon_only":
        return await _run_recon_tools(pool, project_id, project_name, live_rows, total, job_id)

    # ── FULL (recon tools + leak check in parallel) ─────────────────────────
    await log(pool, f"[ReconIntel] Full scan: recon + leak check in parallel", "info", "recon_intel", job_id)

    # Start leak check as a background task (efficient: 1 API call per root domain)
    leak_task = asyncio.create_task(check_project_leaks(pool, project_id, job_id))

    # Run recon tools concurrently
    recon_result = await _run_recon_tools(pool, project_id, project_name, live_rows, total, job_id)

    # Wait for leak check to finish
    try:
        leak_result = await asyncio.wait_for(leak_task, timeout=120)
    except asyncio.TimeoutError:
        leak_result = {"checked": 0, "compromised": 0}
        await log(pool, f"[LeakIntel] Timeout — will retry on next scan", "warning", "leaks", job_id)
    except Exception as e:
        leak_result = {"checked": 0, "compromised": 0}
        await log(pool, f"[LeakIntel] Error: {e}", "error", "leaks", job_id)

    await log(
        pool,
        f"[ReconIntel] ✓ {project_name}: {recon_result['scanned']}/{total} recon | "
        f"{leak_result.get('compromised', 0)} subs with leak data",
        "success", "recon_intel", job_id,
    )
    return {**recon_result, "leaks_found": leak_result.get("compromised", 0)}


async def _run_recon_tools(pool, project_id, project_name, live_rows, total, job_id) -> Dict:
    """Run naabu/katana/trufflehog/etc. for all live subdomains in parallel batches."""
    sem = asyncio.Semaphore(RECON_CONCURRENT)
    done = [0]
    errors = [0]

    async def process_one(subdomain: str, url: str) -> None:
        async with sem:
            try:
                recon_data = await run_full_recon(subdomain, url, job_id, pool, project_id=project_id)
                recon_data["risk"] = calculate_risk_score(recon_data)
                async with pool.acquire() as conn:
                    await upsert_recon_result(conn, project_id, recon_data)
                done[0] += 1
                await asyncio.sleep(1)  # 1s pause between subs — lets CPU recover
                # Progress every 3 subs or at the end
                if done[0] % 3 == 0 or done[0] == total:
                    pct = int(done[0] / total * 100)
                    await log(
                        pool,
                        f"[ReconIntel] {project_name}: {done[0]}/{total} ({pct}%) — "
                        f"ports={len(recon_data.get('ports',[]))} "
                        f"secrets={len(recon_data.get('js_secrets',[]))} "
                        f"score={recon_data.get('risk',{}).get('score',0)}",
                        "info", "recon_intel", job_id,
                    )
            except Exception as e:
                errors[0] += 1
                logger.error("Recon error for %s: %s", subdomain, e)
                await log(pool, f"[ReconIntel] Error {subdomain}: {e}",
                          "warning", "recon_intel", job_id)

    await asyncio.gather(*[
        process_one(r["subdomain"], r["url"] or f"https://{r['subdomain']}")
        for r in live_rows
    ])

    await log(
        pool,
        f"[ReconIntel] ✓ {project_name}: {done[0]}/{total} done, {errors[0]} errors",
        "success", "recon_intel", job_id,
    )
    return {"scanned": done[0], "total": total, "errors": errors[0],
            "project_name": project_name}
