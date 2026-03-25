"""
api/routes_recon.py — Recon Intelligence API endpoints.

FIX-RECON-01: Single-subdomain inline recon (_run coroutine) was calling
              run_full_recon(subdomain, url) without the required job_id,
              pool, and project_id arguments — all defaulted to None,
              causing tool_status updates and DB upserts to silently fail.

FIX-RECON-02: /api/scan/bulk in routes_server.py is a broken duplicate that
              doesn't load scope from DB. The correct endpoint is
              /api/projects/bulk-scan in routes_projects.py. Added a comment
              here to document the preferred endpoint.

FIX-RECON-03: run_recon_migrations() removed from per-request path (BUG-16).
              Already fixed in original — preserved here.
"""
import asyncio
import json
import logging
import mimetypes
import uuid
from datetime import datetime
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import FileResponse, JSONResponse

from api.auth import require_auth
from config.settings import BASE_DIR
from db.pool import get_pool
from db.recon_schema import (
    get_leak_intel,
    get_project_recon_summary,
    get_recon_result,
    run_recon_migrations,
    upsert_leak_intel,
    upsert_recon_result,
)
from task_queue.redis_queue import enqueue

logger = logging.getLogger("api.routes_recon")
router = APIRouter()

# Strong references prevent GC of fire-and-forget tasks (BUG-17 fix)
_recon_tasks: set = set()


# ── Trigger full project recon ────────────────────────────────────────────────

@router.post("/api/projects/{pid}/recon/run")
async def api_trigger_recon(
    pid: str,
    request: Request,
    _: str = Depends(require_auth),
):
    """Enqueue full recon intelligence scan for all live subdomains."""
    pool = await get_pool()

    async with pool.acquire() as conn:
        row = await conn.fetchrow("SELECT id, name FROM projects WHERE id=$1", pid)
    if not row:
        raise HTTPException(status_code=404, detail="Project not found")

    try:
        data = await request.json()
    except Exception:
        data = {}

    jid = str(uuid.uuid4())
    result = await enqueue(
        job_type="recon_intel",
        project_id=pid,
        priority=1,
        job_id=jid,
        payload={
            "project_name": row["name"],
            "mode": data.get("mode", "full"),
        },
    )
    return {**result, "project_id": pid, "project_name": row["name"]}


# ── Trigger single-subdomain recon (inline, async task) ──────────────────────

@router.post("/api/projects/{pid}/recon/{subdomain:path}/run")
async def api_trigger_single_recon(
    pid: str,
    subdomain: str,
    _: str = Depends(require_auth),
):
    """Trigger recon for a single live subdomain. Fires async task, returns immediately."""
    pool = await get_pool()

    async with pool.acquire() as conn:
        sub_row = await conn.fetchrow(
            "SELECT subdomain, url FROM subdomains "
            "WHERE project_id=$1 AND subdomain=$2 AND is_alive=1",
            pid, subdomain,
        )
    if not sub_row:
        raise HTTPException(status_code=404, detail="Subdomain not found or not alive")

    url = sub_row["url"] or f"https://{subdomain}"
    # Generate a job_id for logging correlation
    jid = str(uuid.uuid4())

    async def _run() -> None:
        # FIX-RECON-01: pass pool, job_id, and project_id — previously all were None
        from workers.leak_intelligence import check_subdomain_leaks
        from workers.recon_intelligence import calculate_risk_score, run_full_recon
        from workers.leak_intelligence import correlate_findings

        pool_ = await get_pool()
        recon_data = await run_full_recon(
            subdomain=subdomain,
            url=url,
            job_id=jid,
            pool=pool_,
            project_id=pid,
        )
        leak_data = await check_subdomain_leaks(subdomain)

        recon_data["leak_intel"] = leak_data
        recon_data["risk"] = calculate_risk_score(recon_data)
        recon_data["correlations"] = correlate_findings(leak_data, recon_data)

        async with pool_.acquire() as conn:
            await upsert_recon_result(conn, pid, recon_data)
            await upsert_leak_intel(conn, pid, leak_data)

    # FIX-RECON-01 (continued): keep task reference so GC doesn't discard it
    task = asyncio.create_task(_run())
    _recon_tasks.add(task)
    task.add_done_callback(_recon_tasks.discard)
    return {"ok": True, "message": f"Recon started for {subdomain}", "subdomain": subdomain, "job_id": jid}


# ── Single subdomain leak check ───────────────────────────────────────────────

@router.post("/api/projects/{pid}/recon/{subdomain:path}/leak-check")
async def api_run_leak_check(
    pid: str,
    subdomain: str,
    _: str = Depends(require_auth),
):
    """Trigger an immediate leak intelligence check for a single subdomain."""
    pool = await get_pool()

    async def _check() -> None:
        from workers.leak_intelligence import check_subdomain_leaks
        leak_data = await check_subdomain_leaks(subdomain)
        pool_ = await get_pool()
        async with pool_.acquire() as conn:
            await upsert_leak_intel(conn, pid, leak_data)

    task = asyncio.create_task(_check())
    _recon_tasks.add(task)
    task.add_done_callback(_recon_tasks.discard)
    return {"ok": True, "message": f"Leak check started for {subdomain}"}


# ── List recon results for project ────────────────────────────────────────────

@router.get("/api/projects/{pid}/recon")
async def api_get_recon_list(
    pid: str,
    page: int = Query(1, ge=1),
    per_page: int = Query(100, ge=1, le=500),
    severity: str = Query(""),
    search: str = Query(""),
    _: str = Depends(require_auth),
):
    """List all recon results for a project, ordered by risk score desc."""
    pool = await get_pool()
    offset = (page - 1) * per_page
    conditions = ["r.project_id=$1"]
    params = [pid]
    idx = 2

    if severity:
        conditions.append(f"r.risk_severity=${idx}")
        params.append(severity)
        idx += 1
    if search:
        conditions.append(f"r.subdomain ILIKE ${idx}")
        params.append(f"%{search}%")
        idx += 1

    where = "WHERE " + " AND ".join(conditions)

    async with pool.acquire() as conn:
        total = await conn.fetchval(
            f"SELECT COUNT(*) FROM recon_results r {where}", *params
        )
        rows = await conn.fetch(
            f"""SELECT r.subdomain, r.url, r.ports, r.js_secrets,
                       r.takeover, r.s3_buckets, r.origin_ip, r.screenshot,
                       r.risk_score, r.risk_severity, r.risk_factors, r.scanned_at,
                       l.compromised, l.sources AS leak_sources,
                       l.total_records AS leaked_records, l.checked_at
                FROM recon_results r
                LEFT JOIN leak_intel l
                       ON r.project_id = l.project_id AND r.subdomain = l.subdomain
                {where}
                ORDER BY r.risk_score DESC, r.scanned_at DESC
                LIMIT ${idx} OFFSET ${idx+1}""",
            *params, per_page, offset,
        )

    results = []
    for row in rows:
        d = dict(row)
        for field in ("ports", "js_secrets", "s3_buckets", "risk_factors"):
            try:
                d[field] = json.loads(d.get(field) or "[]")
            except Exception:
                d[field] = []
        for field in ("takeover",):
            try:
                d[field] = json.loads(d.get(field) or "{}")
            except Exception:
                d[field] = {}
        try:
            d["leak_sources"] = json.loads(d.get("leak_sources") or "[]")
        except Exception:
            d["leak_sources"] = []
        results.append(d)

    return {
        "results": results,
        "total": total,
        "page": page,
        "per_page": per_page,
        "pages": max(1, (total + per_page - 1) // per_page),
    }


# ── Project recon summary ─────────────────────────────────────────────────────

@router.get("/api/projects/{pid}/recon/summary")
async def api_get_recon_summary(
    pid: str,
    _: str = Depends(require_auth),
):
    """Aggregated recon summary for a project dashboard."""
    pool = await get_pool()

    async with pool.acquire() as conn:
        summary = await get_project_recon_summary(conn, pid)
        top_risky = await conn.fetch(
            """SELECT r.subdomain, r.risk_score, r.risk_severity, r.ports,
                      r.takeover, r.screenshot,
                      l.compromised, l.total_records
               FROM recon_results r
               LEFT JOIN leak_intel l
                      ON r.project_id = l.project_id AND r.subdomain = l.subdomain
               WHERE r.project_id=$1
               ORDER BY r.risk_score DESC LIMIT 10""",
            pid,
        )
        secrets_count = await conn.fetchval(
            """SELECT COUNT(*) FROM recon_results
               WHERE project_id=$1 AND js_secrets != '[]' AND js_secrets != ''""",
            pid,
        )
        takeover_count = await conn.fetchval(
            """SELECT COUNT(*) FROM recon_results
               WHERE project_id=$1 AND takeover::text LIKE '%"vulnerable": true%'""",
            pid,
        )
        # Email security counts (from recon_schema email_security column if present)
        try:
            email_sec_count = await conn.fetchval(
                """SELECT COUNT(*) FROM recon_results
                   WHERE project_id=$1
                   AND (email_security::text LIKE '%"spf_missing": true%'
                        OR email_security::text LIKE '%"dmarc_missing": true%')""",
                pid,
            ) or 0
        except Exception:
            email_sec_count = 0

    top = []
    for row in top_risky:
        d = dict(row)
        try:
            d["ports"] = json.loads(d.get("ports") or "[]")
        except Exception:
            d["ports"] = []
        try:
            d["takeover"] = json.loads(d.get("takeover") or "{}")
        except Exception:
            d["takeover"] = {}
        top.append(d)

    return {
        **summary,
        "top_risky": top,
        "secrets_found": secrets_count or 0,
        "takeovers_found": takeover_count or 0,
        "email_security_issues": email_sec_count,
    }


# ── Screenshot serving — MUST be before {subdomain:path} catch-all ────────────

@router.get("/api/projects/{pid}/recon/{subdomain:path}/screenshot")
async def api_get_screenshot_by_project(
    pid: str,
    subdomain: str,
    _: str = Depends(require_auth),
):
    path = _find_screenshot(subdomain)
    if not path or not path.exists():
        raise HTTPException(status_code=404, detail="Screenshot not available")
    media_type = mimetypes.guess_type(str(path))[0] or "image/png"
    return FileResponse(str(path), media_type=media_type)


# ── Single subdomain full detail ──────────────────────────────────────────────

@router.get("/api/projects/{pid}/recon/{subdomain:path}")
async def api_get_recon_detail(
    pid: str,
    subdomain: str,
    _: str = Depends(require_auth),
):
    """Full recon + leak + vuln detail for one subdomain."""
    pool = await get_pool()

    async with pool.acquire() as conn:
        recon = await get_recon_result(conn, pid, subdomain)
        leak  = await get_leak_intel(conn, pid, subdomain)
        sub_row = await conn.fetchrow(
            "SELECT * FROM subdomains WHERE project_id=$1 AND subdomain=$2",
            pid, subdomain,
        )
        vulns = await conn.fetch(
            """SELECT id, name, severity, url, template_id, description,
                      matched_at, curl_cmd, review_status, created_at
               FROM vulnerabilities
               WHERE project_id=$1 AND url ILIKE $2
               ORDER BY CASE severity
                 WHEN 'critical' THEN 1 WHEN 'high' THEN 2
                 WHEN 'medium'   THEN 3 WHEN 'low'  THEN 4 ELSE 5 END,
                 created_at DESC""",
            pid, f"%{subdomain}%",
        )

    return {
        "subdomain":   subdomain,
        "httpx_data":  dict(sub_row) if sub_row else None,
        "recon":       recon,
        "leak_intel":  leak,
        "vulnerabilities": [dict(v) for v in vulns],
    }


# ── Leak intelligence list ────────────────────────────────────────────────────

@router.get("/api/projects/{pid}/leak-intel")
async def api_get_leak_list(
    pid: str,
    page: int = Query(1, ge=1),
    per_page: int = Query(100, ge=1, le=500),
    compromised_only: bool = Query(False),
    _: str = Depends(require_auth),
):
    pool = await get_pool()
    offset = (page - 1) * per_page
    conditions = ["project_id=$1"]
    params = [pid]
    if compromised_only:
        conditions.append("compromised=1")

    where = "WHERE " + " AND ".join(conditions)
    async with pool.acquire() as conn:
        total = await conn.fetchval(
            f"SELECT COUNT(*) FROM leak_intel {where}", *params
        )
        rows = await conn.fetch(
            f"""SELECT id, subdomain, domain, compromised, sources,
                       emails, passwords, total_records,
                       first_seen, last_seen, checked_at
                FROM leak_intel {where}
                ORDER BY compromised DESC, total_records DESC
                LIMIT ${len(params)+1} OFFSET ${len(params)+2}""",
            *params, per_page, offset,
        )

    results = []
    for row in rows:
        d = dict(row)
        for col in ("sources", "emails", "passwords"):
            try:
                raw = d.get(col) or "[]"
                d[col] = json.loads(raw) if isinstance(raw, str) else (raw or [])
            except Exception:
                d[col] = []
        results.append(d)

    return {
        "results": results,
        "total": total,
        "page": page,
        "per_page": per_page,
    }


# ── Leak intel status ────────────────────────────────────────────────────────

@router.get("/api/projects/{pid}/leak-intel/status")
async def api_leak_intel_status(
    pid: str,
    _: str = Depends(require_auth),
):
    pool = await get_pool()
    async with pool.acquire() as conn:
        total = await conn.fetchval(
            "SELECT COUNT(*) FROM leak_intel WHERE project_id=$1", pid) or 0
        compromised = await conn.fetchval(
            "SELECT COUNT(*) FROM leak_intel WHERE project_id=$1 AND compromised=1",
            pid) or 0
        emails_count = await conn.fetchval(
            "SELECT COUNT(*) FROM leak_intel WHERE project_id=$1 AND emails != '[]' AND emails IS NOT NULL",
            pid) or 0
        passwords_count = await conn.fetchval(
            "SELECT COUNT(*) FROM leak_intel WHERE project_id=$1 AND passwords != '[]' AND passwords IS NOT NULL",
            pid) or 0
    return {
        "checked":     total,
        "compromised": compromised,
        "emails":      emails_count,
        "passwords":   passwords_count,
    }


# ── Leak intel detail ─────────────────────────────────────────────────────────

@router.get("/api/projects/{pid}/leak-intel/{subdomain:path}")
async def api_get_leak_detail(
    pid: str,
    subdomain: str,
    _: str = Depends(require_auth),
):
    pool = await get_pool()
    async with pool.acquire() as conn:
        leak = await get_leak_intel(conn, pid, subdomain)
    if not leak:
        raise HTTPException(status_code=404, detail="No leak data found for this subdomain")
    return leak


# ── Screenshot helpers ────────────────────────────────────────────────────────

def _find_screenshot(subdomain: str) -> Optional[Path]:
    import re
    safe = re.sub(r"[^a-z0-9\-]", "_", subdomain.lower())
    screenshots_dir = BASE_DIR / "screenshots"
    if not screenshots_dir.exists():
        return None

    for candidate in [safe, subdomain.replace(".", "_"), subdomain.replace(".", "-")]:
        sub_dir = screenshots_dir / candidate
        if sub_dir.exists():
            for ext in ("*.png", "*.jpg", "*.jpeg"):
                files = list(sub_dir.rglob(ext))
                if files:
                    return sorted(files, key=lambda p: p.stat().st_mtime, reverse=True)[0]

    for sub_dir in screenshots_dir.iterdir():
        if not sub_dir.is_dir():
            continue
        sub_safe = subdomain.split(".")[0].replace("-", "_")
        if sub_safe in sub_dir.name or sub_dir.name.startswith(safe[:8]):
            for ext in ("*.png", "*.jpg", "*.jpeg"):
                files = list(sub_dir.rglob(ext))
                if files:
                    return sorted(files, key=lambda p: p.stat().st_mtime, reverse=True)[0]
    return None


@router.get("/screenshots/{subdomain:path}")
async def api_serve_screenshot(
    subdomain: str,
    _: str = Depends(require_auth),
):
    path = _find_screenshot(subdomain)
    if not path or not path.exists():
        raise HTTPException(status_code=404, detail="Screenshot not found")
    media_type = mimetypes.guess_type(str(path))[0] or "image/png"
    return FileResponse(str(path), media_type=media_type)
