"""
api/routes_projects.py — Project, subdomain, vulnerability, alert, and review endpoints.

All routes async. All DB calls use the asyncpg pool.
Scanning is dispatched to the worker task_queue, never run inline.
"""
import csv
import io
import json
import uuid
from datetime import datetime
from math import ceil
from typing import Optional

from fastapi import APIRouter, Request, Depends, HTTPException, Query
from fastapi.responses import JSONResponse, StreamingResponse

from api.auth import require_auth
from db.pool import get_pool
from task_queue.redis_queue import enqueue, get_job_status, clear_scan_progress
from utils.settings import load_settings, save_settings

router = APIRouter()


# ── Projects ──────────────────────────────────────────────────────────────────

@router.get("/api/projects")
async def api_projects(
    request: Request,
    page: int = Query(1, ge=1),
    per_page: int = Query(50, ge=1, le=500),
    limit: int = Query(0, ge=0),          # alias for per_page
    search: str = Query(""),
    q: str = Query(""),                    # alias for search
    source: str = Query(""),
    status: str = Query(""),
    scan_status: str = Query(""),          # alias for status
    platform: str = Query(""),
    scope_type: str = Query(""),
    bounty: Optional[str] = Query(None),   # Accept str to handle empty string from frontend
    is_new: Optional[str] = Query(None),   # Accept str to handle empty string from frontend
    sort: str = Query("updated_at"),
    order: str = Query("desc"),
    format: str = Query(""),
    _: str = Depends(require_auth),
):
    # Convert bounty/is_new: empty string → None, otherwise parse as int
    bounty_int: Optional[int] = None
    if bounty is not None and bounty != "":
        try:
            bounty_int = int(bounty)
        except (ValueError, TypeError):
            bounty_int = None

    is_new_int: Optional[int] = None
    if is_new is not None and is_new != "":
        try:
            is_new_int = int(is_new)
        except (ValueError, TypeError):
            is_new_int = None

    effective_per_page = limit if limit > 0 else per_page
    effective_search = q or search
    effective_status = scan_status or status
    offset = (page - 1) * effective_per_page

    # Whitelist sort columns to prevent SQL injection
    allowed_sort = {"updated_at", "created_at", "name", "count", "bounty", "scan_status"}
    sort_col = sort if sort in allowed_sort else "updated_at"
    sort_dir = "DESC" if order.lower() != "asc" else "ASC"

    conditions = []
    params: list = []
    idx = 1

    if effective_search:
        conditions.append(f"(name ILIKE ${idx} OR description ILIKE ${idx})")
        params.append(f"%{effective_search}%")
        idx += 1
    if source:
        conditions.append(f"source=${idx}")
        params.append(source)
        idx += 1
    if effective_status:
        conditions.append(f"scan_status=${idx}")
        params.append(effective_status)
        idx += 1
    if platform:
        conditions.append(f"platform=${idx}")
        params.append(platform)
        idx += 1
    if scope_type:
        conditions.append(f"scope_type=${idx}")
        params.append(scope_type)
        idx += 1
    if bounty_int is not None:
        conditions.append(f"bounty=${idx}")
        params.append(bounty_int)
        idx += 1
    if is_new_int is not None:
        conditions.append(f"is_new=${idx}")
        params.append(is_new_int)
        idx += 1

    where = ("WHERE " + " AND ".join(conditions)) if conditions else ""

    pool = await get_pool()
    async with pool.acquire() as conn:
        total = await conn.fetchval(f"SELECT COUNT(*) FROM projects {where}", *params)
        rows = await conn.fetch(
            f"""SELECT p.*,
                (SELECT COUNT(*) FROM subdomains WHERE project_id=p.id AND is_alive=1) as sub_alive,
                (SELECT COUNT(*) FROM subdomains WHERE project_id=p.id) as sub_total,
                (SELECT COUNT(*) FROM subdomains WHERE project_id=p.id AND is_new=1) as sub_new,
                (SELECT COUNT(*) FROM vulnerabilities WHERE project_id=p.id) as vuln_count
                FROM projects p {where}
                ORDER BY p.{sort_col} {sort_dir}
                LIMIT ${idx} OFFSET ${idx+1}""",
            *params, effective_per_page, offset
        )

    projects = [dict(r) for r in rows]

    if format == "csv":
        output = io.StringIO()
        if projects:
            writer = csv.DictWriter(output, fieldnames=projects[0].keys())
            writer.writeheader()
            writer.writerows(projects)
        return StreamingResponse(
            iter([output.getvalue()]),
            media_type="text/csv",
            headers={"Content-Disposition": "attachment; filename=projects.csv"},
        )

    return {
        "projects": projects,
        "total": total,
        "page": page,
        "per_page": effective_per_page,
        "pages": ceil(total / effective_per_page) if effective_per_page > 0 else 1,
    }


@router.get("/api/projects/{pid}")
async def api_get_project(pid: str, _: str = Depends(require_auth)):
    pool = await get_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow("""
            SELECT p.*,
                (SELECT COUNT(*) FROM subdomains WHERE project_id=p.id AND is_alive=1) as sub_alive,
                (SELECT COUNT(*) FROM subdomains WHERE project_id=p.id) as sub_total,
                (SELECT COUNT(*) FROM subdomains WHERE project_id=p.id AND is_new=1) as sub_new,
                (SELECT COUNT(*) FROM vulnerabilities WHERE project_id=p.id) as vuln_count
            FROM projects p WHERE p.id=$1
        """, pid)
    if not row:
        raise HTTPException(status_code=404, detail="Project not found")
    return dict(row)


@router.post("/api/projects")
async def api_create_project(request: Request, _: str = Depends(require_auth)):
    data = await request.json()
    if not data.get("name"):
        raise HTTPException(status_code=400, detail="name is required")
    pool = await get_pool()
    pid = str(uuid.uuid4())
    now = datetime.now().isoformat()
    # Accept 'wildcards' as alias for 'scope' — same as old app
    scope = data.get("scope") or data.get("wildcards") or []
    extras = data.get("extras") or []
    # Merge wildcards + extras into scope list (mirrors old create_manual_project)
    all_scope = list(scope) + list(extras)

    async with pool.acquire() as conn:
        await conn.execute(
            """INSERT INTO projects(id,name,description,source,platform,program_url,
               scope_type,bounty,created_at,updated_at,scan_status,scope,sync_enabled)
               VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$9,'pending',$10,1)""",
            pid,
            data.get("name", ""),
            data.get("description", ""),
            data.get("source", "manual"),
            data.get("platform", ""),
            data.get("program_url", ""),
            data.get("scope_type", "public"),
            int(data.get("bounty", 0)),
            now,
            json.dumps(all_scope),
        )

    # Auto-enqueue scan immediately — mirrors old app's executor.submit(_manual_enum)
    # run_subfinder=True so Phase 0 runs subfinder on the scope domains first
    auto_scan = data.get("auto_scan", True)
    job_result = None
    if auto_scan and all_scope:
        job_result = await enqueue(
            job_type="scan",
            project_id=pid,
            priority=0,
            payload={
                "project_name": data.get("name", ""),
                "run_subfinder": True,
                "scope": all_scope,
            },
        )
    elif auto_scan:
        # No scope defined but auto_scan requested — enqueue without subfinder
        job_result = await enqueue(
            job_type="scan",
            project_id=pid,
            priority=0,
            payload={
                "project_name": data.get("name", ""),
                "run_subfinder": False,
                "scope": [],
            },
        )

    return {"ok": True, "id": pid, "project_id": pid, "job": job_result}


@router.put("/api/projects/{pid}")
async def api_update_project(pid: str, request: Request, _: str = Depends(require_auth)):
    data = await request.json()
    pool = await get_pool()
    now = datetime.now().isoformat()
    allowed = {"name", "description", "platform", "program_url",
               "scope_type", "bounty", "scope", "wildcards", "notes"}
    updates = {}
    for k, v in data.items():
        if k == "wildcards":
            updates["scope"] = json.dumps(v) if isinstance(v, list) else v
        elif k == "scope":
            # BUG-15 FIX: scope is TEXT in DB — must be JSON-encoded, not Python repr.
            # Without this, a list sent from the frontend would be stored as
            # "['a.com']" (Python repr) instead of '["a.com"]' (valid JSON).
            updates["scope"] = json.dumps(v) if isinstance(v, list) else v
        elif k in allowed:
            updates[k] = v
    if not updates:
        raise HTTPException(status_code=400, detail="No valid fields to update")
    updates["updated_at"] = now
    set_clause = ", ".join(f"{k}=${i+2}" for i, k in enumerate(updates))
    vals = list(updates.values())
    async with pool.acquire() as conn:
        await conn.execute(
            f"UPDATE projects SET {set_clause} WHERE id=$1", pid, *vals)
    return {"ok": True}


@router.delete("/api/projects/{pid}")
async def api_delete_project(pid: str, _: str = Depends(require_auth)):
    pool = await get_pool()
    async with pool.acquire() as conn:
        await conn.execute("DELETE FROM projects WHERE id=$1", pid)
    # Clean up any stale Redis scan_progress for this project
    try:
        await clear_scan_progress(pid)
    except Exception:
        pass
    return {"ok": True}


# ── Bulk project operations ───────────────────────────────────────────────────

@router.post("/api/projects/bulk-scan")
async def api_bulk_scan_projects(request: Request, _: str = Depends(require_auth)):
    """Enqueue a bulk scan for selected projects."""
    data = await request.json()
    ids = data.get("ids") or data.get("project_ids", [])
    if not ids:
        raise HTTPException(status_code=400, detail="ids required")
    if len(ids) > 500:
        raise HTTPException(status_code=400, detail="Max 500 projects per bulk scan")
    pool = await get_pool()
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            "SELECT id, name, scope FROM projects WHERE id = ANY($1::text[])", ids)
    # RP-04 FIX: include scope so bulk-scanned projects run subfinder
    projects = []
    for r in rows:
        try:
            scope = json.loads(r["scope"] or "[]")
        except Exception:
            scope = []
        projects.append({
            "id": r["id"],
            "name": r["name"],
            "run_subfinder": bool(scope),
            "scope": scope,
        })
    jid = str(uuid.uuid4())
    result = await enqueue(
        job_type="scan_bulk",
        project_id=None,
        priority=1,
        job_id=jid,
        payload={"projects": projects},
    )
    return result


@router.post("/api/projects/bulk-delete")
async def api_bulk_delete_projects(request: Request, _: str = Depends(require_auth)):
    data = await request.json()
    ids = data.get("ids") or data.get("project_ids", [])
    if not ids:
        raise HTTPException(status_code=400, detail="ids required")
    pool = await get_pool()
    async with pool.acquire() as conn:
        deleted = await conn.fetchval(
            "WITH d AS (DELETE FROM projects WHERE id = ANY($1::text[]) RETURNING id) SELECT COUNT(*) FROM d",
            ids)
    # Clean stale Redis scan_progress for all deleted projects
    for pid in ids:
        try:
            await clear_scan_progress(pid)
        except Exception:
            pass
    return {"ok": True, "deleted": deleted}


@router.post("/api/projects/delete-all")
async def api_delete_all_projects(_: str = Depends(require_auth)):
    pool = await get_pool()
    async with pool.acquire() as conn:
        deleted = await conn.fetchval(
            "WITH d AS (DELETE FROM projects RETURNING id) SELECT COUNT(*) FROM d")
    # Wipe all Redis scan_progress — nothing left to scan
    try:
        from task_queue.redis_queue import get_redis as _get_redis
        r = await _get_redis()
        await r.delete("submind:scan_progress")
    except Exception:
        pass
    return {"ok": True, "deleted": deleted}


# ── Scan dispatch ─────────────────────────────────────────────────────────────

@router.post("/api/projects/{pid}/scan")
async def api_scan_project(pid: str, request: Request, _: str = Depends(require_auth)):
    """Enqueue a single-project scan. Returns job_id immediately."""
    pool = await get_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow("SELECT name, scan_status, scope, source FROM projects WHERE id=$1", pid)
    if not row:
        raise HTTPException(status_code=404, detail="Project not found")

    # Parse scope to pass to subfinder
    import json as _json
    try:
        scope = _json.loads(row["scope"] or "[]")
    except Exception:
        scope = []

    # Reset phase AND clear deep-scan timestamps so Phase C fully re-runs fresh
    async with pool.acquire() as conn:
        await conn.execute(
            "UPDATE projects SET scan_status='pending', phase_updated_at=$1 WHERE id=$2 AND scan_status IN ('done','phase_a','phase_a_done','phase_b_done','phase_c_done')",
            datetime.now().isoformat(), pid)
        # Clear last_deep_scan so Phase C re-probes all live subs for fresh tech/url data
        await conn.execute(
            "UPDATE subdomains SET last_deep_scan=NULL WHERE project_id=$1 AND is_alive=1",
            pid)

    result = await enqueue(
        job_type="scan",
        project_id=pid,
        priority=0,
        payload={
            "project_name": row["name"],
            "run_subfinder": bool(scope),   # run subfinder if project has scope wildcards
            "scope": scope,
        },
    )
    return result


@router.post("/api/projects/{pid}/nuclei")
async def api_nuclei_project(pid: str, request: Request, _: str = Depends(require_auth)):
    """Enqueue a nuclei-only scan for a project."""
    pool = await get_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow("SELECT name FROM projects WHERE id=$1", pid)
    if not row:
        raise HTTPException(status_code=404, detail="Project not found")
    data = await request.json()
    result = await enqueue(
        job_type="nuclei_only",
        project_id=pid,
        priority=1,
        payload={
            "project_name": row["name"],
            "templates": data.get("templates"),
            "severity": data.get("severity"),
        },
    )
    return result


@router.post("/api/projects/{pid}/toggle-sync")
async def api_toggle_sync(pid: str, _: str = Depends(require_auth)):
    pool = await get_pool()
    async with pool.acquire() as conn:
        cur = await conn.fetchrow("SELECT sync_enabled FROM projects WHERE id=$1", pid)
        if not cur:
            raise HTTPException(status_code=404)
        nv = 0 if cur["sync_enabled"] else 1
        await conn.execute("UPDATE projects SET sync_enabled=$1 WHERE id=$2", nv, pid)
    return {"ok": True, "sync_enabled": bool(nv)}


# ── Subdomains ────────────────────────────────────────────────────────────────

@router.get("/api/projects/{pid}/subdomains")
async def api_subdomains(
    pid: str,
    page: int = Query(1, ge=1),
    per_page: int = Query(100, ge=1, le=1000),
    limit: int = Query(0, ge=0),           # alias for per_page
    alive_only: bool = Query(False),
    alive: Optional[int] = Query(None),    # None = any; 1 = alive; 0 = dead
    search: str = Query(""),
    q: str = Query(""),                    # alias for search
    lifecycle: str = Query(""),
    status: Optional[int] = Query(None),  # HTTP status code filter
    tech: str = Query(""),
    port: Optional[int] = Query(None),
    is_new: Optional[int] = Query(None),
    cdn: str = Query(""),
    tls: str = Query(""),
    sort: str = Query("last_seen"),
    order: str = Query("desc"),
    _: str = Depends(require_auth),
):
    effective_per_page = limit if limit > 0 else per_page
    effective_search = q or search
    offset = (page - 1) * effective_per_page

    allowed_sort = {"last_seen", "subdomain", "status_code", "title", "tech",
                    "port", "ip", "lifecycle", "fail_count", "last_deep_scan"}
    sort_col = sort if sort in allowed_sort else "last_seen"
    sort_dir = "DESC" if order.lower() != "asc" else "ASC"

    conditions = ["project_id=$1"]
    params: list = [pid]
    idx = 2

    if alive_only or alive == 1:
        conditions.append("is_alive=1")
    elif alive == 0:
        conditions.append("is_alive=0")
    if effective_search:
        conditions.append(f"(subdomain ILIKE ${idx} OR title ILIKE ${idx} OR ip ILIKE ${idx})")
        params.append(f"%{effective_search}%")
        idx += 1
    if lifecycle:
        conditions.append(f"lifecycle=${idx}")
        params.append(lifecycle)
        idx += 1
    if status is not None and status > 0:
        conditions.append(f"status_code=${idx}")
        params.append(status)
        idx += 1
    if tech:
        conditions.append(f"tech ILIKE ${idx}")
        params.append(f"%{tech}%")
        idx += 1
    if port is not None and port > 0:
        conditions.append(f"port=${idx}")
        params.append(port)
        idx += 1
    if is_new is not None:
        conditions.append(f"is_new=${idx}")
        params.append(is_new)
        idx += 1
    if cdn:
        conditions.append(f"cdn_name ILIKE ${idx}")
        params.append(f"%{cdn}%")
        idx += 1
    if tls:
        conditions.append(f"(tls_cn ILIKE ${idx} OR tls_issuer ILIKE ${idx})")
        params.append(f"%{tls}%")
        idx += 1

    where = "WHERE " + " AND ".join(conditions)

    pool = await get_pool()
    async with pool.acquire() as conn:
        total = await conn.fetchval(f"SELECT COUNT(*) FROM subdomains {where}", *params)
        rows = await conn.fetch(
            f"SELECT * FROM subdomains {where} ORDER BY {sort_col} {sort_dir} NULLS LAST LIMIT ${idx} OFFSET ${idx+1}",
            *params, effective_per_page, offset
        )
    return {
        "subdomains": [dict(r) for r in rows],
        "total": total,
        "page": page,
        "per_page": effective_per_page,
        "pages": ceil(total / effective_per_page) if effective_per_page > 0 else 1,
    }


@router.post("/api/projects/{pid}/subdomains/import")
async def api_import_subdomains(pid: str, request: Request, _: str = Depends(require_auth)):
    """Import subdomains from text payload. Runs garbage AI classifier first."""
    from utils.clean import clean_subdomains
    from utils.garbage_classifier import classify_and_store
    from db.queries import upsert_subdomains
    data = await request.json()
    raw = data.get("subdomains", [])
    if isinstance(raw, str):
        raw = [l.strip() for l in raw.splitlines() if l.strip()]
    if len(raw) > 50000:
        raw = raw[:50000]
    cleaned = clean_subdomains(raw)
    pool = await get_pool()
    real_subs, garbage_count = await classify_and_store(pool, pid, cleaned, source="manual")
    async with pool.acquire() as conn:
        count = await upsert_subdomains(conn, pid, real_subs)
    return {"ok": True, "imported": len(real_subs), "garbage": garbage_count, "total": count}


# ── Project exports ───────────────────────────────────────────────────────────

@router.get("/api/projects/{pid}/export")
async def api_export_project(
    pid: str,
    format: str = Query("json"),
    alive_only: bool = Query(False),
    _: str = Depends(require_auth),
):
    """Export all subdomains for a project as JSON or CSV. RP-02: streams in chunks."""
    pool = await get_pool()
    alive_clause = " AND is_alive=1" if alive_only else ""
    CHUNK = 5000

    if format == "csv":
        # RP-02 FIX: Stream CSV in chunks to avoid OOM on large projects
        async def _stream_csv():
            header_written = False
            offset = 0
            async with pool.acquire() as conn:
                while True:
                    rows = await conn.fetch(
                        f"SELECT * FROM subdomains WHERE project_id=$1{alive_clause} "
                        f"ORDER BY subdomain LIMIT $2 OFFSET $3",
                        pid, CHUNK, offset)
                    if not rows:
                        break
                    chunk_data = [dict(r) for r in rows]
                    output = io.StringIO()
                    writer = csv.DictWriter(output, fieldnames=chunk_data[0].keys())
                    if not header_written:
                        writer.writeheader()
                        header_written = True
                    writer.writerows(chunk_data)
                    yield output.getvalue()
                    offset += CHUNK
        return StreamingResponse(
            _stream_csv(),
            media_type="text/csv",
            headers={"Content-Disposition": f"attachment; filename=subdomains_{pid}.csv"},
        )

    # JSON: stream as array
    async def _stream_json():
        yield "["
        first = True
        offset = 0
        async with pool.acquire() as conn:
            while True:
                rows = await conn.fetch(
                    f"SELECT * FROM subdomains WHERE project_id=$1{alive_clause} "
                    f"ORDER BY subdomain LIMIT $2 OFFSET $3",
                    pid, CHUNK, offset)
                if not rows:
                    break
                for r in rows:
                    if not first:
                        yield ","
                    yield json.dumps(dict(r), default=str)
                    first = False
                offset += CHUNK
        yield "]"
    return StreamingResponse(
        _stream_json(),
        media_type="application/json",
        headers={"Content-Disposition": f"attachment; filename=subdomains_{pid}.json"},
    )


@router.get("/api/projects/{pid}/export-urls")
async def api_export_urls(
    pid: str,
    alive_only: bool = Query(True),
    _: str = Depends(require_auth),
):
    """Export live URLs as plain text, one per line."""
    pool = await get_pool()
    conditions = "WHERE project_id=$1 AND url != ''"
    if alive_only:
        conditions += " AND is_alive=1"
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            f"SELECT url FROM subdomains {conditions} ORDER BY url", pid)
    text = "\n".join(r["url"] for r in rows if r["url"])
    return StreamingResponse(
        iter([text]),
        media_type="text/plain",
        headers={"Content-Disposition": f"attachment; filename=urls_{pid}.txt"},
    )


# ── Vulnerabilities ───────────────────────────────────────────────────────────

@router.get("/api/vulnerabilities")
async def api_vulns_global(
    page: int = Query(1, ge=1),
    per_page: int = Query(50, ge=1, le=500),
    severity: str = Query(""),
    review_status: str = Query(""),
    search: str = Query(""),
    project_id: str = Query(""),
    _: str = Depends(require_auth),
):
    """Global vulnerabilities list across all projects. Returns plain array."""
    pool = await get_pool()
    offset = (page - 1) * per_page
    conditions: list = []
    params: list = []
    idx = 1

    if project_id:
        conditions.append(f"v.project_id=${idx}")
        params.append(project_id)
        idx += 1
    if severity:
        conditions.append(f"v.severity=${idx}")
        params.append(severity)
        idx += 1
    if review_status:
        conditions.append(f"v.review_status=${idx}")
        params.append(review_status)
        idx += 1
    if search:
        conditions.append(f"(v.name ILIKE ${idx} OR v.url ILIKE ${idx} OR v.template_id ILIKE ${idx})")
        params.append(f"%{search}%")
        idx += 1

    where = ("WHERE " + " AND ".join(conditions)) if conditions else ""
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            f"""SELECT v.*, p.name as project_name
                FROM vulnerabilities v
                LEFT JOIN projects p ON v.project_id=p.id
                {where}
                ORDER BY v.created_at DESC
                LIMIT ${idx} OFFSET ${idx+1}""",
            *params, per_page, offset
        )
    # Return plain array — frontend does (data||[]).length and data.map(v=>...)
    return [dict(r) for r in rows]


@router.get("/api/vulnerabilities/breakdown")
async def api_vulns_breakdown(_: str = Depends(require_auth)):
    """Vulnerability breakdown by severity + 5 most recent."""
    pool = await get_pool()
    async with pool.acquire() as conn:
        sev_rows = await conn.fetch(
            """SELECT severity, COUNT(*) as count FROM vulnerabilities
               GROUP BY severity ORDER BY CASE severity
               WHEN 'critical' THEN 1 WHEN 'high' THEN 2
               WHEN 'medium' THEN 3 WHEN 'low' THEN 4 ELSE 5 END""")
        recent_rows = await conn.fetch(
            """SELECT v.id, v.name, v.severity, v.url, v.template_id,
                      v.review_status, v.created_at, p.name as project_name
               FROM vulnerabilities v
               LEFT JOIN projects p ON v.project_id=p.id
               ORDER BY v.created_at DESC LIMIT 10""")
    return {
        "by_severity": [dict(r) for r in sev_rows],
        "recent": [dict(r) for r in recent_rows],
    }


@router.get("/api/projects/{pid}/vulnerabilities")
async def api_vulns(
    pid: str,
    page: int = Query(1, ge=1),
    per_page: int = Query(50, ge=1, le=500),
    severity: str = Query(""),
    review_status: str = Query(""),
    _: str = Depends(require_auth),
):
    pool = await get_pool()
    offset = (page - 1) * per_page
    conditions = ["project_id=$1"]
    params: list = [pid]
    idx = 2

    if severity:
        conditions.append(f"severity=${idx}")
        params.append(severity)
        idx += 1
    if review_status:
        conditions.append(f"review_status=${idx}")
        params.append(review_status)
        idx += 1

    where = "WHERE " + " AND ".join(conditions)
    async with pool.acquire() as conn:
        total = await conn.fetchval(f"SELECT COUNT(*) FROM vulnerabilities {where}", *params)
        rows = await conn.fetch(
            f"SELECT * FROM vulnerabilities {where} ORDER BY created_at DESC LIMIT ${idx} OFFSET ${idx+1}",
            *params, per_page, offset
        )
    # Return flat array (frontend does (data||[]).length)
    return [dict(r) for r in rows]


@router.put("/api/vulnerabilities/{vid}/review")
async def api_review_vuln(vid: int, request: Request, _: str = Depends(require_auth)):
    data = await request.json()
    status_val = data.get("status")
    if status_val not in ("pending_review", "confirmed", "false_positive", "fixed"):
        raise HTTPException(status_code=400, detail="Invalid review status")
    pool = await get_pool()
    async with pool.acquire() as conn:
        await conn.execute(
            "UPDATE vulnerabilities SET review_status=$1, notes=$2 WHERE id=$3",
            status_val, data.get("notes", ""), vid)
    return {"ok": True}


# ── Review queue ──────────────────────────────────────────────────────────────

@router.get("/api/review/queue")
async def api_review_queue(
    page: int = Query(1, ge=1),
    per_page: int = Query(50, ge=1, le=200),
    severity: str = Query(""),
    _: str = Depends(require_auth),
):
    pool = await get_pool()
    offset = (page - 1) * per_page
    conditions = ["v.review_status='pending_review'"]
    params: list = []
    idx = 1

    if severity:
        conditions.append(f"v.severity=${idx}")
        params.append(severity)
        idx += 1

    where = "WHERE " + " AND ".join(conditions)
    async with pool.acquire() as conn:
        total = await conn.fetchval(
            f"SELECT COUNT(*) FROM vulnerabilities v {where}", *params)
        rows = await conn.fetch(
            f"""SELECT v.*, p.name as project_name
                FROM vulnerabilities v
                LEFT JOIN projects p ON v.project_id=p.id
                {where}
                ORDER BY CASE v.severity
                    WHEN 'critical' THEN 1 WHEN 'high' THEN 2
                    WHEN 'medium' THEN 3 WHEN 'low' THEN 4 ELSE 5 END,
                    v.created_at DESC
                LIMIT ${idx} OFFSET ${idx+1}""",
            *params, per_page, offset
        )
    return {
        "queue": [dict(r) for r in rows],
        "total": total,
        "page": page,
        "per_page": per_page,
        "pages": ceil(total / per_page),
    }


@router.post("/api/review/{vid}/report")
async def api_review_report(vid: int, request: Request, _: str = Depends(require_auth)):
    data = await request.json()
    pool = await get_pool()
    async with pool.acquire() as conn:
        await conn.execute(
            "UPDATE vulnerabilities SET review_status='confirmed', notes=$1 WHERE id=$2",
            data.get("notes", ""), vid)
    return {"ok": True}


@router.post("/api/review/{vid}/decline")
async def api_review_decline(vid: int, request: Request, _: str = Depends(require_auth)):
    try:
        data = await request.json()
    except Exception:
        data = {}
    pool = await get_pool()
    async with pool.acquire() as conn:
        await conn.execute(
            "UPDATE vulnerabilities SET review_status='false_positive', notes=$1 WHERE id=$2",
            data.get("notes", ""), vid)
    return {"ok": True}


@router.post("/api/review/{vid}/notes")
async def api_review_notes(vid: int, request: Request, _: str = Depends(require_auth)):
    data = await request.json()
    pool = await get_pool()
    async with pool.acquire() as conn:
        await conn.execute(
            "UPDATE vulnerabilities SET notes=$1 WHERE id=$2",
            data.get("notes", ""), vid)
    return {"ok": True}


# ── Alerts ────────────────────────────────────────────────────────────────────

@router.get("/api/alerts/count")
async def api_alerts_count(_: str = Depends(require_auth)):
    pool = await get_pool()
    async with pool.acquire() as conn:
        unread = await conn.fetchval("SELECT COUNT(*) FROM alerts WHERE seen=0")
        total = await conn.fetchval("SELECT COUNT(*) FROM alerts")
        review_pending = await conn.fetchval(
            "SELECT COUNT(*) FROM vulnerabilities WHERE review_status='pending_review'")
    return {
        "unread": unread,
        "total": total,
        "review_pending": review_pending,
        "monitor_running": False,
    }


@router.get("/api/alerts")
async def api_alerts(
    page: int = Query(1, ge=1),
    per_page: int = Query(50, ge=1, le=200),
    unseen_only: bool = Query(False),
    _: str = Depends(require_auth),
):
    pool = await get_pool()
    offset = (page - 1) * per_page
    where = "WHERE a.seen=0" if unseen_only else ""
    async with pool.acquire() as conn:
        total = await conn.fetchval(f"SELECT COUNT(*) FROM alerts a {where}")
        rows = await conn.fetch(
            f"""SELECT a.*, p.name as program_name FROM alerts a
                LEFT JOIN projects p ON a.project_id=p.id
                {where} ORDER BY a.created_at DESC LIMIT $1 OFFSET $2""",
            per_page, offset
        )
    return {
        "alerts": [dict(r) for r in rows],
        "total": total,
        "page": page,
        "per_page": per_page,
        "pages": ceil(total / per_page),
    }


@router.post("/api/alerts/{aid}/seen")
async def api_mark_seen(aid: int, _: str = Depends(require_auth)):
    pool = await get_pool()
    async with pool.acquire() as conn:
        await conn.execute("UPDATE alerts SET seen=1 WHERE id=$1", aid)
    return {"ok": True}


@router.post("/api/alerts/seen-all")
async def api_mark_all_seen(_: str = Depends(require_auth)):
    pool = await get_pool()
    async with pool.acquire() as conn:
        await conn.execute("UPDATE alerts SET seen=1 WHERE seen=0")
    return {"ok": True}


# ── Search ────────────────────────────────────────────────────────────────────

@router.get("/api/search")
async def api_search(
    q: str = Query(..., min_length=1),
    type: str = Query("all"),              # was search_type — now matches frontend
    search_type: str = Query(""),          # backward compat alias
    limit: int = Query(50, ge=1, le=200),
    _: str = Depends(require_auth),
):
    effective_type = type if type != "all" else (search_type or "all")
    pool = await get_pool()
    results = []
    like = f"%{q}%"

    async with pool.acquire() as conn:
        if effective_type in ("all", "program"):
            rows = await conn.fetch("""
                SELECT id, name, platform, scan_status, bounty,
                       (SELECT COUNT(*) FROM subdomains WHERE project_id=p.id AND is_alive=1) as alive_subs,
                       (SELECT COUNT(*) FROM vulnerabilities WHERE project_id=p.id) as vuln_count
                FROM projects p
                WHERE name ILIKE $1 OR description ILIKE $1
                ORDER BY updated_at DESC LIMIT $2
            """, like, limit)
            for r in rows:
                results.append({"type": "program", **dict(r)})

        if effective_type in ("all", "subdomain"):
            rows = await conn.fetch("""
                SELECT s.subdomain, s.url, s.status_code, s.title, s.tech,
                       s.ip, s.is_alive, p.name as program_name
                FROM subdomains s
                JOIN projects p ON s.project_id = p.id
                WHERE s.subdomain ILIKE $1 OR s.title ILIKE $1 OR s.ip ILIKE $1
                ORDER BY s.last_seen DESC NULLS LAST LIMIT $2
            """, like, limit)
            for r in rows:
                results.append({"type": "subdomain", **dict(r)})

        if effective_type in ("all", "vuln"):
            rows = await conn.fetch("""
                SELECT v.name, v.severity, v.url, v.template_id, v.type,
                       v.created_at, p.name as program_name
                FROM vulnerabilities v
                JOIN projects p ON v.project_id = p.id
                WHERE v.name ILIKE $1 OR v.url ILIKE $1 OR v.template_id ILIKE $1
                ORDER BY v.created_at DESC LIMIT $2
            """, like, limit)
            for r in rows:
                results.append({"type": "vuln", **dict(r)})

    return {"results": results, "total": len(results)}


# ── Job status ────────────────────────────────────────────────────────────────

@router.get("/api/jobs/{job_id}")
async def api_job_status(job_id: str, _: str = Depends(require_auth)):
    status = await get_job_status(job_id)
    if not status:
        raise HTTPException(status_code=404, detail="Job not found")
    return status
