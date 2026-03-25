"""
api/routes_garbage.py — Garbage subdomain management endpoints.

Garbage subdomains are classified by the AI classifier and excluded from scans.
Users can:
  - View garbage subdomains per project
  - Promote individual garbage subs to real (they become scannable)
  - Delete garbage subs
  - Bulk promote / bulk delete
"""
from datetime import datetime
from math import ceil
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import JSONResponse

from api.auth import require_auth
from db.pool import get_pool

router = APIRouter()


# ── List garbage subdomains ───────────────────────────────────────────────────

@router.get("/api/projects/{pid}/garbage")
async def api_garbage_list(
    pid: str,
    page: int = Query(1, ge=1),
    per_page: int = Query(100, ge=1, le=1000),
    search: str = Query(""),
    promoted: Optional[int] = Query(None),   # None=all, 0=not promoted, 1=promoted
    sort: str = Query("score"),
    order: str = Query("asc"),
    _: str = Depends(require_auth),
):
    """Return garbage subdomains for a project with pagination."""
    pool = await get_pool()
    offset = (page - 1) * per_page

    allowed_sort = {"subdomain", "score", "reason", "source", "created_at"}
    sort_col = sort if sort in allowed_sort else "score"
    sort_dir = "ASC" if order.lower() != "desc" else "DESC"

    conditions = ["project_id=$1"]
    params: list = [pid]
    idx = 2

    if search:
        conditions.append(f"subdomain ILIKE ${idx}")
        params.append(f"%{search}%")
        idx += 1
    if promoted is not None:
        conditions.append(f"promoted=${idx}")
        params.append(promoted)
        idx += 1

    where = "WHERE " + " AND ".join(conditions)

    async with pool.acquire() as conn:
        total = await conn.fetchval(
            f"SELECT COUNT(*) FROM garbage_subdomains {where}", *params)
        rows = await conn.fetch(
            f"SELECT * FROM garbage_subdomains {where} "
            f"ORDER BY {sort_col} {sort_dir} NULLS LAST "
            f"LIMIT ${idx} OFFSET ${idx+1}",
            *params, per_page, offset
        )
    return {
        "garbage": [dict(r) for r in rows],
        "total": total,
        "page": page,
        "per_page": per_page,
        "pages": ceil(total / per_page) if per_page > 0 else 1,
    }


@router.get("/api/projects/{pid}/garbage/stats")
async def api_garbage_stats(pid: str, _: str = Depends(require_auth)):
    """Summary stats for a project's garbage subdomains."""
    pool = await get_pool()
    async with pool.acquire() as conn:
        total = await conn.fetchval(
            "SELECT COUNT(*) FROM garbage_subdomains WHERE project_id=$1", pid)
        promoted_count = await conn.fetchval(
            "SELECT COUNT(*) FROM garbage_subdomains WHERE project_id=$1 AND promoted=1", pid)
        by_source = await conn.fetch(
            "SELECT source, COUNT(*) as c FROM garbage_subdomains "
            "WHERE project_id=$1 GROUP BY source ORDER BY c DESC", pid)
        by_reason = await conn.fetch(
            "SELECT reason, COUNT(*) as c FROM garbage_subdomains "
            "WHERE project_id=$1 AND promoted=0 GROUP BY reason ORDER BY c DESC LIMIT 10", pid)
    return {
        "total": total,
        "promoted": promoted_count,
        "pending": total - promoted_count,
        "by_source": [dict(r) for r in by_source],
        "top_reasons": [dict(r) for r in by_reason],
    }


# ── Promote garbage → real ────────────────────────────────────────────────────

@router.post("/api/projects/{pid}/garbage/{gid}/promote")
async def api_garbage_promote(
    pid: str,
    gid: int,
    _: str = Depends(require_auth),
):
    """
    Promote a single garbage subdomain to 'real'.
    Moves it to the subdomains table (is_new=1, lifecycle='new') so it gets scanned.
    """
    pool = await get_pool()
    now = datetime.now().isoformat()

    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT * FROM garbage_subdomains WHERE id=$1 AND project_id=$2", gid, pid)
        if not row:
            raise HTTPException(status_code=404, detail="Garbage entry not found")

        subdomain = row["subdomain"]

        # Mark as promoted in garbage table
        await conn.execute(
            "UPDATE garbage_subdomains SET promoted=1, promoted_at=$1 WHERE id=$2",
            now, gid)

        # Insert into real subdomains table (upsert — may already exist as dead)
        await conn.execute(
            """INSERT INTO subdomains(project_id, subdomain, first_seen, last_seen, is_new, lifecycle, in_scope)
               VALUES($1, $2, $3, $3, 1, 'new', 1)
               ON CONFLICT (project_id, subdomain) DO UPDATE SET
                 in_scope=1, lifecycle='new', is_new=1, last_seen=$3""",
            pid, subdomain, now)

    return {"ok": True, "subdomain": subdomain, "promoted": True}


@router.post("/api/projects/{pid}/garbage/bulk-promote")
async def api_garbage_bulk_promote(
    pid: str,
    request: Request,
    _: str = Depends(require_auth),
):
    """Promote multiple garbage subdomains to real by ID list."""
    data = await request.json()
    ids: List[int] = data.get("ids", [])
    if not ids:
        raise HTTPException(status_code=400, detail="ids required")
    if len(ids) > 1000:
        raise HTTPException(status_code=400, detail="Max 1000 per bulk operation")

    pool = await get_pool()
    now = datetime.now().isoformat()

    async with pool.acquire() as conn:
        rows = await conn.fetch(
            "SELECT id, subdomain FROM garbage_subdomains "
            "WHERE id = ANY($1::bigint[]) AND project_id=$2",
            ids, pid)
        if not rows:
            raise HTTPException(status_code=404, detail="No matching garbage entries")

        # Mark promoted
        await conn.execute(
            "UPDATE garbage_subdomains SET promoted=1, promoted_at=$1 "
            "WHERE id = ANY($2::bigint[]) AND project_id=$3",
            now, ids, pid)

        # Insert into subdomains table
        subs = [(pid, r["subdomain"], now) for r in rows]
        await conn.executemany(
            """INSERT INTO subdomains(project_id, subdomain, first_seen, last_seen, is_new, lifecycle, in_scope)
               VALUES($1, $2, $3, $3, 1, 'new', 1)
               ON CONFLICT (project_id, subdomain) DO UPDATE SET
                 in_scope=1, lifecycle='new', is_new=1, last_seen=$3""",
            subs)

    return {"ok": True, "promoted": len(rows)}


# ── Delete garbage ────────────────────────────────────────────────────────────

@router.delete("/api/projects/{pid}/garbage/{gid}")
async def api_garbage_delete(
    pid: str,
    gid: int,
    _: str = Depends(require_auth),
):
    """Permanently delete a garbage subdomain entry."""
    pool = await get_pool()
    async with pool.acquire() as conn:
        deleted = await conn.fetchval(
            "WITH d AS (DELETE FROM garbage_subdomains WHERE id=$1 AND project_id=$2 RETURNING id) "
            "SELECT COUNT(*) FROM d",
            gid, pid)
    if not deleted:
        raise HTTPException(status_code=404, detail="Not found")
    return {"ok": True, "deleted": deleted}


@router.post("/api/projects/{pid}/garbage/bulk-delete")
async def api_garbage_bulk_delete(
    pid: str,
    request: Request,
    _: str = Depends(require_auth),
):
    """Delete multiple garbage subdomain entries by ID list."""
    data = await request.json()
    ids: List[int] = data.get("ids", [])
    if not ids:
        raise HTTPException(status_code=400, detail="ids required")
    if len(ids) > 5000:
        raise HTTPException(status_code=400, detail="Max 5000 per bulk delete")

    pool = await get_pool()
    async with pool.acquire() as conn:
        deleted = await conn.fetchval(
            "WITH d AS (DELETE FROM garbage_subdomains "
            "WHERE id = ANY($1::bigint[]) AND project_id=$2 RETURNING id) "
            "SELECT COUNT(*) FROM d",
            ids, pid)
    return {"ok": True, "deleted": deleted}


@router.delete("/api/projects/{pid}/garbage")
async def api_garbage_delete_all(
    pid: str,
    promoted_only: bool = Query(False),
    _: str = Depends(require_auth),
):
    """Delete all (or only promoted) garbage entries for a project."""
    pool = await get_pool()
    async with pool.acquire() as conn:
        where = "WHERE project_id=$1" + (" AND promoted=1" if promoted_only else "")
        deleted = await conn.fetchval(
            f"WITH d AS (DELETE FROM garbage_subdomains {where} RETURNING id) "
            "SELECT COUNT(*) FROM d", pid)
    return {"ok": True, "deleted": deleted}


# ── Re-classify ───────────────────────────────────────────────────────────────

@router.post("/api/projects/{pid}/garbage/reclassify")
async def api_garbage_reclassify(
    pid: str,
    request: Request,
    _: str = Depends(require_auth),
):
    """
    Re-run the garbage classifier on all subdomains for a project.
    Useful after importing new subs via manual import.
    Returns how many were newly classified as garbage.
    """
    from utils.garbage_classifier import classify_and_store

    pool = await get_pool()
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            "SELECT subdomain FROM subdomains WHERE project_id=$1", pid)
    subs = [r["subdomain"] for r in rows]
    if not subs:
        return {"ok": True, "reclassified": 0}

    from utils.garbage_classifier import classify_subdomains
    import asyncio

    real, garbage = await asyncio.to_thread(classify_subdomains, subs)

    if garbage:
        now = datetime.now().isoformat()
        garbage_subs = [(g[0], g[1], g[2]) for g in garbage]
        async with pool.acquire() as conn:
            await conn.executemany(
                """INSERT INTO garbage_subdomains
                   (project_id, subdomain, score, reason, source, created_at)
                   VALUES($1, $2, $3, $4, 'reclassify', $5)
                   ON CONFLICT (project_id, subdomain) DO NOTHING""",
                [(pid, sub, score, reason, now) for sub, score, reason in garbage_subs]
            )
            # Remove reclassified subs from subdomains table (not promoted)
            garbage_sub_strs = [g[0] for g in garbage_subs]
            await conn.execute(
                "DELETE FROM subdomains WHERE project_id=$1 AND subdomain = ANY($2::text[])",
                pid, garbage_sub_strs)

    return {"ok": True, "reclassified": len(garbage), "real_remaining": len(real)}
