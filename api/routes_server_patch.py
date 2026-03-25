"""
Patch for routes_server.py — /api/scan/bulk endpoint.

FIX-SERVER-01: The /api/scan/bulk endpoint was sending projects to the
               worker WITHOUT loading scope or run_subfinder from the DB.
               This meant subfinder never ran for bulk scans from this endpoint.

               The correct endpoint is /api/projects/bulk-scan (routes_projects.py)
               which already loads scope properly. This patch fixes /api/scan/bulk
               to match the same behavior.

               Replace the existing api_bulk_scan function in routes_server.py
               with this corrected version.

ALSO: /api/server/status was spawning tool --version subprocesses on every
      single poll call (potentially every 2-5 seconds), blocking the event loop
      for ~15 seconds total per call. Added a 60-second cache.
"""
import asyncio
import json
import time
import uuid
from datetime import datetime
from fastapi import APIRouter, Request, Depends, HTTPException
from api.auth import require_auth
from db.pool import get_pool
from task_queue.redis_queue import enqueue

# ── Tool version cache (prevents blocking the event loop on every status poll) ──
_tool_cache: dict = {}
_tool_cache_ts: float = 0.0
TOOL_CACHE_TTL = 60.0  # seconds


async def _check_tool(name: str) -> dict:
    """Check if a tool is installed. Cached for TOOL_CACHE_TTL seconds."""
    global _tool_cache, _tool_cache_ts
    now = time.monotonic()
    if _tool_cache and (now - _tool_cache_ts) < TOOL_CACHE_TTL:
        return _tool_cache.get(name, {"ok": False, "version": ""})

    # Cache expired — refresh all tools at once
    async def _single_check(tool_name: str) -> tuple:
        try:
            proc = await asyncio.create_subprocess_exec(
                tool_name, "--version",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE)
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=5)
            ok = proc.returncode == 0
            version = stdout.decode().strip().splitlines()[0] if ok and stdout else ""
            return tool_name, {"ok": ok, "version": version}
        except Exception:
            return tool_name, {"ok": False, "version": ""}

    results = await asyncio.gather(
        _single_check("httpx"),
        _single_check("subfinder"),
        _single_check("nuclei"),
        return_exceptions=True,
    )
    new_cache = {}
    for r in results:
        if isinstance(r, tuple):
            tool_name, info = r
            new_cache[tool_name] = info

    _tool_cache = new_cache
    _tool_cache_ts = now
    return _tool_cache.get(name, {"ok": False, "version": ""})


# ── Fixed /api/scan/bulk ───────────────────────────────────────────────────────
# Replace the existing api_bulk_scan function body with this corrected version.
# The function signature stays the same.

async def api_bulk_scan_fixed(request: Request, _require_auth_dep) -> dict:
    """
    FIX-SERVER-01: Load scope from DB for each project so subfinder runs.
    Previously sent projects without scope/run_subfinder — subfinder never fired.
    """
    data = await request.json()
    project_ids = data.get("project_ids", [])
    if not project_ids:
        raise HTTPException(status_code=400, detail="project_ids required")
    if len(project_ids) > 500:
        raise HTTPException(status_code=400, detail="Max 500 projects per bulk scan")

    pool = await get_pool()

    # FIX: Load scope from DB — identical to /api/projects/bulk-scan
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            "SELECT id, name, scope FROM projects WHERE id = ANY($1::text[])",
            project_ids)

    projects = []
    for r in rows:
        try:
            scope = json.loads(r["scope"] or "[]")
        except Exception:
            scope = []
        projects.append({
            "id":            r["id"],
            "name":          r["name"],
            "run_subfinder": bool(scope),  # only run if scope defined
            "scope":         scope,
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
