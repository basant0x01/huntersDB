"""
api/routes_server.py — Server control, sync dispatch, logs, settings, stats, keys, monitor.

FIXES APPLIED:
  FIX-SERVER-01: /api/scan/bulk now loads scope+run_subfinder from DB (subfinder now runs)
  FIX-SERVER-02: /api/server/status uses 60s cached tool version checks (no event-loop block)
  FIX-SERVER-03: Stale scan_progress cleanup in /api/stats/live
"""
import asyncio
import json
import time
import uuid
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Request, Depends, HTTPException, Query
from fastapi.responses import StreamingResponse

from api.auth import require_auth
from db.pool import get_pool
from db.queries import get_stats
from process_manager.manager import manager
from task_queue.redis_queue import (
    enqueue, get_queue_depth, flush_queue,
    get_scan_progress, clear_scan_progress, get_redis,
)
from utils.log import get_live_logs, get_live_log_cursor, clear_live_logs
from utils.settings import load_settings, save_settings
from utils.webhooks import send_webhook

router = APIRouter()

# ── FIX-SERVER-02: Tool version cache — 60s TTL prevents blocking on every poll ──
_tool_version_cache: dict = {}
_tool_cache_ts: float = 0.0
TOOL_CACHE_TTL = 60.0


async def _get_tool_status(name: str) -> dict:
    global _tool_version_cache, _tool_cache_ts
    now = time.monotonic()
    if _tool_version_cache and (now - _tool_cache_ts) < TOOL_CACHE_TTL:
        return _tool_version_cache.get(name, {"ok": False, "version": ""})

    async def _check_one(tool_name: str):
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
        _check_one("httpx"), _check_one("subfinder"), _check_one("nuclei"),
        return_exceptions=True)

    new_cache = {}
    for r in results:
        if isinstance(r, tuple):
            tname, info = r
            new_cache[tname] = info

    _tool_version_cache = new_cache
    _tool_cache_ts = now
    return _tool_version_cache.get(name, {"ok": False, "version": ""})


# ── Stats ─────────────────────────────────────────────────────────────────────

@router.get("/api/stats")
async def api_stats(_: str = Depends(require_auth)):
    pool = await get_pool()
    async with pool.acquire() as conn:
        stats = await get_stats(conn)
    progress = await get_scan_progress()
    queue_depth = await get_queue_depth()
    return {**stats, "progress": list(progress.values()), "queue": queue_depth,
            "ts": datetime.now().isoformat()}


@router.get("/api/stats/live")
async def api_stats_live(_: str = Depends(require_auth)):
    pool = await get_pool()
    async with pool.acquire() as conn:
        scanning = await conn.fetchval(
            "SELECT COUNT(*) FROM projects WHERE scan_status NOT IN ('pending','done')")
        pending = await conn.fetchval("SELECT COUNT(*) FROM projects WHERE scan_status='pending'")
        alive = await conn.fetchval("SELECT COUNT(*) FROM subdomains WHERE is_alive=1")
        total_subs = await conn.fetchval("SELECT COUNT(*) FROM subdomains")
        new_subs = await conn.fetchval("SELECT COUNT(*) FROM subdomains WHERE is_new=1")
        total_projs = await conn.fetchval("SELECT COUNT(*) FROM projects")
        chaos_c = await conn.fetchval("SELECT COUNT(*) FROM projects WHERE source='chaos'")
        h1_c = await conn.fetchval(
            "SELECT COUNT(*) FROM projects WHERE platform='hackerone' OR source='bbscope'")
        ywh_c = await conn.fetchval(
            "SELECT COUNT(*) FROM projects WHERE platform='yeswehack' OR source='yeswehack'")
        vulns = await conn.fetchval("SELECT COUNT(*) FROM vulnerabilities")
        alerts = await conn.fetchval("SELECT COUNT(*) FROM alerts WHERE seen=0")
        review_pending = await conn.fetchval(
            "SELECT COUNT(*) FROM vulnerabilities WHERE review_status='pending_review'")

    try:
        _r = await get_redis()
        _prog_count = await _r.hlen("submind:scan_progress")
        progress = await get_scan_progress() if _prog_count > 0 else {}
    except Exception:
        progress = {}
    queue_depth = await get_queue_depth()

    # Stale progress cleanup
    if progress:
        stale_pids = []
        async with pool.acquire() as conn:
            rows = await conn.fetch(
                "SELECT id, scan_status FROM projects WHERE id = ANY($1::text[])",
                list(progress.keys()))
            db_status = {r["id"]: r["scan_status"] for r in rows}
            for pid in list(progress.keys()):
                if db_status.get(pid) in (None, "done", "pending"):
                    stale_pids.append(pid)
        for pid in stale_pids:
            await clear_scan_progress(pid)
            progress.pop(pid, None)

    project_progress = []
    for pid, v in (progress or {}).items():
        total_v = v.get("total") or 0
        alive_v = v.get("alive") or 0
        pct = int(alive_v / total_v * 100) if total_v > 0 else 0
        project_progress.append({"id": pid, "pct": pct, **v})

    job_info = None
    if project_progress:
        first = project_progress[0]
        job_info = {
            "running": True, "phase": first.get("phase", "A"),
            "current": first.get("alive", 0), "total": first.get("total", 0),
            "pct": first.get("pct", 0), "name": first.get("name", ""),
            "tools": first.get("tools", {}), "eta": "",
        }

    async with pool.acquire() as conn:
        recent_rows = await conn.fetch(
            "SELECT s.subdomain, s.url, s.status_code, s.title, s.tech, "
            "p.name as project_name FROM subdomains s "
            "JOIN projects p ON s.project_id = p.id "
            "WHERE s.is_alive=1 ORDER BY s.last_seen DESC NULLS LAST LIMIT 10")
        sev_rows = await conn.fetch(
            "SELECT severity, COUNT(*) as count FROM vulnerabilities "
            "GROUP BY severity ORDER BY CASE severity "
            "WHEN 'critical' THEN 1 WHEN 'high' THEN 2 "
            "WHEN 'medium' THEN 3 WHEN 'low' THEN 4 ELSE 5 END")
        recent_vuln_rows = await conn.fetch(
            "SELECT v.name, v.severity, p.name as project_name "
            "FROM vulnerabilities v LEFT JOIN projects p ON v.project_id=p.id "
            "ORDER BY v.created_at DESC LIMIT 5")

    return {
        "scanning_count": scanning, "alive": alive, "new_subs": new_subs,
        "vulnerabilities": vulns, "unread_alerts": alerts,
        "review_pending": review_pending, "queue": queue_depth,
        "job": job_info, "project_progress": project_progress,
        "projects": {
            "total": total_projs, "chaos": chaos_c, "hackerone": h1_c,
            "yeswehack": ywh_c, "pending": pending, "scanning": scanning,
        },
        "subdomains": {"alive": alive, "total": total_subs, "new": new_subs},
        "recent_live": [dict(r) for r in recent_rows],
        "vuln_by_severity": [dict(r) for r in sev_rows],
        "recent_vulns": [dict(r) for r in recent_vuln_rows],
        "ts": datetime.now().isoformat(),
    }


@router.get("/api/stats/stream")
async def api_stats_stream(request: Request, _: str = Depends(require_auth)):
    pool = await get_pool()

    async def generate():
        while True:
            if await request.is_disconnected():
                break
            try:
                async with pool.acquire() as conn:
                    stats = await get_stats(conn)
                progress = await get_scan_progress()
                queue_depth = await get_queue_depth()
                data = json.dumps({
                    **stats, "progress": list(progress.values()),
                    "queue": queue_depth, "ts": datetime.now().isoformat()})
                yield f"data: {data}\n\n"
            except Exception:
                yield f"data: {json.dumps({'error': 'stats_error'})}\n\n"
            await asyncio.sleep(5)

    return StreamingResponse(generate(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


# ── Logs ──────────────────────────────────────────────────────────────────────

@router.get("/api/logs")
async def api_logs(since: int = Query(0), limit: int = Query(500, le=5000),
                   level: str = Query(""), category: str = Query(""), q: str = Query(""),
                   _: str = Depends(require_auth)):
    entries = get_live_logs(since_id=since)
    if level: entries = [e for e in entries if e.get("level") == level]
    if category: entries = [e for e in entries if e.get("category") == category]
    if q:
        q_lower = q.lower()
        entries = [e for e in entries if q_lower in (e.get("message") or "").lower()]
    return entries[-limit:]


@router.get("/api/logs/live")
async def api_logs_live(since: int = Query(0), limit: int = Query(200, le=2000),
                        level: str = Query(""), category: str = Query(""),
                        _: str = Depends(require_auth)):
    entries = get_live_logs(since_id=since)
    if level: entries = [e for e in entries if e.get("level") == level]
    if category: entries = [e for e in entries if e.get("category") == category]
    return {"logs": entries[-limit:], "cursor": get_live_log_cursor()}


@router.post("/api/logs/clear")
async def api_logs_clear(_: str = Depends(require_auth)):
    clear_live_logs()
    return {"ok": True}


@router.get("/api/logs/db")
async def api_logs_db(limit: int = Query(200, le=1000), level: str = Query(""),
                      category: str = Query(""), job_id: str = Query(""),
                      _: str = Depends(require_auth)):
    pool = await get_pool()
    conditions, params, idx = [], [], 1
    if level: conditions.append(f"level=${idx}"); params.append(level); idx += 1
    if category: conditions.append(f"category=${idx}"); params.append(category); idx += 1
    if job_id: conditions.append(f"job_id=${idx}"); params.append(job_id); idx += 1
    where = ("WHERE " + " AND ".join(conditions)) if conditions else ""
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            f"SELECT * FROM system_logs {where} ORDER BY timestamp DESC LIMIT ${idx}",
            *params, limit)
    return {"logs": [dict(r) for r in rows]}


@router.get("/api/server/logs")
async def api_server_logs(since: int = Query(0), limit: int = Query(200, le=1000),
                          level: str = Query(""), _: str = Depends(require_auth)):
    pool = await get_pool()
    conditions = [f"id>{since}"] if since > 0 else []
    params, idx = [], 1
    if level: conditions.append(f"level=${idx}"); params.append(level); idx += 1
    where = ("WHERE " + " AND ".join(conditions)) if conditions else ""
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            f"SELECT id, timestamp AS ts, level, category AS name, message, detail "
            f"FROM system_logs {where} ORDER BY id DESC LIMIT ${idx}",
            *params, limit)
    logs = [dict(r) for r in rows]
    return {"logs": logs, "cursor": logs[0]["id"] if logs else since}


@router.post("/api/server/logs/clear")
async def api_server_logs_clear(_: str = Depends(require_auth)):
    pool = await get_pool()
    async with pool.acquire() as conn:
        await conn.execute("DELETE FROM system_logs")
    clear_live_logs()
    return {"ok": True}


# ── Settings ──────────────────────────────────────────────────────────────────

@router.get("/api/settings")
async def api_get_settings(_: str = Depends(require_auth)):
    s = load_settings()
    masked = dict(s)
    for k in ("h1_token", "ywh_token", "bbscope_hackerone_token", "bbscope_yeswehack_token"):
        if masked.get(k): masked[k] = "***"
    return masked


@router.post("/api/settings")
async def api_save_settings(request: Request, _: str = Depends(require_auth)):
    data = await request.json()
    s = load_settings()
    s.update(data)
    await asyncio.to_thread(save_settings, s)
    return {"ok": True}


# ── Sync dispatch ──────────────────────────────────────────────────────────────

@router.post("/api/chaos/sync")
@router.post("/api/sync/chaos")
async def api_chaos_sync(request: Request, _: str = Depends(require_auth)):
    data = await request.json()
    jid = str(uuid.uuid4())
    platforms_raw = data.get("platforms") or data.get("platform")
    if isinstance(platforms_raw, list):
        platform_str = ",".join(p.strip() for p in platforms_raw if p.strip()) or None
    elif isinstance(platforms_raw, str) and platforms_raw.strip():
        platform_str = platforms_raw.strip()
    else:
        platform_str = None
    return await enqueue(job_type="chaos_sync", project_id=None, priority=2, job_id=jid,
                         payload={"bounty_only": data.get("bounty_only", True), "platform": platform_str})


@router.get("/api/chaos/available-platforms")
async def api_chaos_available_platforms(_: str = Depends(require_auth)):
    import aiohttp as _aiohttp
    from workers.sync_worker import fetch_chaos_index as _fetch_idx
    try:
        async with _aiohttp.ClientSession(headers={"User-Agent": "SubmindPro/8.0"}) as session:
            idx = await _fetch_idx(session)
        if not idx["ok"]:
            return {"platforms": [], "error": idx.get("error")}
        platforms = sorted({(p.get("platform") or "").strip() for p in idx["data"]
                            if (p.get("platform") or "").strip()})
        from collections import Counter
        counts = Counter((p.get("platform") or "").strip() for p in idx["data"]
                         if (p.get("platform") or "").strip())
        return {"platforms": [{"name": pl, "count": counts[pl]} for pl in platforms],
                "total_programs": len(idx["data"])}
    except Exception as e:
        return {"platforms": [], "error": str(e)}


@router.post("/api/sync/hackerone")
async def api_h1_sync(_: str = Depends(require_auth)):
    s = load_settings()
    jid = str(uuid.uuid4())
    return await enqueue(job_type="h1_sync", project_id=None, priority=2, job_id=jid,
                         payload={"username": s.get("h1_username", ""), "token": s.get("h1_token", "")})


@router.post("/api/sync/yeswehack")
async def api_ywh_sync(_: str = Depends(require_auth)):
    s = load_settings()
    jid = str(uuid.uuid4())
    return await enqueue(job_type="ywh_sync", project_id=None, priority=2, job_id=jid,
                         payload={"token": s.get("ywh_token", "")})


@router.get("/api/sync/history")
async def api_sync_history(_: str = Depends(require_auth)):
    pool = await get_pool()
    async with pool.acquire() as conn:
        rows = await conn.fetch("SELECT * FROM sync_jobs ORDER BY started_at DESC LIMIT 50")
    result = []
    for r in rows:
        row = dict(r)
        plat = (row.get("platform") or "").lower()
        row["sync_type"] = "bbscope" if plat in ("hackerone", "bugcrowd", "yeswehack") else "chaos"
        elapsed = 0
        if row.get("started_at") and row.get("ended_at"):
            try:
                t0 = datetime.fromisoformat(row["started_at"])
                t1 = datetime.fromisoformat(row["ended_at"])
                elapsed = max(0, int((t1 - t0).total_seconds()))
            except Exception:
                pass
        row["time_elapsed"] = elapsed
        row["programs_imported"] = row.get("imported", 0)
        row["subdomains_alive"] = row.get("scanned", 0)
        result.append(row)
    return result


@router.get("/api/sync/history/{jid}/logs")
async def api_sync_job_logs(jid: str, _: str = Depends(require_auth)):
    pool = await get_pool()
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            "SELECT * FROM system_logs WHERE job_id=$1 ORDER BY timestamp ASC LIMIT 500", jid)
    return [dict(r) for r in rows]


@router.get("/api/chaos/platforms")
async def api_chaos_platforms(_: str = Depends(require_auth)):
    pool = await get_pool()
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            "SELECT platform FROM projects WHERE source='chaos' AND platform!='' "
            "GROUP BY platform ORDER BY COUNT(*) DESC")
    return {"platforms": [r["platform"] for r in rows]}


@router.get("/api/chaos/status")
async def api_chaos_status(_: str = Depends(require_auth)):
    pool = await get_pool()
    async with pool.acquire() as conn:
        total = await conn.fetchval("SELECT COUNT(*) FROM projects WHERE source='chaos'")
        last_job = await conn.fetchrow(
            "SELECT * FROM sync_jobs WHERE platform='chaos' OR platform IS NULL OR platform='' "
            "ORDER BY started_at DESC LIMIT 1")
        synced_done = await conn.fetchval(
            "SELECT COUNT(*) FROM projects WHERE source='chaos' AND scan_status='done'")
        total_subs = await conn.fetchval(
            "SELECT COUNT(*) FROM subdomains s JOIN projects p ON s.project_id=p.id WHERE p.source='chaos'")
    job: dict = {}
    if last_job:
        row = dict(last_job)
        running = row.get("status") == "running"
        job = {
            "running": running, "phase": row.get("phase", ""), "total": row.get("total", 0),
            "current": row.get("imported", 0), "imported": row.get("imported", 0),
            "failed": row.get("failed", 0), "skipped": row.get("skipped", 0),
            "scanned": row.get("scanned", 0), "status": row.get("status", ""),
            "started_at": row.get("started_at", ""), "ended_at": row.get("ended_at", ""),
        }
    return {"total": total, "synced_done": synced_done, "total_subs": total_subs, "job": job}


@router.get("/api/chaos/preview")
async def api_chaos_preview(_: str = Depends(require_auth)):
    pool = await get_pool()
    async with pool.acquire() as conn:
        total = await conn.fetchval("SELECT COUNT(*) FROM projects WHERE source='chaos'")
        bounty = await conn.fetchval("SELECT COUNT(*) FROM projects WHERE source='chaos' AND bounty>0")
        total_subs = await conn.fetchval(
            "SELECT COUNT(*) FROM subdomains s JOIN projects p ON s.project_id=p.id WHERE p.source='chaos'")
        plat_rows = await conn.fetch(
            "SELECT platform, COUNT(*) as c FROM projects "
            "WHERE source='chaos' AND platform!='' GROUP BY platform ORDER BY c DESC LIMIT 12")
    return {"total": total, "bounty": bounty, "total_subdomains": total_subs,
            "platforms": {r["platform"]: r["c"] for r in plat_rows}}


@router.post("/api/h1/sync")
async def api_h1_sync_dispatch(request: Request, _: str = Depends(require_auth)):
    data = await request.json()
    platform = data.get("platform", "hackerone").lower()
    s = load_settings()
    jid = str(uuid.uuid4())
    if platform in ("yeswehack", "ywh"):
        return await enqueue(job_type="ywh_sync", project_id=None, priority=2, job_id=jid,
                             payload={"token": s.get("ywh_token", "")})
    return await enqueue(job_type="h1_sync", project_id=None, priority=2, job_id=jid,
                         payload={"username": s.get("h1_username", ""), "token": s.get("h1_token", "")})


@router.post("/api/h1/test")
async def api_h1_test(request: Request, _: str = Depends(require_auth)):
    import aiohttp as _aiohttp
    data = await request.json()
    platform = data.get("platform", "hackerone").lower()
    s = load_settings()
    if platform in ("yeswehack", "ywh"):
        token = s.get("ywh_token", "") or s.get("bbscope_yeswehack_token", "")
        if not token:
            return {"ok": False, "error": "YesWeHack token not configured"}
        try:
            async with _aiohttp.ClientSession(headers={"Authorization": f"Token {token}"}) as session:
                async with session.get("https://api.yeswehack.com/programs?page=1&rowsPerPage=1",
                                       timeout=_aiohttp.ClientTimeout(total=10)) as r:
                    if r.status == 200:
                        d = await r.json()
                        count = d.get("pagination", {}).get("nb_results", 0)
                        return {"ok": True, "message": f"YesWeHack connected — {count} programs"}
                    return {"ok": False, "error": f"HTTP {r.status}"}
        except Exception as e:
            return {"ok": False, "error": f"Connection error: {e}"}
    else:
        token = s.get("h1_token", "") or s.get("bbscope_hackerone_token", "")
        username = s.get("h1_username", "") or s.get("bbscope_hackerone_username", "")
        if not token or not username:
            return {"ok": False, "error": "HackerOne username and token required"}
        try:
            async with _aiohttp.ClientSession() as session:
                async with session.get(
                    "https://api.hackerone.com/v1/hackers/programs?page[number]=1&page[size]=1",
                    auth=_aiohttp.BasicAuth(username, token),
                    timeout=_aiohttp.ClientTimeout(total=10)) as r:
                    if r.status == 200:
                        return {"ok": True, "message": f"HackerOne connected for @{username}"}
                    return {"ok": False, "error": f"HTTP {r.status}"}
        except Exception as e:
            return {"ok": False, "error": f"Connection error: {e}"}


@router.get("/api/h1/platforms")
async def api_h1_platforms(_: str = Depends(require_auth)):
    pool = await get_pool()
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            "SELECT platform FROM projects WHERE platform!='' "
            "GROUP BY platform ORDER BY COUNT(*) DESC LIMIT 20")
    return {"platforms": [r["platform"] for r in rows]}


@router.get("/api/sync/status")
async def api_sync_status(_: str = Depends(require_auth)):
    pool = await get_pool()
    async with pool.acquire() as conn:
        chaos_total = await conn.fetchval("SELECT COUNT(*) FROM projects WHERE source='chaos'")
        chaos_job = await conn.fetchrow(
            "SELECT * FROM sync_jobs WHERE platform='chaos' OR platform IS NULL OR platform='' "
            "ORDER BY started_at DESC LIMIT 1")
        h1_total = await conn.fetchval(
            "SELECT COUNT(*) FROM projects WHERE platform='hackerone' OR source='hackerone'")
        h1_job = await conn.fetchrow(
            "SELECT * FROM sync_jobs WHERE platform='hackerone' ORDER BY started_at DESC LIMIT 1")
        ywh_total = await conn.fetchval(
            "SELECT COUNT(*) FROM projects WHERE platform='yeswehack' OR source='yeswehack'")
        ywh_job = await conn.fetchrow(
            "SELECT * FROM sync_jobs WHERE platform='yeswehack' ORDER BY started_at DESC LIMIT 1")

    def _js(row) -> dict:
        if not row: return {"running": False, "status": "idle"}
        r = dict(row)
        return {"running": r.get("status") == "running", "status": r.get("status", "idle"),
                "phase": r.get("phase", ""), "imported": r.get("imported", 0),
                "total": r.get("total", 0), "failed": r.get("failed", 0),
                "started_at": r.get("started_at", ""), "ended_at": r.get("ended_at", "")}

    return {"chaos": {"total": chaos_total, **_js(chaos_job)},
            "h1": {"total": h1_total, **_js(h1_job)},
            "yeswehack": {"total": ywh_total, **_js(ywh_job)}}


@router.get("/api/nuclei/queue")
async def api_nuclei_queue(_: str = Depends(require_auth)):
    pool = await get_pool()
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            """SELECT p.id, p.name, p.platform, p.source, p.scan_status,
                      p.phase_d_done_at, p.phase_c_done_at,
                      (SELECT COUNT(*) FROM subdomains s WHERE s.project_id=p.id AND s.is_alive=1) as alive_count,
                      (SELECT COUNT(*) FROM vulnerabilities v WHERE v.project_id=p.id) as vuln_count
               FROM projects p WHERE p.scan_status='done' AND p.phase_c_done_at IS NOT NULL
               ORDER BY p.phase_c_done_at DESC LIMIT 200""")
    return {"projects": [dict(r) for r in rows], "total": len(rows)}


@router.post("/api/nuclei/run")
async def api_nuclei_run(request: Request, _: str = Depends(require_auth)):
    data = await request.json()
    pid = data.get("project_id")
    if not pid:
        raise HTTPException(status_code=400, detail="project_id is required")
    pool = await get_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow("SELECT id, name FROM projects WHERE id=$1", pid)
    if not row:
        raise HTTPException(status_code=404, detail="Project not found")
    jid = str(uuid.uuid4())
    result = await enqueue(job_type="nuclei_only", project_id=pid, priority=2, job_id=jid,
                           payload={"templates": data.get("templates"), "severity": data.get("severity")})
    return {**result, "project_id": pid, "project_name": row["name"]}


# ── FIX-SERVER-01: /api/scan/bulk — scope loaded from DB (subfinder will run) ─

@router.post("/api/scan/bulk")
async def api_bulk_scan(request: Request, _: str = Depends(require_auth)):
    """
    FIX-SERVER-01: Previously sent projects without scope — subfinder never ran.
    Now loads scope+run_subfinder from DB, identical to /api/projects/bulk-scan.
    """
    data = await request.json()
    project_ids = data.get("project_ids", [])
    if not project_ids:
        raise HTTPException(status_code=400, detail="project_ids required")
    if len(project_ids) > 500:
        raise HTTPException(status_code=400, detail="Max 500 projects per bulk scan")

    pool = await get_pool()
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            "SELECT id, name, scope FROM projects WHERE id = ANY($1::text[])", project_ids)

    projects = []
    for r in rows:
        try:
            scope = json.loads(r["scope"] or "[]")
        except Exception:
            scope = []
        projects.append({
            "id": r["id"], "name": r["name"],
            "run_subfinder": bool(scope), "scope": scope,
        })

    jid = str(uuid.uuid4())
    return await enqueue(job_type="scan_bulk", project_id=None, priority=1, job_id=jid,
                         payload={"projects": projects})


# ── Stop / Resume ──────────────────────────────────────────────────────────────

@router.post("/api/server/scans/stop")
async def api_stop_all_scans(_: str = Depends(require_auth)):
    await flush_queue()
    killed = await manager.kill_all()
    pool = await get_pool()
    stuck_statuses = (
        "scanning", "nuclei_scanning", "recon_done",
        "phase_a", "phase_a_done", "phase_b_done", "phase_c_done", "phase_d")
    async with pool.acquire() as conn:
        stuck = await conn.fetchval(
            "SELECT COUNT(*) FROM projects WHERE scan_status = ANY($1::text[])", list(stuck_statuses))
        if stuck:
            await conn.execute(
                "UPDATE projects SET scan_status='pending' WHERE scan_status = ANY($1::text[])",
                list(stuck_statuses))
    try:
        r = await get_redis()
        await r.delete("submind:scan_progress")
    except Exception:
        pass
    return {"ok": True, "stopped_procs": killed, "killed_procs": killed, "reset_projects": stuck}


@router.post("/api/server/scans/resume")
async def api_resume_scans(_: str = Depends(require_auth)):
    import json as _json
    pool = await get_pool()
    async with pool.acquire() as conn:
        mid_d = await conn.fetch("SELECT id FROM projects WHERE scan_status='phase_d'")
        if mid_d:
            ids = [r["id"] for r in mid_d]
            await conn.execute(
                "UPDATE projects SET scan_status='phase_c_done' WHERE id = ANY($1::text[])", ids)

    async with pool.acquire() as conn:
        interrupted = await conn.fetch("""
            SELECT p.id, p.name, p.scan_status, p.scope,
                   (SELECT COUNT(*) FROM subdomains s WHERE s.project_id=p.id) AS sub_count,
                   (SELECT COUNT(*) FROM subdomains s WHERE s.project_id=p.id AND s.is_alive=1) AS alive_count
            FROM projects p
            WHERE p.scan_status IN ('phase_a','phase_a_done','phase_b_done')
               OR (p.scan_status='pending' AND EXISTS(SELECT 1 FROM subdomains s WHERE s.project_id=p.id LIMIT 1))
            ORDER BY p.updated_at DESC NULLS LAST
        """)

    if not interrupted:
        return {"ok": True, "queued": 0, "msg": "No interrupted scans found"}

    queued, errors = [], []
    for row in interrupted:
        try:
            pid = row["id"]
            pname = row["name"]
            phase = row["scan_status"]
            sub_count = row["sub_count"]
            try:
                scope = _json.loads(row["scope"] or "[]")
            except Exception:
                scope = []
            run_subfinder = (sub_count == 0 and bool(scope))
            result = await enqueue(
                job_type="scan", project_id=pid, priority=2,
                payload={"project_name": pname, "run_subfinder": run_subfinder,
                         "scope": scope, "resume_from": phase, "auto_resumed": True})
            queued.append({"id": pid, "name": pname, "phase": phase,
                           "subs": sub_count, "job_id": result.get("job_id")})
        except Exception as e:
            errors.append({"id": row["id"], "name": row["name"], "error": str(e)})

    statuses: dict = {}
    for q in queued:
        s = q["phase"]
        statuses[s] = statuses.get(s, 0) + 1

    return {"ok": True, "queued": len(queued), "errors": len(errors),
            "status_breakdown": statuses, "projects": queued, "failed": errors}


@router.post("/api/server/tool/{name}/stop")
async def api_stop_tool(name: str, _: str = Depends(require_auth)):
    killed = await manager.kill_by_name(name)
    return {"ok": True, "killed": killed, "tool": name}


@router.post("/api/server/restart")
async def api_server_restart(_: str = Depends(require_auth)):
    killed = await manager.kill_all()
    return {"ok": True, "killed_procs": killed,
            "msg": "Worker subprocesses stopped. Restart the service to reinitialize."}


# ── FIX-SERVER-02: /api/server/status with cached tool checks ─────────────────

@router.get("/api/server/status")
async def api_server_status(_: str = Depends(require_auth)):
    active = await manager.get_active()
    queue_depth = await get_queue_depth()
    pool = await get_pool()
    async with pool.acquire() as conn:
        stats = await get_stats(conn)
        scanning = await conn.fetchval(
            "SELECT COUNT(*) FROM projects WHERE scan_status NOT IN ('pending','done')")

    tool_descs = {"httpx": "HTTP prober", "subfinder": "Subdomain discovery", "nuclei": "Vulnerability scanner"}
    tool_results = await asyncio.gather(
        _get_tool_status("httpx"), _get_tool_status("subfinder"), _get_tool_status("nuclei"))
    tools = {name: {"desc": tool_descs[name], **result}
             for name, result in zip(tool_descs.keys(), tool_results)}

    processes = {}
    for proc_info in active:
        tool = proc_info.get("tool", proc_info.get("name", "unknown"))
        processes[tool] = {"running": True, **proc_info}

    from config.settings import MAX_SUBPROCESSES
    return {
        "active_subprocesses": active, "subprocess_count": len(active),
        "queue": queue_depth, "tools": tools, "processes": processes,
        "active_scans": {"count": scanning, "max": MAX_SUBPROCESSES},
        "bulk_scan": {"running": scanning > 0, "count": scanning},
        "backup": {"exists": False}, **stats,
    }


@router.get("/api/tools")
async def api_tools(_: str = Depends(require_auth)):
    async def _check(name):
        try:
            proc = await asyncio.create_subprocess_exec(
                name, "--version",
                stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL)
            await asyncio.wait_for(proc.wait(), timeout=5)
            return proc.returncode == 0
        except Exception:
            return False
    results = await asyncio.gather(_check("httpx"), _check("subfinder"), _check("nuclei"))
    return {"httpx": results[0], "subfinder": results[1], "nuclei": results[2]}


@router.get("/api/tech/search")
async def api_tech_search(q: str = Query(""), tech: str = Query(""),
                          limit: int = Query(50, ge=1, le=5000), _: str = Depends(require_auth)):
    query = q or tech
    if not query:
        raise HTTPException(status_code=422, detail="q or tech parameter required")
    pool = await get_pool()
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            """SELECT s.subdomain, s.url, s.tech, s.status_code, s.title,
                      p.name as project_name, p.id as project_id
               FROM subdomains s JOIN projects p ON s.project_id=p.id
               WHERE s.tech ILIKE $1 AND s.is_alive=1
               ORDER BY s.last_seen DESC NULLS LAST LIMIT $2""",
            f"%{query}%", limit)
    results = [dict(r) for r in rows]
    return {"results": results, "subdomains": results, "total": len(results)}


@router.get("/api/monitor/status")
async def api_monitor_status(_: str = Depends(require_auth)):
    pool = await get_pool()
    async with pool.acquire() as conn:
        scanning = await conn.fetchval(
            "SELECT COUNT(*) FROM projects WHERE scan_status NOT IN ('pending','done')")
    return {"running": scanning > 0, "active_scans": scanning}


@router.post("/api/monitor/trigger")
async def api_monitor_trigger(request: Request, _: str = Depends(require_auth)):
    pool = await get_pool()
    async with pool.acquire() as conn:
        pending = await conn.fetch(
            "SELECT id, name, scope FROM projects WHERE scan_status='pending' LIMIT 50")
    if not pending:
        return {"ok": True, "msg": "No pending projects", "queued": 0}
    projects = []
    for r in pending:
        try:
            scope = json.loads(r["scope"] or "[]")
        except Exception:
            scope = []
        projects.append({"id": r["id"], "name": r["name"], "run_subfinder": bool(scope), "scope": scope})
    jid = str(uuid.uuid4())
    result = await enqueue(job_type="scan_bulk", project_id=None, priority=1, job_id=jid,
                           payload={"projects": projects})
    return {**result, "queued": len(projects)}


@router.get("/api/templates/status")
async def api_templates_status(_: str = Depends(require_auth)):
    from pathlib import Path
    templates_path = Path.home() / "nuclei-templates"
    exists = templates_path.exists()
    count = 0
    if exists:
        try:
            count = sum(1 for _ in templates_path.rglob("*.yaml"))
        except Exception:
            pass
    return {"exists": exists, "path": str(templates_path), "count": count}


@router.post("/api/templates/update")
async def api_templates_update(_: str = Depends(require_auth)):
    jid = str(uuid.uuid4())
    return await enqueue(job_type="templates_update", project_id=None, priority=3, job_id=jid, payload={})


@router.post("/api/templates/sweep")
async def api_templates_sweep(request: Request, _: str = Depends(require_auth)):
    try:
        data = await request.json()
    except Exception:
        data = {}
    jid = str(uuid.uuid4())
    return await enqueue(job_type="nuclei_sweep", project_id=None, priority=2, job_id=jid,
                         payload={"templates": data.get("templates"), "severity": data.get("severity")})


@router.get("/api/keys")
async def api_list_keys(_: str = Depends(require_auth)):
    pool = await get_pool()
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            "SELECT id, name, key_hash, created_at, last_used FROM api_keys ORDER BY created_at DESC")
    return [{"id": r["id"], "name": r["name"], "key": r["key_hash"], "active": True,
             "usage_count": 0, "created_at": r["created_at"], "last_used": r["last_used"]}
            for r in rows]


@router.post("/api/keys")
async def api_create_key(request: Request, _: str = Depends(require_auth)):
    import hashlib, secrets
    data = await request.json()
    raw_key = secrets.token_urlsafe(32)
    key_hash = hashlib.sha256(raw_key.encode()).hexdigest()
    now = datetime.now().isoformat()
    pool = await get_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            "INSERT INTO api_keys(key_hash, name, created_at) VALUES($1,$2,$3) RETURNING id",
            key_hash, data.get("name", ""), now)
    return {"ok": True, "id": row["id"], "key": raw_key, "name": data.get("name", "")}


@router.post("/api/keys/{kid}/revoke")
async def api_revoke_key(kid: int, _: str = Depends(require_auth)):
    pool = await get_pool()
    async with pool.acquire() as conn:
        await conn.execute("DELETE FROM api_keys WHERE id=$1", kid)
    return {"ok": True}


@router.post("/api/notifications/test")
async def api_notifications_test(_: str = Depends(require_auth)):
    s = load_settings()
    sent = []
    if s.get("discord_webhook_url", "").strip(): sent.append("Discord")
    if s.get("slack_webhook_url", "").strip(): sent.append("Slack")
    if s.get("telegram_bot_token", "").strip() and s.get("telegram_chat_id", "").strip():
        sent.append("Telegram")
    if not sent:
        raise HTTPException(status_code=400, detail="No notification channels configured")
    await send_webhook("🧪 SUBMIND PRO Test Alert", "Test notification from SUBMIND PRO.", "info")
    return {"ok": True, "message": f"Test sent to: {', '.join(sent)}"}


@router.get("/api/scan-eta")
async def api_scan_eta(count: int = Query(0), _: str = Depends(require_auth)):
    from config.settings import PHASE_A_CONCURRENT
    concurrent = PHASE_A_CONCURRENT
    batches = max(1, (count + concurrent - 1) // concurrent) if concurrent > 0 else count
    eta_secs = batches * 120
    eta_str = f"~{eta_secs // 60}m {eta_secs % 60}s" if eta_secs >= 60 else f"~{eta_secs}s"
    return {"count": count, "concurrent": concurrent, "eta_secs": eta_secs, "eta": eta_str}


@router.post("/api/backup/restore")
async def api_backup_restore(request: Request, _: str = Depends(require_auth)):
    data = await request.json()
    jid = str(uuid.uuid4())
    return await enqueue(job_type="backup_restore", project_id=None, priority=3, job_id=jid,
                         payload={"path": data.get("path", "")})


@router.get("/api/debug/schema")
async def api_debug_schema(_: str = Depends(require_auth)):
    pool = await get_pool()
    async with pool.acquire() as conn:
        proj_cols = await conn.fetch(
            "SELECT column_name, data_type FROM information_schema.columns "
            "WHERE table_name='projects' ORDER BY ordinal_position")
        sub_cols = await conn.fetch(
            "SELECT column_name, data_type FROM information_schema.columns "
            "WHERE table_name='subdomains' ORDER BY ordinal_position")
    return {"projects": [dict(r) for r in proj_cols], "subdomains": [dict(r) for r in sub_cols]}


def _build_platform_live_status(job_row: Optional[dict]) -> dict:
    if not job_row:
        return {"running": False, "phase": ""}
    running = job_row.get("status") == "running"
    return {
        "running": running, "phase": job_row.get("phase", "done" if not running else "import"),
        "imported": job_row.get("imported", 0), "total_programs": job_row.get("total", 0),
        "failed": job_row.get("failed", 0), "skipped": job_row.get("skipped", 0),
        "scanned": job_row.get("scanned", 0), "completed_scan": job_row.get("scanned", 0),
        "total_scan": job_row.get("total", 0), "scanned_subs": job_row.get("scanned", 0),
        "total_alive_db": 0, "deep_scanned_subs": 0, "active_scans": 0,
        "max_concurrent": 10, "current_program": "", "db_projects": None, "project_progress": [],
    }


@router.get("/api/h1/live")
async def api_h1_live(_: str = Depends(require_auth)):
    pool = await get_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT * FROM sync_jobs WHERE platform='hackerone' ORDER BY started_at DESC LIMIT 1")
        prog_count = await conn.fetchval(
            "SELECT COUNT(*) FROM projects WHERE platform='hackerone' OR source='hackerone'")
        done_count = await conn.fetchval(
            "SELECT COUNT(*) FROM projects WHERE (platform='hackerone' OR source='hackerone') AND scan_status='done'")
        vuln_count = await conn.fetchval(
            "SELECT COUNT(*) FROM vulnerabilities v JOIN projects p ON v.project_id=p.id "
            "WHERE p.platform='hackerone' OR p.source='hackerone'")
    status = _build_platform_live_status(dict(row) if row else None)
    status.update({"program_count": prog_count, "done_count": done_count, "vuln_count": vuln_count})
    return status


@router.get("/api/ywh/live")
async def api_ywh_live(_: str = Depends(require_auth)):
    pool = await get_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT * FROM sync_jobs WHERE platform='yeswehack' ORDER BY started_at DESC LIMIT 1")
        prog_count = await conn.fetchval(
            "SELECT COUNT(*) FROM projects WHERE platform='yeswehack' OR source='yeswehack'")
        done_count = await conn.fetchval(
            "SELECT COUNT(*) FROM projects WHERE (platform='yeswehack' OR source='yeswehack') AND scan_status='done'")
        vuln_count = await conn.fetchval(
            "SELECT COUNT(*) FROM vulnerabilities v JOIN projects p ON v.project_id=p.id "
            "WHERE p.platform='yeswehack' OR p.source='yeswehack'")
    status = _build_platform_live_status(dict(row) if row else None)
    status.update({"program_count": prog_count, "done_count": done_count, "vuln_count": vuln_count})
    return status
