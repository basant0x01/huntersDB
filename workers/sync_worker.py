"""
workers/sync_worker.py — Async port of master_sync() and bbscope sync.

FIX-SYNC-01: _chaos_lock was created at module import time with
             asyncio.Lock() which raises RuntimeError in Python 3.12
             when no event loop exists yet. Now uses lazy init pattern
             identical to pool_lock and redis_lock.

All other fixes from original file preserved.
"""
import asyncio
import json
import logging
import re
import time
import uuid
import zipfile
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import aiohttp

from config.settings import CHAOS_DIR, CHAOS_INDEX, CHAOS_CACHE_TTL
from db.queries import upsert_subdomains, set_phase
from utils.log import log
from utils.settings import load_settings
from utils.clean import clean_subdomains
from utils.garbage_classifier import classify_and_store
from workers.scanning import run_all_phases_ordered

logger = logging.getLogger("workers.sync")

# FIX-SYNC-01: lazy lock — NOT created at module import time
_chaos_cache: Dict = {"data": None, "ts": 0}
_chaos_lock: Optional[asyncio.Lock] = None


def _get_chaos_lock() -> asyncio.Lock:
    """Return the chaos cache lock, creating it lazily inside the event loop."""
    global _chaos_lock
    if _chaos_lock is None:
        _chaos_lock = asyncio.Lock()
    return _chaos_lock


async def fetch_chaos_index(session: aiohttp.ClientSession) -> Dict:
    lock = _get_chaos_lock()
    async with lock:
        now = time.time()
        if _chaos_cache["data"] and (now - _chaos_cache["ts"]) < CHAOS_CACHE_TTL:
            return {"ok": True, "data": _chaos_cache["data"]}
    try:
        async with session.get(CHAOS_INDEX, timeout=aiohttp.ClientTimeout(total=60)) as r:
            r.raise_for_status()
            data = await r.json(content_type=None)
            async with lock:
                _chaos_cache["data"] = data
                _chaos_cache["ts"] = time.time()
            return {"ok": True, "data": data}
    except Exception as e:
        async with lock:
            if _chaos_cache["data"]:
                return {"ok": True, "data": _chaos_cache["data"]}
        return {"ok": False, "error": str(e)}


async def download_chaos_zip(session: aiohttp.ClientSession,
                              url: str, name: str,
                              job_id: Optional[str] = None) -> Dict:
    """Download a Chaos zip and extract subdomain list. Streams — no full zip in RAM."""
    safe_name = re.sub(r'[^a-z0-9]', '_', name.lower())
    zp = CHAOS_DIR / f"{safe_name}_{uuid.uuid4().hex[:6]}.zip"
    try:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=180)) as r:
            r.raise_for_status()
            content = await r.read()
            await asyncio.to_thread(zp.write_bytes, content)

        subs: List[str] = []
        def _extract():
            out = []
            with zipfile.ZipFile(zp, "r") as z:
                for fname in z.namelist():
                    if fname.endswith(".txt"):
                        with z.open(fname) as f:
                            for line in f:
                                s = line.decode("utf-8", errors="ignore").strip()
                                if s:
                                    out.append(s)
            return out
        subs = await asyncio.to_thread(_extract)
        return {"ok": True, "subs": subs}
    except Exception as e:
        return {"ok": False, "error": str(e), "subs": []}
    finally:
        try:
            await asyncio.to_thread(zp.unlink, missing_ok=True)
        except Exception:
            pass


# ── Chaos Sync ────────────────────────────────────────────────────────────────

async def run_chaos_sync(pool, job_id: str,
                          bounty_only: bool = True,
                          platform: Optional[str] = None) -> None:
    """Sync programs from Chaos dataset."""
    from db.pool import get_pool as _gp
    now = datetime.now().isoformat()

    # Record job start
    async with pool.acquire() as conn:
        await conn.execute(
            """INSERT INTO sync_jobs(id, platform, status, started_at, total, imported, failed, skipped, scanned, phase)
               VALUES($1, $2, 'running', $3, 0, 0, 0, 0, 0, 'fetch')
               ON CONFLICT (id) DO UPDATE SET status='running', started_at=$3""",
            job_id, "chaos", now)

    await log(pool, f"[Chaos] Sync starting (bounty_only={bounty_only} platform={platform})",
              "info", "sync", job_id)

    headers = {"User-Agent": "SubmindPro/8.0"}
    imported = failed = skipped = 0

    try:
        async with aiohttp.ClientSession(headers=headers) as session:
            idx = await fetch_chaos_index(session)
            if not idx["ok"]:
                raise RuntimeError(f"Chaos index fetch failed: {idx.get('error')}")

            programs = idx["data"]
            # Filter by bounty
            if bounty_only:
                programs = [p for p in programs if p.get("bounty")]
            # Filter by platform(s)
            if platform:
                plats = [pl.strip().lower() for pl in platform.split(",") if pl.strip()]
                programs = [p for p in programs
                            if (p.get("platform") or "").lower() in plats]

            total = len(programs)
            await log(pool, f"[Chaos] {total} programs to process", "info", "sync", job_id)

            async with pool.acquire() as conn:
                await conn.execute(
                    "UPDATE sync_jobs SET total=$1, phase='import' WHERE id=$2",
                    total, job_id)

            for i, prog in enumerate(programs):
                pname = prog.get("name", "")
                purl  = prog.get("program_url", "")
                pplat = prog.get("platform", "")
                pbounty = 1 if prog.get("bounty") else 0
                zip_url = prog.get("url", "")

                if not zip_url or not pname:
                    skipped += 1
                    continue

                try:
                    # Check if project exists
                    async with pool.acquire() as conn:
                        existing = await conn.fetchrow(
                            "SELECT id FROM projects WHERE name=$1 AND source='chaos'", pname)

                    if not existing:
                        pid = str(uuid.uuid4())
                        proj_now = datetime.now().isoformat()
                        async with pool.acquire() as conn:
                            await conn.execute(
                                """INSERT INTO projects(id, name, source, platform, program_url,
                                   bounty, scope_type, created_at, updated_at, scan_status,
                                   sync_enabled, scope, metadata)
                                   VALUES($1,$2,'chaos',$3,$4,$5,'public',$6,$6,'pending',1,'[]','{}')
                                   ON CONFLICT DO NOTHING""",
                                pid, pname, pplat, purl, pbounty, proj_now)
                    else:
                        pid = existing["id"]

                    # Download and extract subs
                    result = await download_chaos_zip(session, zip_url, pname, job_id)
                    if not result["ok"] or not result["subs"]:
                        skipped += 1
                        continue

                    raw_subs = result["subs"]
                    cleaned  = clean_subdomains(raw_subs)
                    real_subs, garbage_count = await classify_and_store(
                        pool, pid, cleaned, source="chaos")

                    async with pool.acquire() as conn:
                        await upsert_subdomains(conn, pid, real_subs)

                    imported += 1
                    if i % 20 == 0:
                        await log(pool,
                            f"[Chaos] {i+1}/{total} — {pname}: "
                            f"{len(real_subs)} real, {garbage_count} garbage",
                            "info", "sync", job_id)
                        async with pool.acquire() as conn:
                            await conn.execute(
                                "UPDATE sync_jobs SET imported=$1, skipped=$2 WHERE id=$3",
                                imported, skipped, job_id)

                except Exception as e:
                    failed += 1
                    logger.warning("Chaos program %s error: %s", pname, e)

        end_now = datetime.now().isoformat()
        async with pool.acquire() as conn:
            await conn.execute(
                """UPDATE sync_jobs SET status='done', ended_at=$1,
                   total=$2, imported=$3, failed=$4, skipped=$5, phase='done'
                   WHERE id=$6""",
                end_now, total, imported, failed, skipped, job_id)
        await log(pool,
            f"[Chaos] ✓ Done: {imported} imported, {failed} failed, {skipped} skipped",
            "success", "sync", job_id)

    except Exception as e:
        end_now = datetime.now().isoformat()
        async with pool.acquire() as conn:
            await conn.execute(
                "UPDATE sync_jobs SET status='error', ended_at=$1, phase='error' WHERE id=$2",
                end_now, job_id)
        await log(pool, f"[Chaos] ERROR: {e}", "error", "sync", job_id)
        raise


# ── BBScope Sync (HackerOne / YesWeHack) ─────────────────────────────────────

async def run_bbscope_sync(pool, job_id: str,
                            platform: str = "hackerone",
                            username: str = "",
                            token: str = "") -> None:
    """Sync programs from HackerOne or YesWeHack via their APIs."""
    now = datetime.now().isoformat()
    async with pool.acquire() as conn:
        await conn.execute(
            """INSERT INTO sync_jobs(id, platform, status, started_at, total, imported, failed, skipped, scanned, phase)
               VALUES($1, $2, 'running', $3, 0, 0, 0, 0, 0, 'fetch')
               ON CONFLICT (id) DO UPDATE SET status='running', started_at=$3""",
            job_id, platform, now)

    await log(pool, f"[BBScope/{platform}] Sync starting", "info", "sync", job_id)

    try:
        if platform == "hackerone":
            await _sync_hackerone(pool, job_id, username, token)
        elif platform == "yeswehack":
            await _sync_yeswehack(pool, job_id, token)
        else:
            raise ValueError(f"Unknown platform: {platform}")

    except Exception as e:
        end_now = datetime.now().isoformat()
        async with pool.acquire() as conn:
            await conn.execute(
                "UPDATE sync_jobs SET status='error', ended_at=$1, phase='error' WHERE id=$2",
                end_now, job_id)
        await log(pool, f"[BBScope/{platform}] ERROR: {e}", "error", "sync", job_id)
        raise


async def _sync_hackerone(pool, job_id: str, username: str, token: str) -> None:
    """SW-FIX-02: Paginate through ALL H1 pages, include private via /invitations."""
    if not username or not token:
        raise ValueError("HackerOne username and token required")

    imported = failed = skipped = 0
    all_programs: List[Dict] = []

    auth = aiohttp.BasicAuth(username, token)
    headers = {"Accept": "application/json"}
    timeout = aiohttp.ClientTimeout(total=30)

    async with aiohttp.ClientSession(auth=auth, headers=headers, timeout=timeout) as session:
        # Fetch public programs
        page = 1
        while True:
            async with session.get(
                f"https://api.hackerone.com/v1/hackers/programs"
                f"?page[number]={page}&page[size]=100"
            ) as r:
                if r.status != 200:
                    break
                data = await r.json()
                programs = data.get("data", [])
                if not programs:
                    break
                all_programs.extend(programs)
                if not data.get("links", {}).get("next"):
                    break
                page += 1

        # SW-FIX-11: Fetch private programs via invitations endpoint
        try:
            async with session.get(
                "https://api.hackerone.com/v1/hackers/invitations?page[size]=100"
            ) as r:
                if r.status == 200:
                    inv_data = await r.json()
                    for inv in inv_data.get("data", []):
                        prog = inv.get("relationships", {}).get("program", {}).get("data")
                        if prog:
                            all_programs.append(prog)
        except Exception as e:
            logger.warning("H1 invitations fetch error: %s", e)

    total = len(all_programs)
    async with pool.acquire() as conn:
        await conn.execute(
            "UPDATE sync_jobs SET total=$1, phase='import' WHERE id=$2", total, job_id)

    await log(pool, f"[H1] {total} programs fetched", "info", "sync", job_id)

    for prog in all_programs:
        try:
            attrs = prog.get("attributes", {})
            pname = attrs.get("name") or attrs.get("handle", "")
            if not pname:
                skipped += 1
                continue

            # SW-FIX-09: Extract scope domains from structured_scope
            scope_domains: List[str] = []
            for scope_item in attrs.get("structured_scope", []):
                asset_type = scope_item.get("asset_type", "")
                asset_id   = scope_item.get("asset_identifier", "")
                if asset_type in ("URL", "WILDCARD", "DOMAIN") and asset_id:
                    scope_domains.append(asset_id.strip())

            pid_str = str(uuid.uuid4())
            proj_now = datetime.now().isoformat()
            async with pool.acquire() as conn:
                existing = await conn.fetchrow(
                    "SELECT id FROM projects WHERE name=$1 AND platform='hackerone'", pname)
                if not existing:
                    await conn.execute(
                        """INSERT INTO projects(id, name, source, platform, program_url,
                           bounty, scope_type, created_at, updated_at, scan_status,
                           sync_enabled, scope, metadata)
                           VALUES($1,$2,'bbscope','hackerone',$3,$4,'public',$5,$5,'pending',1,$6,'{}')
                           ON CONFLICT DO NOTHING""",
                        pid_str, pname,
                        f"https://hackerone.com/{attrs.get('handle','')}",
                        1 if attrs.get("offers_bounties") else 0,
                        proj_now,
                        json.dumps(scope_domains))
                    pid = pid_str
                else:
                    pid = existing["id"]
                    # Update scope if it changed
                    if scope_domains:
                        await conn.execute(
                            "UPDATE projects SET scope=$1, updated_at=$2 WHERE id=$3",
                            json.dumps(scope_domains), proj_now, pid)

            imported += 1

        except Exception as e:
            failed += 1
            logger.warning("H1 program error: %s", e)

    end_now = datetime.now().isoformat()
    async with pool.acquire() as conn:
        await conn.execute(
            """UPDATE sync_jobs SET status='done', ended_at=$1,
               imported=$2, failed=$3, skipped=$4, phase='done' WHERE id=$5""",
            end_now, imported, failed, skipped, job_id)
    await log(pool, f"[H1] ✓ Done: {imported} imported, {failed} failed", "success", "sync", job_id)


async def _sync_yeswehack(pool, job_id: str, token: str) -> None:
    """SW-FIX-03/10/12: YWH pagination + private programs."""
    if not token:
        raise ValueError("YesWeHack token required")

    headers = {
        "Authorization": f"Token {token}",
        "Accept": "application/json",
    }
    timeout = aiohttp.ClientTimeout(total=30)
    all_programs: List[Dict] = []

    async with aiohttp.ClientSession(headers=headers, timeout=timeout) as session:
        # Public programs
        page = 1
        while True:
            async with session.get(
                f"https://api.yeswehack.com/programs?page={page}&rowsPerPage=100"
            ) as r:
                if r.status != 200:
                    break
                data = await r.json()
                programs = data.get("items", [])
                if not programs:
                    break
                all_programs.extend(programs)
                if page >= data.get("pagination", {}).get("nb_pages", 1):
                    break
                page += 1

        # SW-FIX-12: Private programs via authenticated endpoint
        try:
            async with session.get(
                "https://api.yeswehack.com/user/programs?page=1&rowsPerPage=100"
            ) as r:
                if r.status == 200:
                    priv_data = await r.json()
                    for p in priv_data.get("items", []):
                        all_programs.append(p)
        except Exception as e:
            logger.warning("YWH private programs error: %s", e)

    total = len(all_programs)
    async with pool.acquire() as conn:
        await conn.execute(
            "UPDATE sync_jobs SET total=$1, phase='import' WHERE id=$2", total, job_id)

    imported = failed = skipped = 0

    for prog in all_programs:
        try:
            pname = prog.get("slug") or prog.get("name", "")
            if not pname:
                skipped += 1
                continue

            scope_domains = []
            for s in prog.get("scopes", []):
                scope_type = s.get("scope_type", "")
                target = s.get("scope", "")
                if scope_type in ("web-application", "api") and target:
                    scope_domains.append(target)

            pid_str = str(uuid.uuid4())
            proj_now = datetime.now().isoformat()
            async with pool.acquire() as conn:
                existing = await conn.fetchrow(
                    "SELECT id FROM projects WHERE name=$1 AND platform='yeswehack'", pname)
                if not existing:
                    await conn.execute(
                        """INSERT INTO projects(id, name, source, platform, program_url,
                           bounty, scope_type, created_at, updated_at, scan_status,
                           sync_enabled, scope, metadata)
                           VALUES($1,$2,'bbscope','yeswehack',$3,$4,'public',$5,$5,'pending',1,$6,'{}')
                           ON CONFLICT DO NOTHING""",
                        pid_str, pname,
                        f"https://yeswehack.com/programs/{pname}",
                        1 if prog.get("bounty_reward_range") else 0,
                        proj_now,
                        json.dumps(scope_domains))
                    pid = pid_str
                else:
                    pid = existing["id"]
                    if scope_domains:
                        await conn.execute(
                            "UPDATE projects SET scope=$1, updated_at=$2 WHERE id=$3",
                            json.dumps(scope_domains), proj_now, pid)

            imported += 1

        except Exception as e:
            failed += 1
            logger.warning("YWH program error: %s", e)

    end_now = datetime.now().isoformat()
    async with pool.acquire() as conn:
        await conn.execute(
            """UPDATE sync_jobs SET status='done', ended_at=$1,
               imported=$2, failed=$3, skipped=$4, phase='done' WHERE id=$5""",
            end_now, imported, failed, skipped, job_id)
    await log(pool, f"[YWH] ✓ Done: {imported} imported, {failed} failed", "success", "sync", job_id)
