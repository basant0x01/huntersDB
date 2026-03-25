"""
queue/redis_task_queue.py — Redis-backed priority task_queue.

Queue structure:
  ZSET  submind:queue:scan       → members = JSON job blobs, score = priority
  HASH  submind:job_status       → job_id → JSON status
  LIST  submind:dlq              → dead-letter queue (failed after max retries)

Priority scores (lower = higher priority):
  0 = new_sub (fastest, first)
  1 = sweep
  2 = monitor
  3 = rescan
"""
import json
import asyncio
import logging
from datetime import datetime
from typing import Optional, Dict, Any
import redis.asyncio as aioredis

from config.settings import (
    REDIS_URL, QUEUE_SCAN, QUEUE_STATUS, DLQ_KEY,
    MAX_QUEUE_SIZE, JOB_RETRY_MAX, JOB_RETRY_DELAY_SECS
)

logger = logging.getLogger("task_queue.redis")

_redis_client: Optional[aioredis.Redis] = None
# BUG-06 FIX: asyncio.Lock() created lazily, not at module import time.
# Creating asyncio primitives at module level raises DeprecationWarning in
# Python 3.10+ and RuntimeError in 3.12+ when no event loop exists yet.
_redis_lock: Optional[asyncio.Lock] = None


def _get_redis_lock() -> asyncio.Lock:
    global _redis_lock
    if _redis_lock is None:
        _redis_lock = asyncio.Lock()
    return _redis_lock


async def get_redis() -> aioredis.Redis:
    global _redis_client
    if _redis_client is not None:
        return _redis_client
    async with _get_redis_lock():
        if _redis_client is None:
            _redis_client = aioredis.from_url(
                REDIS_URL,
                encoding="utf-8",
                decode_responses=True,
                max_connections=20,
            )
    return _redis_client


async def close_redis() -> None:
    global _redis_client
    if _redis_client is not None:
        await _redis_client.aclose()
        _redis_client = None


# ── Enqueue ────────────────────────────────────────────────────────────────────

async def enqueue(
    job_type: str,
    project_id: Optional[str],
    priority: int = 1,
    payload: Optional[Dict] = None,
    job_id: Optional[str] = None,
) -> Dict:
    """
    Add a job to the scan task_queue.
    Returns {"ok": True, "job_id": ...} or {"ok": False, "error": ...}.

    Backpressure: rejects if queue length >= MAX_QUEUE_SIZE.
    """
    import uuid
    r = await get_redis()

    qsize = await r.zcard(QUEUE_SCAN)
    if qsize >= MAX_QUEUE_SIZE:
        return {"ok": False, "error": f"Queue full ({qsize}/{MAX_QUEUE_SIZE}). Retry later."}

    jid = job_id or str(uuid.uuid4())
    now = datetime.now().isoformat()
    job = {
        "job_id":     jid,
        "job_type":   job_type,
        "project_id": project_id,
        "priority":   priority,
        "created_at": now,
        "retries":    0,
        "payload":    payload or {},
    }
    await r.zadd(QUEUE_SCAN, {json.dumps(job): priority})
    await set_job_status(jid, "queued", meta={"queued_at": now})
    logger.debug("Enqueued job %s type=%s proj=%s prio=%d",
                 jid, job_type, project_id, priority)
    return {"ok": True, "job_id": jid}


# ── Dequeue ────────────────────────────────────────────────────────────────────

async def dequeue(timeout: float = 1.0) -> Optional[Dict]:
    """
    Pop the highest-priority job (lowest score) from the task_queue.
    Returns None if queue is empty or all jobs are future-scheduled.

    BUG-08 NOTE: The zrange→zpopmin TOCTOU race is acceptable in single-worker
    architecture. For multi-worker, replace with a Lua script. Left as-is per
    current single-worker design.
    """
    import time as _time
    r = await get_redis()
    items = await r.zrange(QUEUE_SCAN, 0, 0, withscores=True)
    if not items:
        return None
    raw_peek, score = items[0]
    # Priority jobs use scores 0-3; retry jobs use unix timestamp (>1e9)
    if score > 1e9 and score > _time.time():
        return None  # retry not yet due
    popped = await r.zpopmin(QUEUE_SCAN, count=1)
    if not popped:
        return None
    raw, _score = popped[0]
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        logger.error("Corrupt job blob discarded from queue: %r", raw[:200])
        return None


# ── Retry / DLQ ───────────────────────────────────────────────────────────────

async def requeue_with_retry(job: Dict, error: str) -> bool:
    """
    Increment retry counter and re-enqueue with delay.
    Returns True if re-queued, False if sent to DLQ.
    """
    r = await get_redis()
    job["retries"] = job.get("retries", 0) + 1
    job["last_error"] = error
    job["last_retry_at"] = datetime.now().isoformat()

    if job["retries"] >= JOB_RETRY_MAX:
        await r.rpush(DLQ_KEY, json.dumps(job))
        await set_job_status(job["job_id"], "dead_letter",
                             meta={"error": error, "retries": job["retries"]})
        logger.error("Job %s sent to DLQ after %d retries: %s",
                     job["job_id"], job["retries"], error)
        return False

    import time as _time
    delay_secs = JOB_RETRY_DELAY_SECS * job["retries"]
    retry_score = _time.time() + delay_secs
    await r.zadd(QUEUE_SCAN, {json.dumps(job): retry_score})
    await set_job_status(job["job_id"], "retrying",
                         meta={"retries": job["retries"], "error": error})
    logger.warning("Job %s retry %d/%d (error: %s)",
                   job["job_id"], job["retries"], JOB_RETRY_MAX, error)
    return True


# ── Job Status ────────────────────────────────────────────────────────────────

async def set_job_status(job_id: str, status: str,
                          meta: Optional[Dict] = None) -> None:
    r = await get_redis()
    existing_raw = await r.hget(QUEUE_STATUS, job_id)
    existing = json.loads(existing_raw) if existing_raw else {}
    existing.update({"status": status, "updated_at": datetime.now().isoformat()})
    if meta:
        existing.update(meta)
    await r.hset(QUEUE_STATUS, job_id, json.dumps(existing))
    # BUG-07 FIX: expire only on creation so we don't reset the 7-day clock on
    # every status update (which would expire the entire hash from the last update,
    # not from creation). Individual job entries are implicitly removed when the
    # hash eventually expires. For per-job TTLs, store as separate string keys.
    if status == "queued":
        await r.expire(QUEUE_STATUS, 7 * 86400)


async def get_job_status(job_id: str) -> Optional[Dict]:
    r = await get_redis()
    raw = await r.hget(QUEUE_STATUS, job_id)
    return json.loads(raw) if raw else None


async def get_queue_depth() -> Dict:
    r = await get_redis()
    return {
        "scan_queue": await r.zcard(QUEUE_SCAN),
        "dlq":        await r.llen(DLQ_KEY),
    }


async def flush_queue() -> None:
    """Emergency: clear the scan task_queue."""
    r = await get_redis()
    await r.delete(QUEUE_SCAN)
    logger.warning("Scan queue flushed by admin")


# ── Scan Progress ─────────────────────────────────────────────────────────────

PROGRESS_KEY = "submind:scan_progress"


async def set_scan_progress(project_id: str, data: Dict) -> None:
    r = await get_redis()
    await r.hset(PROGRESS_KEY, str(project_id), json.dumps(data))


async def get_scan_progress(project_id: Optional[str] = None) -> Any:
    r = await get_redis()
    if project_id:
        raw = await r.hget(PROGRESS_KEY, str(project_id))
        return json.loads(raw) if raw else None
    all_raw = await r.hgetall(PROGRESS_KEY)
    return {k: json.loads(v) for k, v in all_raw.items()}


async def clear_scan_progress(project_id: str) -> None:
    r = await get_redis()
    await r.hdel(PROGRESS_KEY, str(project_id))
