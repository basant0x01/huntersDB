"""
utils/log.py — Async logging system.
"""
import asyncio
import json
import logging
import os
from collections import deque
from datetime import datetime
from pathlib import Path
from typing import Optional, Set

import redis.asyncio as aioredis

from config.settings import (
    LOGS_DIR, LOG_BUFFER_MAX, LOG_DB_BATCH,
    LOG_MAX_MSG_LEN, LOG_MAX_DETAIL, REDIS_URL,
)

logger = logging.getLogger("utils.log")

_live_logs: deque = deque(maxlen=LOG_BUFFER_MAX)
_live_log_id = 0
_log_buffer: list = []
# BUG-20 FIX: asyncio.Lock() created lazily, not at module import time.
_log_lock: Optional[asyncio.Lock] = None

# BUG-10 FIX: keep strong references to background tasks so they are not
# garbage-collected before completing (Python docs warn that tasks with no
# references can be silently discarded mid-execution).
_background_tasks: Set[asyncio.Task] = set()

LIVE_LOG_REDIS_KEY = "submind:live_logs"
LIVE_LOG_MAX_REDIS = 5000


def _get_log_lock() -> asyncio.Lock:
    global _log_lock
    if _log_lock is None:
        _log_lock = asyncio.Lock()
    return _log_lock


async def log(pool_or_none,
              msg: str,
              level: str = "info",
              category: str = "system",
              job_id: Optional[str] = None,
              detail: Optional[str] = None) -> None:
    """
    Async replacement for original log().
    Appends to in-process deque + batched DB writes.
    """
    global _live_log_id

    if msg and len(msg) > LOG_MAX_MSG_LEN:
        msg = msg[:LOG_MAX_MSG_LEN - 3] + "..."
    if detail and len(str(detail)) > LOG_MAX_DETAIL:
        detail = str(detail)[:LOG_MAX_DETAIL - 3] + "..."

    ts = datetime.now().isoformat()
    async with _get_log_lock():
        _live_log_id += 1
        entry = {
            "id": _live_log_id, "timestamp": ts,
            "level": level, "category": category,
            "job_id": job_id, "message": msg, "detail": detail or "",
        }
        _live_logs.append(entry)
        _log_buffer.append((ts, level, category, job_id, msg, detail or ""))
        should_flush = len(_log_buffer) >= LOG_DB_BATCH

    if level in ("warning", "error", "success"):
        try:
            lf = LOGS_DIR / f"submind_{datetime.now().strftime('%Y%m%d')}.log"
            def _write():
                with open(lf, "a") as f:
                    f.write(f"[{ts}] [{level.upper():7}] [{category:8}] {msg}\n")
            # BUG-10 FIX: keep reference to task so it is not GC'd mid-execution
            task = asyncio.create_task(asyncio.to_thread(_write))
            _background_tasks.add(task)
            task.add_done_callback(_background_tasks.discard)
        except Exception as _e:
            logger.debug("Log file write setup error: %s", _e)

    py_level = {"info": logging.INFO, "warning": logging.WARNING,
                "error": logging.ERROR, "success": logging.INFO,
                "debug": logging.DEBUG}.get(level, logging.INFO)
    logging.getLogger(f"submind.{category}").log(py_level, "[%s] %s", category, msg)

    if should_flush and pool_or_none is not None:
        # BUG-10 FIX: keep reference so task is not GC'd
        task = asyncio.create_task(_flush_batch_to_db(pool_or_none))
        _background_tasks.add(task)
        task.add_done_callback(_background_tasks.discard)


async def _flush_batch_to_db(pool) -> None:
    async with _get_log_lock():
        if not _log_buffer:
            return
        batch = list(_log_buffer)
        _log_buffer.clear()

    try:
        async with pool.acquire() as conn:
            await conn.executemany(
                "INSERT INTO system_logs(timestamp,level,category,job_id,message,detail) VALUES($1,$2,$3,$4,$5,$6)",
                batch)
    except Exception as e:
        logger.error("Log flush error: %s", e)


async def flush_log_buffer(pool) -> None:
    """Force-flush all pending log entries. Call on shutdown."""
    async with _get_log_lock():
        batch = list(_log_buffer)
        _log_buffer.clear()
    if batch:
        try:
            async with pool.acquire() as conn:
                await conn.executemany(
                    "INSERT INTO system_logs(timestamp,level,category,job_id,message,detail) VALUES($1,$2,$3,$4,$5,$6)",
                    batch)
        except Exception as e:
            logger.error("Final log flush error: %s", e)


def get_live_logs(since_id: int = 0):
    return [e for e in _live_logs if e["id"] > since_id]


def get_live_log_cursor() -> int:
    return _live_log_id


def clear_live_logs() -> None:
    global _live_log_id
    _live_logs.clear()
    _live_log_id = 0
