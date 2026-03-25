"""
db/pool.py — asyncpg connection pool.

Replaces SQLite + thread-local connections with PostgreSQL + asyncpg pool.
No blocking DB calls anywhere in API or worker code.
"""
import asyncpg
import asyncio
import logging
from typing import Optional
from config.settings import DATABASE_URL, DB_POOL_MIN, DB_POOL_MAX

logger = logging.getLogger("db.pool")

_pool: Optional[asyncpg.Pool] = None
# BUG-02 FIX: asyncio.Lock() created lazily inside a coroutine, not at module
# import time. Creating asyncio primitives at module level raises DeprecationWarning
# in Python 3.10+ and RuntimeError in 3.12+ when no event loop exists yet.
_pool_lock: Optional[asyncio.Lock] = None


def _get_pool_lock() -> asyncio.Lock:
    global _pool_lock
    if _pool_lock is None:
        _pool_lock = asyncio.Lock()
    return _pool_lock


async def get_pool() -> asyncpg.Pool:
    """Return the global connection pool, creating it on first call."""
    global _pool
    if _pool is not None:
        return _pool
    async with _get_pool_lock():
        if _pool is not None:
            return _pool
        logger.info("Creating asyncpg connection pool (min=%d, max=%d)", DB_POOL_MIN, DB_POOL_MAX)
        _pool = await asyncpg.create_pool(
            dsn=DATABASE_URL,
            min_size=DB_POOL_MIN,
            max_size=DB_POOL_MAX,
            command_timeout=60,
            server_settings={"application_name": "submind_pro"},
        )
        logger.info("asyncpg pool ready")
    return _pool


async def close_pool() -> None:
    """Gracefully close the pool on shutdown."""
    global _pool
    if _pool is not None:
        await _pool.close()
        _pool = None
        logger.info("asyncpg pool closed")


# ── Convenience context manager ────────────────────────────────────────────────
from contextlib import asynccontextmanager

@asynccontextmanager
async def acquire():
    """Acquire a connection from the pool. Auto-releases on exit."""
    pool = await get_pool()
    async with pool.acquire() as conn:
        yield conn
