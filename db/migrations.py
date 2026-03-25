"""
db/migrations.py — PostgreSQL schema initialization.

Converts the original SQLite schema to PostgreSQL.
All column names and logic preserved exactly.
Run once on startup via: await run_migrations()
"""
import logging
from db.pool import acquire

logger = logging.getLogger("db.migrations")

SCHEMA_SQL = """
-- ── Projects ────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS projects (
    id                  TEXT PRIMARY KEY,
    name                TEXT NOT NULL,
    description         TEXT DEFAULT '',
    source              TEXT DEFAULT 'manual',
    platform            TEXT DEFAULT '',
    program_url         TEXT DEFAULT '',
    scope_type          TEXT DEFAULT 'public',
    bounty              INTEGER DEFAULT 0,
    is_new              INTEGER DEFAULT 0,
    count               INTEGER DEFAULT 0,
    change              INTEGER DEFAULT 0,
    last_updated        TEXT DEFAULT '',
    created_at          TEXT NOT NULL,
    updated_at          TEXT NOT NULL,
    scan_status         TEXT DEFAULT 'pending',
    sync_enabled        INTEGER DEFAULT 1,
    sync_cycle          INTEGER DEFAULT 0,
    metadata            TEXT DEFAULT '{}',
    last_synced         TEXT,
    phase_updated_at    TEXT,
    phase_job_id        TEXT,
    phase_a_done_at     TEXT,
    phase_b_done_at     TEXT,
    phase_c_done_at     TEXT,
    phase_d_done_at     TEXT,
    scope               TEXT DEFAULT '[]',
    notes               TEXT DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_proj_scan_status ON projects(scan_status);
CREATE INDEX IF NOT EXISTS idx_proj_source_status ON projects(source, scan_status);
CREATE INDEX IF NOT EXISTS idx_proj_updated ON projects(updated_at DESC);

-- ── Subdomains ─────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS subdomains (
    id                  BIGSERIAL PRIMARY KEY,
    project_id          TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    subdomain           TEXT NOT NULL,
    url                 TEXT DEFAULT '',
    status_code         INTEGER DEFAULT 0,
    title               TEXT DEFAULT '',
    tech                TEXT DEFAULT '',
    content_length      INTEGER DEFAULT 0,
    ip                  TEXT DEFAULT '',
    cdn_name            TEXT DEFAULT '',
    cdn_type            TEXT DEFAULT '',
    cname               TEXT DEFAULT '',
    webserver           TEXT DEFAULT '',
    response_time       TEXT DEFAULT '',
    body_hash           TEXT DEFAULT '',
    favicon_hash        TEXT DEFAULT '',
    tls_host            TEXT DEFAULT '',
    tls_cn              TEXT DEFAULT '',
    tls_issuer          TEXT DEFAULT '',
    tls_sans            TEXT DEFAULT '',
    port                INTEGER DEFAULT 0,
    scheme              TEXT DEFAULT '',
    path                TEXT DEFAULT '',
    is_alive            INTEGER DEFAULT 0,
    is_new              INTEGER DEFAULT 1,
    failed              INTEGER DEFAULT 0,
    fail_count          INTEGER DEFAULT 0,
    lifecycle           TEXT DEFAULT 'new',
    in_scope            INTEGER DEFAULT 1,
    first_seen          TEXT,
    last_seen           TEXT,
    last_alive_check    TEXT,
    last_deep_scan      TEXT,
    last_nuclei_scan    TEXT,
    nuclei_scanned_at   TEXT,
    discovery_cycle     INTEGER DEFAULT 0,
    UNIQUE(project_id, subdomain)
);

CREATE INDEX IF NOT EXISTS idx_sub_project ON subdomains(project_id);
CREATE INDEX IF NOT EXISTS idx_sub_is_alive  ON subdomains(is_alive);
CREATE INDEX IF NOT EXISTS idx_sub_lifecycle ON subdomains(lifecycle);
CREATE INDEX IF NOT EXISTS idx_sub_failcount ON subdomains(fail_count);
CREATE INDEX IF NOT EXISTS idx_sub_inscope   ON subdomains(in_scope);
CREATE INDEX IF NOT EXISTS idx_sub_proj_alive ON subdomains(project_id, is_alive);
CREATE INDEX IF NOT EXISTS idx_sub_proj_scope ON subdomains(project_id, in_scope, lifecycle);
CREATE INDEX IF NOT EXISTS idx_sub_proj_url_alive ON subdomains(project_id, is_alive, url);
CREATE INDEX IF NOT EXISTS idx_sub_proj_deepscan ON subdomains(project_id, is_alive, last_deep_scan);
CREATE INDEX IF NOT EXISTS idx_sub_alive_check ON subdomains(project_id, last_alive_check);
CREATE INDEX IF NOT EXISTS idx_sub_proj_lifecycle ON subdomains(project_id, lifecycle, in_scope);
CREATE INDEX IF NOT EXISTS idx_sub_lastdeep ON subdomains(project_id, is_alive, last_deep_scan);

-- ── Garbage Subdomains ─────────────────────────────────────────────────────
-- Subdomains classified as garbage by the AI classifier.
-- These are excluded from all scans. Users can promote them to real.
CREATE TABLE IF NOT EXISTS garbage_subdomains (
    id              BIGSERIAL PRIMARY KEY,
    project_id      TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    subdomain       TEXT NOT NULL,
    score           REAL DEFAULT 0,
    reason          TEXT DEFAULT '',
    promoted        INTEGER DEFAULT 0,   -- 1 = user promoted to real
    promoted_at     TEXT,
    source          TEXT DEFAULT '',     -- 'chaos','hackerone','yeswehack','manual'
    created_at      TEXT NOT NULL,
    UNIQUE(project_id, subdomain)
);

CREATE INDEX IF NOT EXISTS idx_garbage_proj ON garbage_subdomains(project_id);
CREATE INDEX IF NOT EXISTS idx_garbage_promoted ON garbage_subdomains(project_id, promoted);

-- ── Vulnerabilities ────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS vulnerabilities (
    id              BIGSERIAL PRIMARY KEY,
    project_id      TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    url             TEXT DEFAULT '',
    template_id     TEXT DEFAULT '',
    name            TEXT DEFAULT '',
    severity        TEXT DEFAULT 'unknown',
    type            TEXT DEFAULT '',
    description     TEXT DEFAULT '',
    matched_at      TEXT DEFAULT '',
    curl_cmd        TEXT DEFAULT '',
    created_at      TEXT NOT NULL,
    review_status   TEXT DEFAULT 'pending_review',
    nuclei_scope    TEXT DEFAULT 'auto',
    notes           TEXT DEFAULT '',
    UNIQUE(project_id, template_id, matched_at)
);

CREATE INDEX IF NOT EXISTS idx_vuln_proj_sev ON vulnerabilities(project_id, severity);
CREATE INDEX IF NOT EXISTS idx_vuln_review ON vulnerabilities(review_status, created_at);
CREATE INDEX IF NOT EXISTS idx_vuln_template ON vulnerabilities(template_id, matched_at);

-- ── Alerts ─────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS alerts (
    id          BIGSERIAL PRIMARY KEY,
    alert_type  TEXT DEFAULT '',
    project_id  TEXT REFERENCES projects(id) ON DELETE CASCADE,
    subdomain   TEXT DEFAULT '',
    vuln_id     BIGINT REFERENCES vulnerabilities(id) ON DELETE SET NULL,
    title       TEXT DEFAULT '',
    detail      TEXT DEFAULT '',
    severity    TEXT DEFAULT 'info',
    seen        INTEGER DEFAULT 0,
    created_at  TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_alerts_unseen ON alerts(seen, created_at);
CREATE INDEX IF NOT EXISTS idx_alerts_proj ON alerts(project_id, created_at DESC);

-- ── System Logs ────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS system_logs (
    id          BIGSERIAL PRIMARY KEY,
    timestamp   TEXT NOT NULL,
    level       TEXT DEFAULT 'info',
    category    TEXT DEFAULT 'system',
    job_id      TEXT,
    message     TEXT DEFAULT '',
    detail      TEXT DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_log_ts ON system_logs(timestamp DESC);

-- ── Sync Jobs ──────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS sync_jobs (
    id          TEXT PRIMARY KEY,
    platform    TEXT DEFAULT '',
    status      TEXT DEFAULT 'running',
    started_at  TEXT NOT NULL,
    ended_at    TEXT,
    total       INTEGER DEFAULT 0,
    imported    INTEGER DEFAULT 0,
    failed      INTEGER DEFAULT 0,
    skipped     INTEGER DEFAULT 0,
    scanned     INTEGER DEFAULT 0,
    phase       TEXT DEFAULT ''
);

-- ── API Keys ───────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS api_keys (
    id          BIGSERIAL PRIMARY KEY,
    key_hash    TEXT UNIQUE NOT NULL,
    name        TEXT DEFAULT '',
    created_at  TEXT NOT NULL,
    last_used   TEXT
);
"""


async def run_migrations() -> None:
    """Apply schema to the database. Idempotent (IF NOT EXISTS everywhere)."""
    logger.info("Running database migrations...")
    async with acquire() as conn:
        async with conn.transaction():
            await conn.execute(SCHEMA_SQL)
    logger.info("Migrations complete")


async def startup_recovery(pool) -> None:
    """
    Called once on worker startup.

    AUTO-RESUME: Every project interrupted mid-scan is automatically
    re-enqueued to continue from the EXACT phase stored in the DB.
    """
    import json
    from datetime import datetime

    now = datetime.now().isoformat()
    logger.info("startup_recovery: starting...")

    try:
        async with pool.acquire() as conn:
            async with conn.transaction():
                legacy_map = {
                    "scanning":        "phase_a",
                    "recon_done":      "phase_c_done",
                    "nuclei_scanning": "phase_c_done",
                }
                for old_val, new_val in legacy_map.items():
                    rows = await conn.fetch(
                        "SELECT id, name FROM projects WHERE scan_status=$1", old_val)
                    if rows:
                        ids = [r["id"] for r in rows]
                        await conn.execute(
                            "UPDATE projects SET scan_status=$1 WHERE id = ANY($2::text[])",
                            new_val, ids)
                        logger.info("Recovery: %d projects %s→%s", len(rows), old_val, new_val)

                mid_d = await conn.fetch(
                    "SELECT id FROM projects WHERE scan_status='phase_d'")
                if mid_d:
                    ids = [r["id"] for r in mid_d]
                    await conn.execute(
                        "UPDATE projects SET scan_status='phase_c_done'"
                        " WHERE id = ANY($1::text[])", ids)
                    logger.info("Recovery: %d mid-nuclei projects → phase_c_done", len(mid_d))

                await conn.execute(
                    "UPDATE sync_jobs SET status='interrupted', ended_at=$1"
                    " WHERE status='running'", now)
    except Exception as e:
        logger.error("Recovery step 1 failed: %s", e)

    try:
        from task_queue.redis_queue import get_redis as _get_redis
        _r = await _get_redis()
        await _r.delete("submind:scan_progress")
        logger.info("Recovery: cleared stale Redis scan_progress")
    except Exception as e:
        logger.warning("Recovery: could not clear scan_progress: %s", e)

    try:
        from task_queue.redis_queue import enqueue as _enqueue

        async with pool.acquire() as conn:
            mid_scan = await conn.fetch(
                """SELECT id, name, scan_status, scope
                   FROM projects
                   WHERE scan_status IN ('phase_a','phase_a_done','phase_b_done')
                   ORDER BY updated_at DESC NULLS LAST""")

            pending_with_subs = await conn.fetch(
                """SELECT p.id, p.name, p.scan_status, p.scope
                   FROM projects p
                   WHERE p.scan_status = 'pending'
                     AND EXISTS (
                       SELECT 1 FROM subdomains s
                       WHERE s.project_id = p.id LIMIT 1
                     )
                   ORDER BY p.updated_at DESC NULLS LAST""")

        interrupted = list(mid_scan) + list(pending_with_subs)

        if not interrupted:
            logger.info("Recovery: no interrupted scans found")
        else:
            logger.info("Recovery: %d interrupted project(s) to resume", len(interrupted))

            for row in interrupted:
                try:
                    pid   = row["id"]
                    pname = row["name"]
                    phase = row["scan_status"]

                    try:
                        scope = json.loads(row["scope"] or "[]")
                    except Exception:
                        scope = []

                    async with pool.acquire() as conn2:
                        sub_count = await conn2.fetchval(
                            "SELECT COUNT(*) FROM subdomains WHERE project_id=$1", pid)
                        alive_count = await conn2.fetchval(
                            "SELECT COUNT(*) FROM subdomains"
                            " WHERE project_id=$1 AND is_alive=1", pid)

                    run_subfinder = (sub_count == 0 and bool(scope))

                    result = await _enqueue(
                        job_type="scan",
                        project_id=pid,
                        priority=2,
                        payload={
                            "project_name":  pname,
                            "run_subfinder": run_subfinder,
                            "scope":         scope,
                            "resume_from":   phase,
                            "auto_resumed":  True,
                        },
                    )
                    logger.info(
                        "Recovery: queued %s (phase=%s subs=%d alive=%d"
                        " subfinder=%s) job=%s",
                        pname, phase, sub_count, alive_count,
                        run_subfinder, result.get("job_id", "?"),
                    )
                except Exception as proj_err:
                    logger.error("Recovery: failed to queue %s: %s",
                                 row.get("name", "?"), proj_err)

    except Exception as e:
        logger.error("Recovery step 3 (auto-resume enqueue) failed: %s", e)

    logger.info("startup_recovery: complete")
