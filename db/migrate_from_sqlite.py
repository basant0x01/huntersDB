"""
db/migrate_from_sqlite.py — One-time migration from SQLite to PostgreSQL.

Usage:
  python -m db.migrate_from_sqlite --sqlite ~/.submind-pro/submind.db

Migrates:
  - projects
  - subdomains (streamed in batches to avoid OOM)
  - vulnerabilities
  - alerts
  - system_logs (last 10k entries only)
  - sync_jobs

Safe to re-run (ON CONFLICT DO NOTHING everywhere).
"""
import argparse
import asyncio
import json
import logging
import sqlite3
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from db.migrations import run_migrations
from db.pool import get_pool, close_pool

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger("migrate")

BATCH = 2000  # rows per insert batch


async def migrate(sqlite_path: str) -> None:
    logger.info("Connecting to SQLite: %s", sqlite_path)
    src = sqlite3.connect(sqlite_path, timeout=30)
    src.row_factory = sqlite3.Row

    pool = await get_pool()
    await run_migrations()

    # ── Projects ─────────────────────────────────────────────────────────────
    logger.info("Migrating projects...")
    rows = src.execute("SELECT * FROM projects").fetchall()
    async with pool.acquire() as conn:
        await conn.executemany(
            """INSERT INTO projects(id,name,description,source,platform,program_url,
               scope_type,bounty,is_new,count,change,last_updated,created_at,updated_at,
               scan_status,sync_enabled,sync_cycle,metadata,last_synced,
               phase_updated_at,phase_job_id,phase_a_done_at,phase_b_done_at,
               phase_c_done_at,phase_d_done_at,scope,notes)
               VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25,$26,$27)
               ON CONFLICT (id) DO NOTHING""",
            [
                (
                    r["id"], r["name"], r.get("description",""),
                    r.get("source","manual"), r.get("platform",""),
                    r.get("program_url",""), r.get("scope_type","public"),
                    r.get("bounty",0), r.get("is_new",0), r.get("count",0),
                    r.get("change",0), r.get("last_updated",""),
                    r.get("created_at",""), r.get("updated_at",""),
                    r.get("scan_status","pending"), r.get("sync_enabled",1),
                    r.get("sync_cycle",0),
                    r.get("metadata","{}") or "{}",
                    r.get("last_synced"), r.get("phase_updated_at"),
                    r.get("phase_job_id"), r.get("phase_a_done_at"),
                    r.get("phase_b_done_at"), r.get("phase_c_done_at"),
                    r.get("phase_d_done_at"),
                    r.get("scope","[]") or "[]",
                    r.get("notes","") or "",
                )
                for r in rows
            ]
        )
    logger.info("  ✓ %d projects", len(rows))

    # ── Subdomains (batched to avoid OOM) ─────────────────────────────────────
    logger.info("Migrating subdomains (batched)...")
    total = src.execute("SELECT COUNT(*) FROM subdomains").fetchone()[0]
    logger.info("  Total: %d", total)
    done = 0
    offset = 0
    while True:
        batch = src.execute(
            "SELECT * FROM subdomains LIMIT ? OFFSET ?", (BATCH, offset)).fetchall()
        if not batch:
            break
        async with pool.acquire() as conn:
            await conn.executemany(
                """INSERT INTO subdomains(project_id,subdomain,url,status_code,title,tech,
                   content_length,ip,cdn_name,cdn_type,cname,webserver,response_time,
                   body_hash,favicon_hash,tls_host,tls_cn,tls_issuer,tls_sans,port,scheme,
                   path,is_alive,is_new,failed,fail_count,lifecycle,in_scope,
                   first_seen,last_seen,last_alive_check,last_deep_scan,
                   last_nuclei_scan,nuclei_scanned_at,discovery_cycle)
                   VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,
                          $19,$20,$21,$22,$23,$24,$25,$26,$27,$28,$29,$30,$31,$32,$33,$34,$35)
                   ON CONFLICT (project_id, subdomain) DO NOTHING""",
                [
                    (
                        r["project_id"], r["subdomain"],
                        r.get("url",""), r.get("status_code",0),
                        r.get("title",""), r.get("tech",""),
                        r.get("content_length",0), r.get("ip",""),
                        r.get("cdn_name",""), r.get("cdn_type",""),
                        r.get("cname",""), r.get("webserver",""),
                        r.get("response_time",""), r.get("body_hash",""),
                        r.get("favicon_hash",""), r.get("tls_host",""),
                        r.get("tls_cn",""), r.get("tls_issuer",""),
                        r.get("tls_sans",""), r.get("port",0),
                        r.get("scheme",""), r.get("path",""),
                        r.get("is_alive",0), r.get("is_new",1),
                        r.get("failed",0), r.get("fail_count",0),
                        r.get("lifecycle","new"), r.get("in_scope",1),
                        r.get("first_seen"), r.get("last_seen"),
                        r.get("last_alive_check"), r.get("last_deep_scan"),
                        r.get("last_nuclei_scan"), r.get("nuclei_scanned_at"),
                        r.get("discovery_cycle",0),
                    )
                    for r in batch
                ]
            )
        done += len(batch)
        offset += BATCH
        logger.info("  %d / %d (%.1f%%)", done, total, 100*done/max(total,1))
    logger.info("  ✓ %d subdomains", done)

    # ── Vulnerabilities ───────────────────────────────────────────────────────
    logger.info("Migrating vulnerabilities...")
    vuln_rows = src.execute("SELECT * FROM vulnerabilities").fetchall()
    if vuln_rows:
        async with pool.acquire() as conn:
            await conn.executemany(
                """INSERT INTO vulnerabilities(project_id,url,template_id,name,severity,
                   type,description,matched_at,curl_cmd,created_at,review_status,nuclei_scope,notes)
                   VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)""",
                [
                    (
                        r["project_id"], r.get("url",""), r.get("template_id",""),
                        r.get("name",""), r.get("severity","unknown"),
                        r.get("type",""), r.get("description",""),
                        r.get("matched_at",""), r.get("curl_cmd",""),
                        r.get("created_at",""), r.get("review_status","pending_review"),
                        r.get("nuclei_scope","auto"), r.get("notes","") or "",
                    )
                    for r in vuln_rows
                ]
            )
    logger.info("  ✓ %d vulnerabilities", len(vuln_rows))

    # ── Alerts ────────────────────────────────────────────────────────────────
    logger.info("Migrating alerts...")
    alert_rows = src.execute("SELECT * FROM alerts").fetchall()
    if alert_rows:
        async with pool.acquire() as conn:
            await conn.executemany(
                """INSERT INTO alerts(alert_type,project_id,subdomain,title,detail,severity,seen,created_at)
                   VALUES($1,$2,$3,$4,$5,$6,$7,$8)""",
                [
                    (
                        r.get("alert_type",""), r.get("project_id"),
                        r.get("subdomain",""), r.get("title",""),
                        r.get("detail",""), r.get("severity","info"),
                        r.get("seen",0), r.get("created_at",""),
                    )
                    for r in alert_rows
                ]
            )
    logger.info("  ✓ %d alerts", len(alert_rows))

    # ── Sync jobs ──────────────────────────────────────────────────────────────
    logger.info("Migrating sync jobs...")
    sj_rows = src.execute("SELECT * FROM sync_jobs ORDER BY started_at DESC LIMIT 100").fetchall()
    if sj_rows:
        async with pool.acquire() as conn:
            await conn.executemany(
                """INSERT INTO sync_jobs(id,platform,status,started_at,ended_at,total,imported,failed,skipped,scanned,phase)
                   VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
                   ON CONFLICT (id) DO NOTHING""",
                [
                    (
                        r["id"], r.get("platform",""), r.get("status","done"),
                        r.get("started_at",""), r.get("ended_at"),
                        r.get("total",0), r.get("imported",0),
                        r.get("failed",0), r.get("skipped",0),
                        r.get("scanned",0), r.get("phase",""),
                    )
                    for r in sj_rows
                ]
            )
    logger.info("  ✓ %d sync jobs", len(sj_rows))

    # BUG-18 FIX: system_logs migration was listed in the docstring but never
    # implemented. Added here — migrates last 10k entries only to avoid OOM.
    logger.info("Migrating system_logs (last 10k entries)...")
    log_rows = src.execute(
        "SELECT * FROM system_logs ORDER BY id DESC LIMIT 10000").fetchall()
    if log_rows:
        log_rows = list(reversed(log_rows))  # restore chronological order
        async with pool.acquire() as conn:
            await conn.executemany(
                """INSERT INTO system_logs(timestamp,level,category,job_id,message,detail)
                   VALUES($1,$2,$3,$4,$5,$6)""",
                [
                    (
                        r.get("timestamp",""), r.get("level","info"),
                        r.get("category","system"), r.get("job_id"),
                        r.get("message",""), r.get("detail","") or "",
                    )
                    for r in log_rows
                ]
            )
    logger.info("  ✓ %d system_logs", len(log_rows))

    src.close()
    await close_pool()
    logger.info("Migration complete ✓")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Migrate SUBMIND PRO data: SQLite → PostgreSQL")
    parser.add_argument("--sqlite", required=True, help="Path to submind.db SQLite file")
    args = parser.parse_args()
    asyncio.run(migrate(args.sqlite))
