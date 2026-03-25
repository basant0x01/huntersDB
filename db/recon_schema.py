"""
db/recon_schema.py — Schema additions for Recon Intelligence module.

v3 adds columns for:
  - email_security   (SPF/DMARC/DKIM results)
  - waf              (WAF detection result)
  - header_issues    (missing/misconfigured HTTP security headers)
  - hidden_params    (arjun hidden parameter discovery)
  - bypass_403       (successful 403 bypass attempts)

Run via: await run_recon_migrations(pool)
Safe to re-run (IF NOT EXISTS / ADD COLUMN IF NOT EXISTS everywhere).
"""
import json
import logging
from datetime import datetime
from typing import Dict, List, Optional

logger = logging.getLogger("db.recon_schema")

RECON_SCHEMA_SQL = """
-- ── Recon Intelligence Results ─────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS recon_results (
    id              BIGSERIAL PRIMARY KEY,
    project_id      TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    subdomain       TEXT NOT NULL,
    url             TEXT DEFAULT '',
    ports           TEXT DEFAULT '[]',
    crawled_urls    TEXT DEFAULT '[]',
    archive_urls    TEXT DEFAULT '[]',
    endpoints       TEXT DEFAULT '[]',
    js_files        TEXT DEFAULT '[]',
    js_secrets      TEXT DEFAULT '[]',
    js_endpoints    TEXT DEFAULT '[]',
    js_lib_vulns    TEXT DEFAULT '[]',
    directories     TEXT DEFAULT '[]',
    broken_links    TEXT DEFAULT '[]',
    takeover        TEXT DEFAULT '{}',
    s3_buckets      TEXT DEFAULT '[]',
    origin_ip       TEXT DEFAULT '',
    risk_score      INTEGER DEFAULT 0,
    risk_severity   TEXT DEFAULT 'low',
    risk_factors    TEXT DEFAULT '[]',
    screenshot      TEXT DEFAULT '',
    scanned_at      TEXT NOT NULL,
    UNIQUE(project_id, subdomain)
);

CREATE INDEX IF NOT EXISTS idx_recon_proj ON recon_results(project_id);
CREATE INDEX IF NOT EXISTS idx_recon_sub ON recon_results(subdomain);
CREATE INDEX IF NOT EXISTS idx_recon_risk ON recon_results(risk_score DESC);

-- ── Leak Intelligence Results ──────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS leak_intel (
    id              BIGSERIAL PRIMARY KEY,
    project_id      TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    subdomain       TEXT NOT NULL,
    domain          TEXT DEFAULT '',
    compromised     INTEGER DEFAULT 0,
    sources         TEXT DEFAULT '[]',
    emails          TEXT DEFAULT '[]',
    passwords       TEXT DEFAULT '[]',
    api_tokens      TEXT DEFAULT '[]',
    github_leaks    TEXT DEFAULT '[]',
    breach_timeline TEXT DEFAULT '[]',
    hibp_breaches   TEXT DEFAULT '[]',
    hackedlist_data TEXT DEFAULT '{}',
    total_records   INTEGER DEFAULT 0,
    first_seen      TEXT,
    last_seen       TEXT,
    checked_at      TEXT NOT NULL,
    UNIQUE(project_id, subdomain)
);

CREATE INDEX IF NOT EXISTS idx_leak_proj ON leak_intel(project_id);
CREATE INDEX IF NOT EXISTS idx_leak_sub ON leak_intel(subdomain);
CREATE INDEX IF NOT EXISTS idx_leak_compromised ON leak_intel(compromised);
"""

# New columns added in v3 — safe to run on existing databases
RECON_SCHEMA_V3_MIGRATIONS = """
ALTER TABLE recon_results ADD COLUMN IF NOT EXISTS email_security  TEXT DEFAULT '{}';
ALTER TABLE recon_results ADD COLUMN IF NOT EXISTS waf             TEXT DEFAULT '{}';
ALTER TABLE recon_results ADD COLUMN IF NOT EXISTS header_issues   TEXT DEFAULT '[]';
ALTER TABLE recon_results ADD COLUMN IF NOT EXISTS hidden_params   TEXT DEFAULT '[]';
ALTER TABLE recon_results ADD COLUMN IF NOT EXISTS bypass_403      TEXT DEFAULT '[]';
"""


async def run_recon_migrations(pool) -> None:
    """Apply recon intelligence schema. Idempotent — safe to re-run."""
    logger.info("Running recon intelligence migrations (v3)...")
    async with pool.acquire() as conn:
        async with conn.transaction():
            await conn.execute(RECON_SCHEMA_SQL)
            await conn.execute(RECON_SCHEMA_V3_MIGRATIONS)
    logger.info("Recon intelligence migrations (v3) complete")


# ── Query helpers ──────────────────────────────────────────────────────────────

async def upsert_recon_result(conn, project_id: str, data: Dict) -> None:
    """Insert or update recon results for a subdomain (v3 — includes new fields)."""
    now  = data.get("scanned_at", datetime.now().isoformat())
    risk = data.get("risk", {})
    await conn.execute(
        """INSERT INTO recon_results(
            project_id, subdomain, url, ports, crawled_urls, archive_urls,
            endpoints, js_files, js_secrets, js_endpoints, js_lib_vulns,
            directories, broken_links, takeover, s3_buckets, origin_ip,
            screenshot, risk_score, risk_severity, risk_factors, scanned_at,
            email_security, waf, header_issues, hidden_params, bypass_403
        ) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,
                 $17,$18,$19,$20,$21,$22,$23,$24,$25,$26)
        ON CONFLICT(project_id, subdomain) DO UPDATE SET
            url=$3, ports=$4, crawled_urls=$5, archive_urls=$6,
            endpoints=$7, js_files=$8, js_secrets=$9, js_endpoints=$10,
            js_lib_vulns=$11, directories=$12, broken_links=$13,
            takeover=$14, s3_buckets=$15, origin_ip=$16,
            screenshot=$17, risk_score=$18, risk_severity=$19,
            risk_factors=$20, scanned_at=$21,
            email_security=$22, waf=$23, header_issues=$24,
            hidden_params=$25, bypass_403=$26
        """,
        project_id,
        data.get("subdomain", ""),
        data.get("url", ""),
        json.dumps(data.get("ports", [])),
        json.dumps(data.get("crawled_urls", [])),
        json.dumps(data.get("archive_urls", [])),
        json.dumps(data.get("endpoints", [])),
        json.dumps(data.get("js_files", [])),
        json.dumps(data.get("js_secrets", [])),
        json.dumps(data.get("js_endpoints", [])),
        json.dumps(data.get("js_lib_vulns", [])),
        json.dumps(data.get("directories", [])),
        json.dumps(data.get("broken_links", [])),
        json.dumps(data.get("takeover", {})),
        json.dumps(data.get("s3_buckets", [])),
        data.get("origin_ip", "") or "",
        data.get("screenshot", "") or "",
        int(risk.get("score", 0)),
        risk.get("severity", "low"),
        json.dumps(risk.get("factors", [])),
        now,
        json.dumps(data.get("email_security", {})),
        json.dumps(data.get("waf", {})),
        json.dumps(data.get("header_issues", [])),
        json.dumps(data.get("hidden_params", [])),
        json.dumps(data.get("bypass_403", [])),
    )


async def upsert_leak_intel(conn, project_id: str, data: Dict) -> None:
    """Insert or update leak intelligence for a subdomain."""
    now = data.get("checked_at", datetime.now().isoformat())
    await conn.execute(
        """INSERT INTO leak_intel(
            project_id, subdomain, domain, compromised, sources,
            emails, passwords, api_tokens, github_leaks, breach_timeline,
            hibp_breaches, hackedlist_data, total_records, first_seen, last_seen, checked_at
        ) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)
        ON CONFLICT(project_id, subdomain) DO UPDATE SET
            domain=$3, compromised=$4, sources=$5, emails=$6, passwords=$7,
            api_tokens=$8, github_leaks=$9, breach_timeline=$10,
            hibp_breaches=$11, hackedlist_data=$12, total_records=$13,
            first_seen=$14, last_seen=$15, checked_at=$16
        """,
        project_id,
        data.get("subdomain", ""),
        data.get("domain", ""),
        1 if data.get("compromised") else 0,
        json.dumps(data.get("sources", [])),
        json.dumps(data.get("emails", [])),
        json.dumps(data.get("passwords", [])),
        json.dumps(data.get("api_tokens", [])),
        json.dumps(data.get("github_leaks", [])),
        json.dumps(data.get("breach_timeline", [])),
        json.dumps(data.get("hibp_breaches", [])),
        json.dumps(data.get("hackedlist", {})),
        int(data.get("total_records", 0)),
        data.get("first_seen"),
        data.get("last_seen"),
        now,
    )


async def get_recon_result(conn, project_id: str, subdomain: str) -> Optional[Dict]:
    """Fetch recon result for a subdomain."""
    row = await conn.fetchrow(
        "SELECT * FROM recon_results WHERE project_id=$1 AND subdomain=$2",
        project_id, subdomain
    )
    if not row:
        return None
    d = dict(row)
    for field in ("ports", "crawled_urls", "archive_urls", "endpoints",
                  "js_files", "js_secrets", "js_endpoints", "js_lib_vulns",
                  "directories", "broken_links", "s3_buckets", "risk_factors",
                  "header_issues", "hidden_params", "bypass_403"):
        try:
            d[field] = json.loads(d.get(field) or "[]")
        except Exception:
            d[field] = []
    for field in ("takeover", "email_security", "waf"):
        try:
            d[field] = json.loads(d.get(field) or "{}")
        except Exception:
            d[field] = {}
    return d


async def get_leak_intel(conn, project_id: str, subdomain: str) -> Optional[Dict]:
    """Fetch leak intelligence for a subdomain."""
    row = await conn.fetchrow(
        "SELECT * FROM leak_intel WHERE project_id=$1 AND subdomain=$2",
        project_id, subdomain
    )
    if not row:
        return None
    d = dict(row)
    for field in ("sources", "emails", "passwords", "api_tokens",
                  "github_leaks", "breach_timeline", "hibp_breaches"):
        try:
            d[field] = json.loads(d.get(field) or "[]")
        except Exception:
            d[field] = []
    try:
        d["hackedlist"] = json.loads(d.get("hackedlist_data") or "{}")
    except Exception:
        d["hackedlist"] = {}
    return d


async def get_project_recon_summary(conn, project_id: str) -> Dict:
    """Get aggregated recon summary for a project."""
    row = await conn.fetchrow("""
        SELECT
            COUNT(*) AS total_scanned,
            SUM(CASE WHEN risk_severity='critical' THEN 1 ELSE 0 END) AS critical_count,
            SUM(CASE WHEN risk_severity='high'     THEN 1 ELSE 0 END) AS high_count,
            SUM(CASE WHEN risk_severity='medium'   THEN 1 ELSE 0 END) AS medium_count,
            SUM(CASE WHEN risk_severity='low'      THEN 1 ELSE 0 END) AS low_count,
            AVG(risk_score) AS avg_risk_score,
            MAX(risk_score) AS max_risk_score,
            SUM(CASE WHEN email_security::text LIKE '%"spf_missing": true%' THEN 1 ELSE 0 END) AS spf_missing_count,
            SUM(CASE WHEN email_security::text LIKE '%"dmarc_missing": true%' THEN 1 ELSE 0 END) AS dmarc_missing_count,
            SUM(CASE WHEN waf::text LIKE '%"detected": true%' THEN 1 ELSE 0 END) AS waf_detected_count,
            SUM(CASE WHEN bypass_403 != '[]' AND bypass_403 != '' THEN 1 ELSE 0 END) AS bypass_found_count
        FROM recon_results WHERE project_id=$1
    """, project_id)
    leak_row = await conn.fetchrow("""
        SELECT
            COUNT(*) AS total_checked,
            SUM(compromised) AS compromised_count,
            SUM(total_records) AS total_leaked_records
        FROM leak_intel WHERE project_id=$1
    """, project_id)
    return {
        "recon": dict(row) if row else {},
        "leaks": dict(leak_row) if leak_row else {},
    }
