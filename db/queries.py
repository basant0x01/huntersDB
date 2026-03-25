"""
db/queries.py — All async database query helpers.

Replaces the synchronous SQLite helpers in app.py.
All functions accept a pool or connection — no thread-local state.
"""
import asyncio
import json
import logging
from datetime import datetime
from typing import Optional, List, Dict, Any

logger = logging.getLogger("db.queries")

# ── Phase helpers ─────────────────────────────────────────────────────────────
_PHASE_ORDER = ("pending", "phase_a", "phase_a_done", "phase_b_done",
                "phase_c_done", "phase_d", "done")

def phase_rank(status: str) -> int:
    try:
        return _PHASE_ORDER.index(status)
    except ValueError:
        legacy = {"scanning": 1, "recon_done": 4, "nuclei_scanning": 5}
        return legacy.get(status, 0)


async def get_phase(conn, project_id: str) -> str:
    row = await conn.fetchrow(
        "SELECT scan_status FROM projects WHERE id=$1", project_id)
    return row["scan_status"] if row else "pending"


async def set_phase(conn, project_id: str, status: str,
                    job_id: Optional[str] = None,
                    extra: Optional[Dict] = None) -> None:
    now = datetime.now().isoformat()
    done_map = {
        "phase_a_done": "phase_a_done_at",
        "phase_b_done": "phase_b_done_at",
        "phase_c_done": "phase_c_done_at",
        "done":         "phase_d_done_at",
    }
    sets = ["scan_status=$2", "phase_updated_at=$3"]
    vals: List[Any] = [project_id, status, now]
    idx = 4
    if job_id:
        sets.append(f"phase_job_id=${idx}")
        vals.append(job_id)
        idx += 1
    if status in done_map:
        sets.append(f"{done_map[status]}=${idx}")
        vals.append(now)
        idx += 1
    if extra:
        for k, v in extra.items():
            sets.append(f"{k}=${idx}")
            vals.append(v)
            idx += 1
    sql = f"UPDATE projects SET {', '.join(sets)} WHERE id=$1"
    await conn.execute(sql, *vals)


# ── Project helpers ───────────────────────────────────────────────────────────
async def get_project(conn, project_id: str) -> Optional[Dict]:
    row = await conn.fetchrow("SELECT * FROM projects WHERE id=$1", project_id)
    return dict(row) if row else None


async def upsert_subdomains(conn, project_id: str, subdomains: List[str]) -> int:
    if not subdomains:
        return 0
    now = datetime.now().isoformat()
    CHUNK = 5000
    for i in range(0, len(subdomains), CHUNK):
        chunk = subdomains[i:i + CHUNK]
        await conn.executemany(
            """INSERT INTO subdomains
               (project_id, subdomain, first_seen, last_seen, is_new, lifecycle, in_scope, fail_count, is_alive)
               VALUES($1, $2, $3, $4, 1, 'new', 1, 0, 0)
               ON CONFLICT (project_id, subdomain) DO NOTHING""",
            [(project_id, s, now, now) for s in chunk]
        )
    count = await conn.fetchval(
        "SELECT COUNT(*) FROM subdomains WHERE project_id=$1", project_id)
    await conn.execute(
        "UPDATE projects SET count=$1, updated_at=$2 WHERE id=$3",
        count, now, project_id)
    return count


async def bulk_update_httpx(conn, project_id: str, results: List[Dict]) -> None:
    """Bulk UPDATE subdomains with deep httpx scan results."""
    if not results:
        return
    now = datetime.now().isoformat()
    CHUNK = 1000
    for ci in range(0, len(results), CHUNK):
        chunk = results[ci:ci + CHUNK]
        await conn.executemany(
            """UPDATE subdomains SET
               url=$1, status_code=$2, title=$3, tech=$4, content_length=$5,
               ip=$6, cdn_name=$7, cdn_type=$8, cname=$9, webserver=$10,
               response_time=$11, body_hash=$12, favicon_hash=$13,
               tls_host=$14, tls_cn=$15, tls_issuer=$16, tls_sans=$17,
               port=$18, scheme=$19, path=$20, failed=$21, last_seen=$22,
               is_alive=$23, last_deep_scan=$24
               WHERE project_id=$25 AND subdomain=$26""",
            [(r["url"], r["status_code"], r["title"], r["tech"],
              r["content_length"], r["ip"], r["cdn_name"], r["cdn_type"],
              r["cname"], r["webserver"], r["response_time"], r["body_hash"],
              r["favicon_hash"], r["tls_host"], r["tls_cn"], r["tls_issuer"],
              r["tls_sans"], r["port"], r["scheme"], r["path"], r["failed"],
              now, 0 if r["failed"] else 1, now, project_id, r["subdomain"])
             for r in chunk]
        )


async def update_lifecycle_states(conn, project_id: str,
                                   alive_set: set,
                                   job_id: Optional[str] = None):
    """
    Lifecycle state machine — direct port from original update_lifecycle_states().
    Returns (newly_dead, alive_count, resurrected).
    """
    # SC-03 FIX: Do NOT skip when alive_set is empty.
    # If Phase A found zero alive hosts, we must mark all previously-alive subs as failed.
    # Skipping would leave stale is_alive=1 forever.
    # alive_set empty = all hosts are down = treat as "nothing in alive_set" for lifecycle logic
    if not alive_set:
        logger.warning("[Lifecycle] alive_set empty — all subdomains will be marked failed/dead")
        # Fall through: the loop below will process all rows and none will match alive_set

    now = datetime.now().isoformat()
    all_rows = await conn.fetch(
        """SELECT subdomain, is_alive, fail_count, lifecycle
           FROM subdomains
           WHERE project_id=$1 AND in_scope=1 AND lifecycle!='dead'""",
        project_id
    )

    alive_count = newly_dead = resurrected = 0
    batch_alive = []
    batch_resurrected = []
    batch_unstable = []
    batch_dead = []

    for row in all_rows:
        sub = row["subdomain"].lower().strip()
        if sub in alive_set:
            alive_count += 1
            prev = row["lifecycle"] or "stable"
            if prev == "dead":
                resurrected += 1
                batch_resurrected.append((now, now, project_id, row["subdomain"]))
            elif prev == "new":
                batch_alive.append(("stable", now, now, project_id, row["subdomain"]))  # BUG-04 FIX: "alive" is not a valid lifecycle state
            else:
                batch_alive.append(("stable", now, now, project_id, row["subdomain"]))
        else:
            new_fail = (row["fail_count"] or 0) + 1
            if new_fail >= 3:
                newly_dead += 1
                batch_dead.append((new_fail, now, project_id, row["subdomain"]))
            else:
                batch_unstable.append((new_fail, now, project_id, row["subdomain"]))

    if batch_alive:
        await conn.executemany(
            """UPDATE subdomains SET is_alive=1, fail_count=0, lifecycle=$1,
               last_seen=$2, last_alive_check=$3
               WHERE project_id=$4 AND subdomain=$5""",
            batch_alive)
    if batch_resurrected:
        await conn.executemany(
            """UPDATE subdomains SET is_alive=1, fail_count=0, lifecycle='resurrected',
               last_seen=$1, last_alive_check=$2
               WHERE project_id=$3 AND subdomain=$4""",
            batch_resurrected)
    if batch_unstable:
        await conn.executemany(
            """UPDATE subdomains SET fail_count=$1, lifecycle='unstable', last_alive_check=$2
               WHERE project_id=$3 AND subdomain=$4""",
            batch_unstable)
    if batch_dead:
        await conn.executemany(
            """UPDATE subdomains SET is_alive=0, fail_count=$1, lifecycle='dead',
               last_alive_check=$2
               WHERE project_id=$3 AND subdomain=$4""",
            batch_dead)

    alive_total = await conn.fetchval(
        "SELECT COUNT(*) FROM subdomains WHERE project_id=$1 AND is_alive=1",
        project_id)
    await conn.execute(
        "UPDATE projects SET count=$1, updated_at=$2 WHERE id=$3",
        alive_total, now, project_id)

    logger.info("[Lifecycle] ✓%d alive | ✗%d newly dead | 🔥%d resurrected",
                alive_count, newly_dead, resurrected)
    return newly_dead, alive_count, resurrected


async def insert_vulnerability(conn, project_id: str, data: Dict) -> Optional[int]:
    """Insert a single vulnerability. Returns the new row ID."""
    now = datetime.now().isoformat()
    # QR-05 FIX: ON CONFLICT prevents duplicate vulns on nuclei re-run
    row_id = await conn.fetchval(
        """INSERT INTO vulnerabilities
           (project_id, url, template_id, name, severity, type, description,
            matched_at, curl_cmd, created_at, review_status, nuclei_scope)
           VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
           ON CONFLICT (project_id, template_id, matched_at) DO NOTHING
           RETURNING id""",
        project_id,
        data.get("url", ""),
        data.get("template_id", ""),
        data.get("name", ""),
        data.get("severity", "unknown"),
        data.get("type", ""),
        data.get("description", ""),
        data.get("matched_at", ""),
        data.get("curl_cmd", ""),
        now,
        "pending_review",
        data.get("scope", "auto"),
    )
    return row_id


async def insert_alert(conn, alert_type: str, project_id: str,
                        title: str, detail: str,
                        severity: str = "info",
                        vuln_id: Optional[int] = None,
                        subdomain: Optional[str] = None) -> None:
    now = datetime.now().isoformat()
    await conn.execute(
        """INSERT INTO alerts
           (alert_type, project_id, subdomain, vuln_id, title, detail, severity, seen, created_at)
           VALUES($1,$2,$3,$4,$5,$6,$7,0,$8)""",
        alert_type, project_id, subdomain or "", vuln_id, title,
        detail, severity, now)


async def batch_log(conn, entries: List[tuple]) -> None:
    """Batch insert log entries. entries = list of (ts, level, cat, job_id, msg, detail)."""
    await conn.executemany(
        """INSERT INTO system_logs(timestamp, level, category, job_id, message, detail)
           VALUES($1,$2,$3,$4,$5,$6)""",
        entries)


async def get_stats(conn) -> Dict:
    # QR-01 FIX: single SQL query with CTEs instead of asyncio.gather on one conn
    # asyncpg connections are NOT multiplexed — parallel calls on same conn serialize or error
    counts_row = await conn.fetchrow("""
        SELECT
            (SELECT COUNT(*) FROM projects)                                                    AS projs,
            (SELECT COUNT(*) FROM subdomains WHERE is_alive=1)                                AS alive,
            (SELECT COUNT(*) FROM subdomains)                                                  AS total_subs,
            (SELECT COUNT(*) FROM subdomains WHERE is_new=1)                                   AS new_subs,
            (SELECT COUNT(*) FROM vulnerabilities)                                             AS vulns,
            (SELECT COUNT(*) FROM alerts WHERE seen=0)                                        AS alerts,
            (SELECT COUNT(*) FROM vulnerabilities WHERE review_status='pending_review')       AS review_pend,
            (SELECT COUNT(*) FROM projects WHERE scan_status NOT IN ('pending','done'))       AS scanning,
            (SELECT COUNT(*) FROM projects WHERE scan_status='pending')                       AS pending,
            (SELECT COUNT(*) FROM projects WHERE source='chaos')                              AS chaos_c,
            (SELECT COUNT(*) FROM projects WHERE platform='hackerone' OR source='bbscope')   AS h1_c,
            (SELECT COUNT(*) FROM projects WHERE platform='yeswehack' OR source='yeswehack') AS ywh_c
    """)
    projs      = counts_row["projs"]
    alive      = counts_row["alive"]
    total_subs = counts_row["total_subs"]
    new_subs   = counts_row["new_subs"]
    vulns      = counts_row["vulns"]
    alerts     = counts_row["alerts"]
    review_pend= counts_row["review_pend"]
    scanning   = counts_row["scanning"]
    pending    = counts_row["pending"]
    chaos_c    = counts_row["chaos_c"]
    h1_c       = counts_row["h1_c"]
    ywh_c      = counts_row["ywh_c"]

    plat_rows = await conn.fetch(
        "SELECT platform, COUNT(*) as c FROM projects "
        "WHERE platform != '' GROUP BY platform ORDER BY c DESC LIMIT 10")
    try:
        tech_rows = await conn.fetch(
            "SELECT trim(t) as tech, COUNT(*) as c FROM subdomains, "
            "unnest(string_to_array(tech, ',')) as t "
            "WHERE tech != '' AND is_alive=1 "
            "GROUP BY trim(t) ORDER BY c DESC LIMIT 10")
    except Exception:
        tech_rows = []
    port_rows = await conn.fetch(
        "SELECT port, COUNT(*) as count FROM subdomains "
        "WHERE port > 0 AND is_alive=1 GROUP BY port ORDER BY count DESC LIMIT 10")
    recent_rows = await conn.fetch(
        "SELECT s.subdomain, s.url, s.status_code, s.title, s.tech, "
        "p.name as project_name FROM subdomains s "
        "JOIN projects p ON s.project_id = p.id "
        "WHERE s.is_alive=1 ORDER BY s.last_seen DESC NULLS LAST LIMIT 20")
    vuln_sev = await conn.fetch(
        "SELECT severity, COUNT(*) as count FROM vulnerabilities "
        "GROUP BY severity ORDER BY CASE severity "
        "WHEN 'critical' THEN 1 WHEN 'high' THEN 2 "
        "WHEN 'medium' THEN 3 WHEN 'low' THEN 4 ELSE 5 END")
    recent_vulns = await conn.fetch(
        "SELECT v.name, v.severity, p.name as project_name "
        "FROM vulnerabilities v LEFT JOIN projects p ON v.project_id=p.id "
        "ORDER BY v.created_at DESC LIMIT 5")

    port_svc = {80:"http",443:"https",8080:"http-alt",8443:"https-alt",
                22:"ssh",21:"ftp",25:"smtp",3306:"mysql",5432:"postgres",6379:"redis"}

    return {
        # Flat fields kept for SSE backward compat
        "programs": projs, "alive": alive, "vulnerabilities": vulns,
        "alerts": alerts, "scanning": scanning,
        "scanning_count": scanning,
        "review_pending": review_pend,
        "unread_alerts": alerts,
        # Nested structure for dashboard
        "projects": {
            "total": projs, "chaos": chaos_c,
            "hackerone": h1_c, "yeswehack": ywh_c,
            "pending": pending, "scanning": scanning,
        },
        "subdomains": {"alive": alive, "total": total_subs, "new": new_subs},
        # Dashboard widgets
        "platforms": [{"p": r["platform"], "c": r["c"]} for r in plat_rows],
        "tech_top":  [{"tech": (r["tech"] or "").strip(), "c": r["c"]}
                      for r in tech_rows if (r["tech"] or "").strip()],
        "top_ports": [{"port": r["port"],
                       "service": port_svc.get(r["port"], ""),
                       "count": r["count"]} for r in port_rows],
        "recent_alive":    [dict(r) for r in recent_rows],
        "vuln_by_severity":[dict(r) for r in vuln_sev],
        "recent_vulns":    [dict(r) for r in recent_vulns],
        "monitor": {"running": False},
        # Frontend compat — old app returned these from /api/stats
        "job":       {"running": scanning > 0},
        "bulk_scan": {"running": scanning > 0, "concurrent": 20,
                      "total": 0, "completed": 0, "eta": ""},
    }
