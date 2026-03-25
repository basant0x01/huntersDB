"""
workers/scanning.py — Async scanning pipeline.

Direct async port of the original scanning functions:
  run_httpx_alive_check()     → Phase A
  update_lifecycle_states()   → Phase B  (lives in db/queries.py)
  run_httpx_batch()           → Phase C
  _nuclei_stream_scan()       → Phase D
  scan_project_recon()        → Phases A+B+C for one project
  scan_project_nuclei()       → Phase D for one project
  run_all_phases_ordered()    → Universal orchestrator

FIX-01: _nuclei_sem lazy-init — asyncio.Semaphore() was created at module
        import time which raises RuntimeError in Python 3.12 when no event
        loop exists yet. Now initialised on first use inside a coroutine.

FIX-02: Auto-nuclei trigger now tracks newly_discovered count from Phase B
        return value instead of querying is_new=1 (which Phase C resets to 0
        before the trigger fires — so the old check always found 0).

FIX-03: /api/scan/bulk duplicate — routes_server.py has a second bulk-scan
        endpoint that does NOT load scope from DB. Workaround here: the
        scan payload always includes scope so scan_project_recon picks it up.

All subprocess calls route through process_manager.manager (hard limit).
All DB calls use asyncpg — no blocking I/O anywhere.
"""
import asyncio
import json
import logging
import re
import uuid
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

from config.settings import (
    CHAOS_DIR, PHASE_A_CONCURRENT, PHASE_C_CONCURRENT, PHASE_D_CONCURRENT,
    HTTPX_ALIVE_TIMEOUT_SECS, HTTPX_DEEP_TIMEOUT_SECS, NUCLEI_TIMEOUT_SECS,
    PROC_POLL_INTERVAL, MAX_BATCH_SIZE, CPU_COUNT, NUCLEI_MAX_CONCURRENT,
)
from db.queries import (
    bulk_update_httpx, get_phase, set_phase, phase_rank,
    update_lifecycle_states, insert_vulnerability, insert_alert,
    upsert_subdomains,
)
from process_manager.manager import manager
from task_queue.redis_queue import set_scan_progress, clear_scan_progress, enqueue
from utils.log import log
from utils.settings import load_settings
from utils.webhooks import send_webhook
from workers.adaptive_scanner import run_httpx_adaptive

logger = logging.getLogger("workers.scanning")

# FIX-01: lazy semaphore — never created at import time
_nuclei_sem: Optional[asyncio.Semaphore] = None


def _get_nuclei_sem() -> asyncio.Semaphore:
    """Return the nuclei semaphore, creating it lazily inside the event loop."""
    global _nuclei_sem
    if _nuclei_sem is None:
        _nuclei_sem = asyncio.Semaphore(NUCLEI_MAX_CONCURRENT)
    return _nuclei_sem


# ── HTTPX helpers ──────────────────────────────────────────────────────────────

def _parse_httpx_json_line(line: str) -> Optional[Dict]:
    """Parse a single httpx JSON output line. Preserves original field extraction."""
    if not line.strip():
        return None
    try:
        d = json.loads(line)
        host = (d.get("input", "") or "").replace("http://", "").replace("https://", "").split("/")[0].split(":")[0]
        tls = d.get("tls", {}) or {}
        cdn = d.get("cdn", {}) or {}
        bh = ""
        for v in (d.get("hash") or {}).values():
            bh = v
            break
        tech_list = d.get("tech") or d.get("technologies") or []
        tech_str = ", ".join(tech_list) if isinstance(tech_list, list) else str(tech_list)
        cdn_name = cdn.get("name", "") if isinstance(cdn, dict) else str(cdn or "")
        cdn_type = cdn.get("type", "") if isinstance(cdn, dict) else ""
        cname = d.get("cname", "")
        if isinstance(cname, list):
            cname = ", ".join(cname)
        sans = tls.get("subject_an", [])
        if isinstance(sans, list):
            sans = ", ".join(sans[:5])
        a_records = d.get("a") or []
        if isinstance(a_records, list) and a_records:
            ip_val = a_records[0]
        elif isinstance(a_records, str) and a_records:
            ip_val = a_records
        else:
            host_val = d.get("host", "") or ""
            import re as _re
            ip_val = host_val if _re.match(r"^\d+\.\d+\.\d+\.\d+$", host_val) else ""
        return {
            "subdomain": host,
            "url": (d.get("url") or d.get("input", ""))[:500],
            "status_code": int(d.get("status_code") or 0),
            "title": (d.get("title") or "")[:200],
            "tech": tech_str[:500],
            "content_length": int(d.get("content_length") or 0),
            "ip": str(ip_val)[:45],
            "cdn_name": cdn_name[:100],
            "cdn_type": cdn_type[:50],
            "cname": cname[:300],
            "webserver": (d.get("webserver") or "")[:100],
            "response_time": (d.get("time") or d.get("response_time") or "")[:30],
            "body_hash": bh[:64],
            "favicon_hash": str(d.get("favicon_mmh3") or d.get("favicon") or "")[:64],
            "tls_host": (tls.get("host") or "")[:200],
            "tls_cn": (tls.get("subject_cn") or "")[:200],
            "tls_issuer": (tls.get("issuer_cn") or "")[:200],
            "tls_sans": sans[:500] if isinstance(sans, str) else "",
            "port": int(d.get("port") or 0),
            "scheme": (d.get("scheme") or "")[:10],
            "path": (d.get("path") or "")[:500],
            "failed": 1 if d.get("failed") else 0,
        }
    except Exception:
        return None


# ── Phase A: Fast alive check ──────────────────────────────────────────────────

async def run_httpx_alive_check(
    pool,
    subdomains: List[str],
    project_id: str,
    project_name: str,
    job_id: Optional[str] = None,
    batch_num: int = 1,
    batch_total: int = 1,
    total_all: int = 0,
    found_so_far: int = 0,
) -> Set[str]:
    if not subdomains:
        return set()

    s    = load_settings()
    t0   = s.get("httpx_threads", 50)
    rl0  = s.get("httpx_rate_limit", 300)
    cpu_tgt = s.get("atc_cpu_target", 70.0)

    init_threads = max(20, min(t0, 80))
    init_rate    = max(50,  min(rl0, 300))

    alive_hosts: Set[str] = set()

    async def _on_lines(raw_lines: List[str]):
        nonlocal alive_hosts
        new_alive = []
        for line in raw_lines:
            if not line.strip():
                continue
            try:
                d  = json.loads(line)
                h  = (d.get("input","") or "").replace("http://","").replace("https://","").split("/")[0].split(":")[0].lower().strip()
                sc = d.get("status_code") or 0
                if h and sc and sc > 0:
                    new_alive.append((h, int(sc)))
            except Exception:
                pass

        if not new_alive:
            return

        now = datetime.now().isoformat()
        async with pool.acquire() as conn:
            await conn.executemany(
                """UPDATE subdomains SET status_code=$1, is_alive=1,
                   last_seen=$2, last_alive_check=$3
                   WHERE project_id=$4 AND subdomain=$5""",
                [(sc, now, now, project_id, h) for h, sc in new_alive]
            )
        alive_hosts.update(h for h, _ in new_alive)

        _total = total_all if total_all > 0 else len(subdomains)
        _found = found_so_far + len(alive_hosts)
        await set_scan_progress(project_id, {
            "name":    project_name,
            "phase":   "A",
            "alive":   _found,
            "total":   _total,
            "batch":   batch_num,
            "batches": batch_total,
            "pct":     int(_found / max(_total, 1) * 100),
        })

    extra_flags = [
        "-timeout", "5",
        "-retries", "0",
        "-status-code",
        "-follow-redirects",
        "-random-agent",
    ]

    try:
        await run_httpx_adaptive(
            pool=pool,
            subdomains=subdomains,
            project_id=project_id,
            project_name=project_name,
            output_dir=CHAOS_DIR,
            initial_threads=init_threads,
            initial_rate=init_rate,
            timeout_secs=HTTPX_ALIVE_TIMEOUT_SECS,
            extra_flags=extra_flags,
            job_id=job_id,
            batch_num=batch_num,
            batch_total=batch_total,
            total_all=total_all,
            found_so_far=found_so_far,
            on_result_lines=_on_lines,
            cpu_target=cpu_tgt,
        )
        await log(pool,
            f"  [ATC-A] ✓ batch {batch_num}/{batch_total}: "
            f"{len(alive_hosts)}/{len(subdomains)} alive",
            "success", "httpx", job_id)
        return alive_hosts

    except Exception as e:
        await log(pool, f"  [ATC-A] error: {e}", "error", "httpx", job_id)
        return alive_hosts


async def _flush_alive_lines(path: Path, offset: int) -> Tuple[List[Tuple[str, int]], int]:
    if not path.exists():
        return [], offset
    try:
        def _read():
            with open(path, "r", errors="ignore") as fh:
                fh.seek(offset)
                data = fh.read()
                new_off = fh.tell()
            return data, new_off

        data, new_offset = await asyncio.to_thread(_read)
        new_alive = []
        for line in data.splitlines():
            if not line.strip():
                continue
            try:
                d = json.loads(line)
                host = (d.get("input", "") or "").replace("http://", "").replace("https://", "").split("/")[0].split(":")[0].lower().strip()
                sc = d.get("status_code") or 0
                if host and sc and sc > 0:
                    new_alive.append((host, int(sc)))
            except Exception:
                continue
        return new_alive, new_offset
    except Exception:
        return [], offset


# ── Phase C: Deep httpx scan ───────────────────────────────────────────────────

async def run_httpx_batch(
    pool,
    subdomains: List[str],
    job_id: Optional[str] = None,
    project_id: Optional[str] = None,
    project_name: Optional[str] = None,
) -> List[Dict]:
    if not subdomains:
        return []

    s       = load_settings()
    t0      = s.get("httpx_threads", 50)
    rl0     = s.get("httpx_rate_limit", 300)
    ports   = s.get("httpx_ports", "80,443,8080,8443")
    cpu_tgt = s.get("atc_cpu_target", 70.0)

    init_threads = max(10, min(t0, 50))
    init_rate    = max(50, min(rl0, 200))

    all_results: List[Dict] = []

    async def _on_lines_c(raw_lines: List[str]):
        batch = []
        for line in raw_lines:
            if not line.strip():
                continue
            parsed = _parse_httpx_json_line(line)
            if parsed:
                batch.append(parsed)
        if batch:
            all_results.extend(batch)
            if project_id:
                async with pool.acquire() as conn:
                    await bulk_update_httpx(conn, project_id, batch)

    extra_flags = [
        "-timeout",    str(s.get("httpx_timeout", 10)),
        "-retries",    "1",
        "-ports",      ports,
        "-title", "-status-code", "-tech-detect", "-content-length",
        "-ip", "-cname", "-cdn", "-favicon", "-hash", "body",
        "-tls-grab", "-follow-redirects", "-web-server", "-response-time",
    ]

    await log(pool,
        f"  [ATC-C] Phase C: {len(subdomains)} targets "
        f"start t={init_threads} rl={init_rate}",
        "info", "httpx", job_id)

    try:
        _, stats = await run_httpx_adaptive(
            pool=pool,
            subdomains=subdomains,
            project_id=project_id,
            project_name=project_name or "",
            output_dir=CHAOS_DIR,
            initial_threads=init_threads,
            initial_rate=init_rate,
            timeout_secs=HTTPX_DEEP_TIMEOUT_SECS,
            extra_flags=extra_flags,
            job_id=job_id,
            on_result_lines=_on_lines_c,
            cpu_target=cpu_tgt,
        )
        await log(pool,
            f"  [ATC-C] Done: {len(all_results)}/{len(subdomains)} "
            f"final t={stats['threads']} cpu={stats.get('cpu', stats.get('cpu_ewma', 0))}% "
            f"adjustments={stats['adjustments']}",
            "success", "httpx", job_id)
        return all_results
    except Exception as e:
        await log(pool, f"  [ATC-C] error: {e}", "error", "httpx", job_id)
        return all_results


async def _flush_httpx_lines(path: Path, offset: int) -> Tuple[List[Dict], int]:
    if not path.exists():
        return [], offset
    try:
        def _read():
            with open(path, "r", errors="ignore") as fh:
                fh.seek(offset)
                data = fh.read()
                new_off = fh.tell()
            return data, new_off

        data, new_offset = await asyncio.to_thread(_read)
        batch = []
        for line in data.splitlines():
            r = _parse_httpx_json_line(line)
            if r:
                batch.append(r)
        return batch, new_offset
    except Exception:
        return [], offset


# ── Phase D: Nuclei vulnerability scan ────────────────────────────────────────

async def _nuclei_stream_scan(
    pool,
    project_id: str,
    project_name: str,
    urls: List[str],
    job_id: Optional[str] = None,
    scope: str = "auto",
    extra_flags: Optional[List[str]] = None,
    severity_filter: str = "critical,high,medium,low",
) -> int:
    if not urls:
        return 0

    try:
        project_id = int(project_id)
    except (ValueError, TypeError):
        pass

    s = load_settings()
    nuclei_threads = s.get("nuclei_threads", 50)
    nuclei_rl = s.get("nuclei_rate_limit", 200)

    safe_max = max(10, (CPU_COUNT * 30) // NUCLEI_MAX_CONCURRENT)
    if nuclei_threads > safe_max:
        await log(pool, f"  ⚠ Nuclei threads capped: {nuclei_threads}→{safe_max}", "warning", "nuclei", job_id)
        nuclei_threads = safe_max
        nuclei_rl = min(nuclei_rl, safe_max * 4)

    if len(urls) > 10000:
        nuclei_threads = min(nuclei_threads, 40)
        nuclei_rl = min(nuclei_rl, 150)

    await log(pool, f"  ┌─ Nuclei: {project_name} | {len(urls):,} URLs | t={nuclei_threads} rl={nuclei_rl}",
              "info", "nuclei", job_id)

    nuc_ti = CHAOS_DIR / f"nuc_in_{uuid.uuid4().hex}.txt"
    nuc_cmd = [
        "nice", "-n", "10",
        "nuclei",
        "-l", str(nuc_ti),
        "-jsonl",
        "-c", str(nuclei_threads),
        "-rl", str(nuclei_rl),
        "-bs", str(min(50, nuclei_threads)),
        "-timeout", "7",
        "-retries", "0",
        "-mhe", "5",
        "-no-interactsh",
        "-nc",
        "-stats",
        "-si", "15",
    ]
    if severity_filter:
        nuc_cmd += ["-s", severity_filter]
    if extra_flags:
        nuc_cmd += extra_flags

    vuln_count = 0

    # FIX-01: use lazy getter instead of module-level semaphore
    nuclei_sem = _get_nuclei_sem()

    await log(pool, f"  │  [semaphore] waiting for nuclei slot (max {NUCLEI_MAX_CONCURRENT})…",
              "info", "nuclei", job_id)
    async with nuclei_sem:
        await log(pool, f"  │  [semaphore] slot acquired → starting nuclei", "info", "nuclei", job_id)

        try:
            await asyncio.to_thread(nuc_ti.write_text, "\n".join(urls))

            proc = await manager.run_streaming("nuclei", nuc_cmd, NUCLEI_TIMEOUT_SECS)

            stderr_task = asyncio.create_task(
                _nuclei_stderr_reader(pool, proc, project_id, job_id))

            try:
                vuln_batch = []
                alert_batch = []
                sub_update_batch = []
                _vuln_seen_this_run: set = set()
                COMMIT_EVERY = 50

                async def flush_vuln_batch():
                    nonlocal vuln_count
                    if not vuln_batch:
                        return
                    try:
                        async with pool.acquire() as conn:
                            inserted_ids = []
                            for vdata in vuln_batch:
                                vid = await insert_vulnerability(conn, str(project_id), vdata)
                                inserted_ids.append(vid)
                            for alert in alert_batch:
                                await insert_alert(
                                    conn,
                                    alert_type="vuln_found",
                                    project_id=str(project_id),
                                    title=alert["title"],
                                    detail=alert["detail"],
                                    severity=alert["severity"],
                                    vuln_id=inserted_ids[alert["vuln_idx"]] if alert.get("vuln_idx") is not None else None,
                                )
                            if sub_update_batch:
                                await conn.executemany(
                                    "UPDATE subdomains SET nuclei_scanned_at=$1 WHERE project_id=$2 AND subdomain=$3",
                                    sub_update_batch)
                        vuln_batch.clear()
                        alert_batch.clear()
                        sub_update_batch.clear()
                    except Exception as e:
                        await log(pool, f"  │  Batch vuln flush error: {e}", "error", "nuclei", job_id)
                        if len(vuln_batch) > 500:
                            vuln_batch.clear(); alert_batch.clear(); sub_update_batch.clear()

                async for line in proc.stdout:
                    line_s = line.decode("utf-8", errors="replace").strip()
                    if not line_s:
                        continue
                    try:
                        vd = json.loads(line_s)
                    except json.JSONDecodeError:
                        continue

                    info = vd.get("info", {})
                    sev = (info.get("severity") or "unknown").lower()
                    if sev == "info" and s.get("nuclei_skip_info", True):
                        continue

                    tpl_id = vd.get("template-id") or vd.get("templateID") or ""
                    vname  = info.get("name") or tpl_id or "Unknown"
                    vtype  = vd.get("type") or ""
                    vdesc  = info.get("description") or ""
                    matched = vd.get("matched-at") or vd.get("host") or ""
                    curl   = vd.get("curl-command") or ""

                    await log(pool, f"  │  🎯 [{sev.upper()}] {vname} → {matched[:100]}", "success", "nuclei", job_id)

                    vdata = {
                        "template_id": tpl_id, "name": vname, "severity": sev,
                        "type": vtype, "description": vdesc,
                        "matched_at": matched, "curl_cmd": curl, "scope": scope,
                        "url": matched,
                    }
                    dedup_key = f"{tpl_id}:{matched}"
                    if dedup_key not in _vuln_seen_this_run:
                        _vuln_seen_this_run.add(dedup_key)
                    else:
                        continue
                    vuln_idx = len(vuln_batch)
                    vuln_batch.append(vdata)
                    vuln_count += 1

                    if sev in ("critical", "high"):
                        alert_batch.append({
                            "title": f"[{sev.upper()}] {vname}",
                            "detail": json.dumps({"template": tpl_id, "target": matched[:200]}),
                            "severity": sev,
                            "vuln_idx": vuln_idx,
                        })
                        asyncio.create_task(send_webhook(
                            f"🛡 {sev.upper()}: {vname}",
                            f"Project: {project_name}\nURL: {matched}\nTemplate: {tpl_id}",
                            severity=sev,
                        ))

                    host = matched.replace("http://", "").replace("https://", "").split("/")[0].split(":")[0]
                    if host:
                        sub_update_batch.append((datetime.now().isoformat(), str(project_id), host))

                    if len(vuln_batch) >= COMMIT_EVERY:
                        await flush_vuln_batch()

                await flush_vuln_batch()

            finally:
                stderr_task.cancel()
                try:
                    await asyncio.wait_for(stderr_task, timeout=5.0)
                except (asyncio.CancelledError, asyncio.TimeoutError):
                    pass
                await manager.release_process(proc)

        except FileNotFoundError:
            await log(pool, "  └─ FAILED: 'nuclei' not installed!", "error", "nuclei", job_id)
        except Exception as e:
            await log(pool, f"  └─ Nuclei error: {type(e).__name__}: {e}", "error", "nuclei", job_id)
        finally:
            try:
                await asyncio.to_thread(nuc_ti.unlink, missing_ok=True)
            except Exception:
                pass

    await log(pool, f"  └─ Nuclei done: {vuln_count} new vulns (scope={scope})",
              "success" if vuln_count > 0 else "info", "nuclei", job_id)
    return vuln_count


async def _nuclei_stderr_reader(pool, proc, project_id, job_id):
    try:
        async for line in proc.stderr:
            line_s = line.decode("utf-8", errors="replace").strip()
            if not line_s:
                continue
            clean = re.sub(r'\x1b\[[0-9;]*m', '', line_s)
            if clean.startswith("{") and "percent" in clean:
                try:
                    st = json.loads(clean)
                    pct = st.get("percent", "?")
                    rps = st.get("rps", "?")
                    matched = st.get("matched", "0")
                    dur = st.get("duration", "?")
                    await set_scan_progress(str(project_id), {"nuclei_pct": pct})
                    await log(pool, f"  │  ⏳ {pct}% | {rps} rps | {matched} found | {dur}",
                              "info", "nuclei", job_id)
                except Exception:
                    pass
            else:
                lower = clean.lower()
                if any(kw in lower for kw in ["loaded", "error", "warn", "fatal"]):
                    await log(pool, f"  │  [nuclei] {clean[:200]}", "info", "nuclei", job_id)
    except asyncio.CancelledError:
        pass
    except Exception:
        pass


# ── Phase orchestration ────────────────────────────────────────────────────────

async def scan_project_recon(pool, project_id: str, job_id: Optional[str] = None,
                             run_subfinder: bool = False,
                             scope: Optional[List[str]] = None) -> Dict:
    """
    Phase 0 (subfinder) + A + B + C for a single project.
    Returns dict including 'newly_discovered' count used by auto-nuclei trigger.
    """
    async with pool.acquire() as conn:
        proj_row = await conn.fetchrow(
            "SELECT name, scan_status, scope FROM projects WHERE id=$1", project_id)
    if not proj_row:
        return {"scanned": 0, "total": 0, "removed": 0, "project_name": project_id, "newly_discovered": 0}

    project_name   = proj_row["name"]
    current_status = proj_row["scan_status"] or "pending"
    cur_rank = phase_rank(current_status)

    if cur_rank >= phase_rank("done") or cur_rank == phase_rank("phase_d"):
        async with pool.acquire() as conn:
            live  = await conn.fetchval("SELECT COUNT(*) FROM subdomains WHERE project_id=$1 AND is_alive=1", project_id)
            total = await conn.fetchval("SELECT COUNT(*) FROM subdomains WHERE project_id=$1 AND in_scope=1", project_id)
        await log(pool, f"  [SKIP-RECON] {project_name}: already done — {live:,} alive",
                  "info", "httpx", job_id)
        return {"scanned": live, "total": total, "removed": 0,
                "project_name": project_name, "skipped": True, "newly_discovered": 0}

    resume_labels = {
        "pending":      "fresh scan — Phase 0→A→B→C",
        "phase_a":      "resuming from Phase A (alive check)",
        "phase_a_done": "resuming from Phase B (lifecycle)",
        "phase_b_done": "resuming from Phase C (deep httpx)",
    }
    resume_label = resume_labels.get(current_status, f"resuming from {current_status}")
    await log(pool, f"  [{project_name}] {resume_label}",
              "info", "httpx", job_id)

    s_cfg = load_settings()
    BATCH = min(s_cfg.get("httpx_batch_size", 3000), MAX_BATCH_SIZE)

    # ── Phase 0: Subfinder discovery ──────────────────────────────────────────
    if cur_rank < phase_rank("phase_a") and run_subfinder:
        raw_scope = scope or []
        if not raw_scope:
            try:
                stored = proj_row["scope"] or "[]"
                raw_scope = json.loads(stored) if isinstance(stored, str) else (stored or [])
            except Exception:
                raw_scope = []

        domains_to_enum: List[str] = []
        for entry in raw_scope:
            if not entry or not isinstance(entry, str):
                continue
            d = entry.strip().lstrip("*.").lower()
            if d and "." in d:
                domains_to_enum.append(d)
        domains_to_enum = list(dict.fromkeys(domains_to_enum))

        if domains_to_enum:
            from workers.subfinder import run_subfinder as _run_subfinder
            from utils.clean import clean_subdomains
            async with pool.acquire() as conn:
                await set_phase(conn, project_id, "phase_a", job_id)
            await set_scan_progress(project_id, {
                "name": project_name, "phase": "0",
                "alive": 0, "total": 1, "pct": 0,
                "status": "Discovering subdomains with Subfinder...",
            })
            await log(pool,
                      f"  ┌─ [0] Subfinder discovery: {len(domains_to_enum)} domain(s) — {project_name}",
                      "info", "subfinder", job_id)

            async def _sf_domain(domain: str) -> List[str]:
                found = await _run_subfinder(domain, job_id)
                found.append(domain)
                await log(pool, f"  │  [0] {domain} → {len(found)} subs found",
                          "info", "subfinder", job_id)
                return found

            sf_results = await asyncio.gather(*[_sf_domain(d) for d in domains_to_enum])
            all_found: List[str] = [s for batch in sf_results for s in batch]

            if all_found:
                cleaned = clean_subdomains(all_found)
                async with pool.acquire() as conn:
                    await upsert_subdomains(conn, project_id, cleaned)
                await log(pool,
                          f"  └─ [0] Subfinder done: {len(cleaned)} unique subs upserted — {project_name}",
                          "success", "subfinder", job_id)
            else:
                await log(pool, f"  └─ [0] Subfinder: no subs found — {project_name}",
                          "warning", "subfinder", job_id)
        else:
            await log(pool,
                      f"  [0] Subfinder requested but no scope domains defined — {project_name}",
                      "warning", "subfinder", job_id)

    async with pool.acquire() as conn:
        fresh = await conn.fetchrow("SELECT scan_status FROM projects WHERE id=$1", project_id)
    current_status = (fresh["scan_status"] if fresh else current_status) or "pending"
    cur_rank = phase_rank(current_status)

    # ── Phase A ────────────────────────────────────────────────────────────────
    alive_set: Set[str] = set()
    if cur_rank < phase_rank("phase_a_done"):
        async with pool.acquire() as conn:
            already_alive = {r["subdomain"].lower() for r in
                             await conn.fetch(
                                 "SELECT subdomain FROM subdomains WHERE project_id=$1 AND is_alive=1",
                                 project_id)}
            all_subs = [r["subdomain"] for r in
                        await conn.fetch(
                            "SELECT subdomain FROM subdomains WHERE project_id=$1 AND in_scope=1 AND lifecycle!='dead'",
                            project_id)]

        subs_to_check = all_subs
        alive_set = set(already_alive)

        if not all_subs:
            async with pool.acquire() as conn:
                await set_phase(conn, project_id, "done", job_id)
            return {"scanned": 0, "total": 0, "removed": 0, "project_name": project_name, "newly_discovered": 0}

        if subs_to_check:
            original_count = len(subs_to_check)
            total_batches_a = (original_count + BATCH - 1) // BATCH
            async with pool.acquire() as conn:
                await set_phase(conn, project_id, "phase_a", job_id)

            await log(pool, f"  ┌─ [A] Alive check: {original_count:,} remaining — {project_name}",
                      "info", "httpx", job_id)
            for i in range(0, original_count, BATCH):
                batch  = subs_to_check[i:i + BATCH]
                bn     = i // BATCH + 1
                found  = await run_httpx_alive_check(
                    pool, batch, project_id, project_name, job_id, bn, total_batches_a,
                    total_all=original_count, found_so_far=len(alive_set))
                alive_set.update(found)
                await asyncio.sleep(0.05)

            await log(pool, f"  └─ [A] done: {len(alive_set):,}/{len(all_subs):,} alive",
                      "success", "httpx", job_id)
        else:
            await log(pool, f"  [A] RESUME: all {len(already_alive):,} alive preserved — skipping",
                      "success", "httpx", job_id)

        async with pool.acquire() as conn:
            await set_phase(conn, project_id, "phase_a_done", job_id)
    else:
        async with pool.acquire() as conn:
            rows = await conn.fetch(
                "SELECT subdomain FROM subdomains WHERE project_id=$1 AND is_alive=1", project_id)
        alive_set = {r["subdomain"].lower() for r in rows}
        await log(pool, f"  [RESUME-A] {project_name}: {len(alive_set):,} alive from DB",
                  "info", "httpx", job_id)

    cur_rank = phase_rank(await _get_phase_pool(pool, project_id))
    original_count = len(alive_set)
    removed = 0
    # FIX-02: Track newly_discovered from Phase B (resurrected + brand-new alive)
    # so auto-nuclei trigger doesn't falsely read is_new=1 which Phase C clears
    newly_discovered = 0

    # ── Phase B ────────────────────────────────────────────────────────────────
    if cur_rank < phase_rank("phase_b_done"):
        alive_count_b = len(alive_set)
        await log(pool, f"  ┌─ [B] Lifecycle update — {project_name}", "info", "httpx", job_id)
        await set_scan_progress(project_id, {
            "name":    project_name,
            "phase":   "B",
            "alive":   alive_count_b,
            "total":   alive_count_b,
            "pct":     100,
            "batch":   1,
            "batches": 1,
            "status":  f"Lifecycle update: {alive_count_b:,} hosts",
        })
        async with pool.acquire() as conn:
            newly_dead, alive_count, resurrected = await update_lifecycle_states(
                conn, project_id, alive_set, job_id)
            removed = newly_dead
            # FIX-02: resurrected = hosts that came back + brand-new ones from subfinder
            # This is safe to use for auto-nuclei trigger — Phase C doesn't clear it
            newly_discovered = resurrected
            await log(pool, f"  └─ [B] done: alive={alive_count:,} dead={newly_dead:,} resurrected={resurrected:,}",
                      "success", "httpx", job_id)
            await set_phase(conn, project_id, "phase_b_done", job_id)

        if alive_count == 0:
            async with pool.acquire() as conn:
                await set_phase(conn, project_id, "done", job_id,
                                extra={"last_synced": datetime.now().isoformat()})
            await clear_scan_progress(project_id)
            return {"scanned": 0, "total": original_count, "removed": removed,
                    "project_name": project_name, "newly_discovered": 0}
    else:
        await log(pool, f"  [RESUME-B] {project_name}: Phase B already done", "info", "httpx", job_id)

    cur_rank = phase_rank(await _get_phase_pool(pool, project_id))

    # ── Phase C ────────────────────────────────────────────────────────────────
    scanned = 0
    if cur_rank < phase_rank("phase_c_done"):
        async with pool.acquire() as conn:
            live_subs_all = [r["subdomain"] for r in await conn.fetch(
                "SELECT subdomain FROM subdomains WHERE project_id=$1 AND is_alive=1", project_id)]
            already_deep = await conn.fetchval(
                "SELECT COUNT(*) FROM subdomains WHERE project_id=$1 AND is_alive=1 AND last_deep_scan IS NOT NULL",
                project_id)
            live_subs_rows = await conn.fetch(
                "SELECT subdomain, url FROM subdomains "
                "WHERE project_id=$1 AND is_alive=1 AND last_deep_scan IS NULL",
                project_id)
            live_subs = [
                (r["url"].replace("http://","").replace("https://","").split("/")[0]
                 if r["url"] and r["url"].strip() else r["subdomain"])
                for r in live_subs_rows
            ]
            seen_c = set()
            live_subs_deduped = []
            for s in live_subs:
                if s and s not in seen_c:
                    seen_c.add(s); live_subs_deduped.append(s)
            live_subs = live_subs_deduped

        if not live_subs_all:
            async with pool.acquire() as conn:
                await set_phase(conn, project_id, "done", job_id,
                                extra={"last_synced": datetime.now().isoformat()})
            await clear_scan_progress(project_id)
            return {"scanned": 0, "total": original_count, "removed": removed,
                    "project_name": project_name, "newly_discovered": newly_discovered}

        if live_subs:
            total_c = len(live_subs)
            total_batches_c = (total_c + BATCH - 1) // BATCH
            await log(pool, f"  ┌─ [C] Deep scan: {total_c:,} remaining ({already_deep:,} done) — {project_name}",
                      "info", "httpx", job_id)
            await set_scan_progress(project_id, {
                "name":    project_name,
                "phase":   "C",
                "alive":   already_deep,
                "total":   already_deep + total_c,
                "pct":     int(already_deep / max(already_deep + total_c, 1) * 100),
                "batch":   1,
                "batches": total_batches_c,
            })
            for i in range(0, total_c, BATCH):
                batch = live_subs[i:i + BATCH]
                bn = i // BATCH + 1
                results = await run_httpx_batch(
                    pool, batch, job_id, project_id=project_id, project_name=project_name)
                scanned += len(results)
                done_so_far = already_deep + scanned
                total_all_c = already_deep + total_c
                pct_c = int(done_so_far / max(total_all_c, 1) * 100)
                await set_scan_progress(project_id, {
                    "name":    project_name,
                    "phase":   "C",
                    "alive":   done_so_far,
                    "total":   total_all_c,
                    "pct":     pct_c,
                    "batch":   bn,
                    "batches": total_batches_c,
                })
                await log(pool, f"  │  [C] batch {bn}/{total_batches_c}: {len(results)} enriched",
                          "success", "httpx", job_id)
                await asyncio.sleep(0.25)

            now_c = datetime.now().isoformat()
            async with pool.acquire() as conn:
                await conn.execute(
                    "UPDATE subdomains SET last_deep_scan=$1, is_new=0 "
                    "WHERE project_id=$2 AND is_alive=1 AND failed=0 AND url != ''",
                    now_c, project_id)
                await conn.execute(
                    "UPDATE subdomains SET is_new=0 WHERE project_id=$1 AND is_new=1",
                    project_id)
                await conn.execute(
                    "UPDATE subdomains SET lifecycle='stable' "
                    "WHERE project_id=$1 AND is_alive=1 AND failed=0 "
                    "AND lifecycle NOT IN ('dead','resurrected','unstable')",
                    project_id)
                await set_phase(conn, project_id, "done", job_id,
                                extra={"last_synced": now_c})

            await log(pool, f"  └─ [C] done: {scanned:,} hosts enriched — {project_name}",
                      "success", "httpx", job_id)
        else:
            await log(pool, f"  [C] RESUME: all {already_deep:,} already deep-scanned",
                      "success", "httpx", job_id)
            async with pool.acquire() as conn:
                alive_cnt = await conn.fetchval(
                    "SELECT COUNT(*) FROM subdomains WHERE project_id=$1 AND is_alive=1", project_id)
                await conn.execute(
                    "UPDATE projects SET count=$1, updated_at=$2 WHERE id=$3",
                    alive_cnt, datetime.now().isoformat(), project_id)
                await set_phase(conn, project_id, "done", job_id,
                                extra={"last_synced": datetime.now().isoformat()})
            scanned = already_deep
    else:
        await log(pool, f"  [RESUME-C] {project_name}: Phase C already done", "info", "httpx", job_id)
        async with pool.acquire() as conn:
            scanned = await conn.fetchval(
                "SELECT COUNT(*) FROM subdomains WHERE project_id=$1 AND is_alive=1 AND last_deep_scan IS NOT NULL",
                project_id)

    await clear_scan_progress(project_id)
    return {"scanned": scanned, "total": original_count, "removed": removed,
            "project_name": project_name, "newly_discovered": newly_discovered}


async def scan_project_nuclei(
    pool,
    project_id: str,
    job_id: Optional[str] = None,
    templates: Optional[str] = None,
    severity: Optional[str] = None,
) -> int:
    project_id_str = str(project_id)

    async with pool.acquire() as conn:
        proj_row = await conn.fetchrow(
            "SELECT name, scan_status FROM projects WHERE id=$1", project_id)
    if not proj_row:
        return 0

    project_name = proj_row["name"]

    async with pool.acquire() as conn:
        live_rows = await conn.fetch(
            "SELECT url FROM subdomains WHERE project_id=$1 AND is_alive=1 "
            "AND url IS NOT NULL AND url!='' AND (failed=0 OR failed IS NULL)",
            project_id)
    live_urls = list({r["url"] for r in live_rows if r["url"]})

    if not live_urls:
        await log(pool, f"  [D] skipped: no live URLs found — {project_name}", "info", "nuclei", job_id)
        return 0

    await set_scan_progress(str(project_id), {
        "name": project_name, "total": len(live_urls), "alive": len(live_urls),
        "phase": "D", "batch": 0, "batches": 1,
        "nuclei_found": 0, "nuclei_pct": 0,
    })
    async with pool.acquire() as conn:
        await set_phase(conn, project_id, "phase_d", job_id)

    vuln_count = 0
    phase_d_ok = False
    try:
        if live_urls:
            await log(pool, f"  ┌─ [D] Nuclei scan: {len(live_urls):,} live URLs — {project_name}",
                      "info", "nuclei", job_id)
            extra_flags: List[str] = []
            if templates and templates.strip():
                extra_flags += ["-t", templates.strip()]
            severity_filter = (severity.strip() if severity and severity.strip()
                               else "critical,high,medium,low")
            vuln_count = await _nuclei_stream_scan(
                pool, project_id, project_name, live_urls, job_id,
                scope="auto",
                extra_flags=extra_flags if extra_flags else None,
                severity_filter=severity_filter)
            await log(pool, f"  └─ [D] done: {vuln_count} findings — {project_name}",
                      "success", "nuclei", job_id)
        else:
            await log(pool, f"  [D] skipped: no live URLs — {project_name}", "info", "nuclei", job_id)
        phase_d_ok = True
    except Exception as e:
        await log(pool, f"  [D] ERROR {project_name}: {e}", "error", "nuclei", job_id)
        raise
    finally:
        now_nuc = datetime.now().isoformat()
        if phase_d_ok:
            async with pool.acquire() as conn:
                await conn.execute(
                    "UPDATE subdomains SET last_nuclei_scan=$1 "
                    "WHERE project_id=$2 AND is_alive=1 AND url IS NOT NULL AND url!=''",
                    now_nuc, project_id)
                await set_phase(conn, project_id, "done", job_id,
                                extra={"phase_d_done_at": now_nuc, "last_synced": now_nuc})
        await clear_scan_progress(str(project_id))
        await clear_scan_progress(project_id_str)

    return vuln_count


# ── Universal orchestrator ─────────────────────────────────────────────────────

async def run_all_phases_ordered(
    pool,
    projects: List[Dict],
    job_id: Optional[str] = None,
    max_phase_a: int = PHASE_A_CONCURRENT,
    max_phase_c: int = PHASE_C_CONCURRENT,
    max_phase_d: int = PHASE_D_CONCURRENT,
    label: str = "",
) -> Dict:
    if not projects:
        return {"recon_results": {}, "nuclei_results": {}}

    prefix = f"[{label}] " if label else ""
    await log(pool, f"{prefix}Starting pipeline: {len(projects)} projects | nuclei=MANUAL ONLY",
              "info", "scan", job_id)

    sem_ac = asyncio.Semaphore(max_phase_a)
    recon_results = {}

    async def recon_one(proj):
        async with sem_ac:
            try:
                res = await scan_project_recon(
                    pool, proj["id"], job_id,
                    run_subfinder=proj.get("run_subfinder", False),
                    scope=proj.get("scope"),
                )
                recon_results[proj["id"]] = res
            except Exception as e:
                await log(pool, f"{prefix}[A-C] ERROR {proj.get('name', proj['id'])}: {e}",
                          "error", "scan", job_id)
                recon_results[proj["id"]] = {"error": str(e)}

    await log(pool, f"{prefix}═══ Phase 0+A+B+C (recon) — {len(projects)} projects ═══",
              "info", "scan", job_id)
    await asyncio.gather(*[recon_one(p) for p in projects])
    await log(pool, f"{prefix}═══ Phase A+B+C complete ═══", "success", "scan", job_id)

    # ── AUTO RECON INTELLIGENCE ──────────────────────────────────────────────
    try:
        _s = load_settings()
        _auto_recon = _s.get("auto_recon_after_scan", True)
        _auto_leak  = _s.get("auto_leak_after_scan", True)
        if _auto_recon or _auto_leak:
            _mode = ("full"       if (_auto_recon and _auto_leak) else
                     "recon_only" if _auto_recon else "leak_only")
            for _proj in projects:
                _pid = _proj.get("id")
                if not _pid:
                    continue
                try:
                    _r = await enqueue(
                        job_type="recon_intel",
                        project_id=_pid,
                        priority=3,
                        payload={
                            "project_name": _proj.get("name", _pid),
                            "mode": _mode,
                            "triggered_by": "auto_post_scan",
                        },
                    )
                    await log(pool,
                        f"{prefix}[AUTO] Queued {_mode} recon for "
                        f"{_proj.get('name', _pid)} "
                        f"(job={_r.get('job_id', '?')})",
                        "info", "scan", job_id)
                except Exception as _qe:
                    await log(pool, f"{prefix}[AUTO] Queue error: {_qe}",
                              "warning", "scan", job_id)
    except Exception as _ae:
        logger.warning("Auto recon-intel trigger failed: %s", _ae)

    # ── FIX-02: Auto-nuclei uses newly_discovered from Phase B ───────────────
    # OLD (broken): checked is_new=1 after Phase C already reset it to 0
    # NEW (correct): uses newly_discovered count returned by scan_project_recon
    try:
        _s = load_settings()
        if _s.get("auto_nuclei_on_new_subs", True):
            for _proj in projects:
                _pid = _proj.get("id")
                if not _pid:
                    continue
                _res = recon_results.get(_pid, {})
                _new = _res.get("newly_discovered", 0)
                if _new and _new > 0:
                    _nr = await enqueue(
                        job_type="nuclei_only", project_id=_pid, priority=2,
                        payload={"triggered_by": "auto_new_subs", "new_count": int(_new)},
                    )
                    await log(pool,
                        f"{prefix}[AUTO-NUCLEI] {_new} newly discovered alive subs → "
                        f"nuclei queued (job={_nr.get('job_id', '?')})",
                        "info", "scan", job_id)
    except Exception as _ae:
        logger.warning("Auto-nuclei trigger error: %s", _ae)

    return {"recon_results": recon_results, "nuclei_results": {}}


async def _get_phase_pool(pool, project_id: str) -> str:
    async with pool.acquire() as conn:
        return await get_phase(conn, project_id)
