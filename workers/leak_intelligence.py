"""
workers/leak_intelligence.py — Leak Intelligence Engine v2.

PRIMARY: HackedList API (https://hackedlist.io/api/domain)
  - Queries root domain once → returns ALL subdomains with breach data
  - 1 API call covers entire project (f1soft.com.np → all 20 subs)
  - No API key required

SECONDARY (require API keys in Settings):
  - Dehashed, LeakCheck, GitHub

HaveIBeenPwned REMOVED — HackedList gives richer per-subdomain data.
"""
import asyncio
import logging
import re
from datetime import datetime, timezone
from typing import Dict, List, Optional, Set
from urllib.parse import urlparse

import aiohttp

from utils.settings import load_settings

logger = logging.getLogger("workers.leak_intelligence")

HEADERS = {
    "Accept": "application/json",
    "User-Agent": "Mozilla/5.0 (compatible; SUBMIND-PRO/8.0; security-research)",
}


# ── HackedList API (obfuscated, mirrors leakChecker.py exactly) ───────────────

def _hackedlist_api() -> str:
    return "".join(chr(x) for x in (
        104,116,116,112,115,58,47,47,
        104,97,99,107,101,100,108,105,115,116,
        46,105,111,
        47,97,112,105,47,100,111,109,97,105,110
    ))


def _extract_root_domain(subdomain: str) -> str:
    """
    Extract registrable root domain from any subdomain.
    Handles ccSLDs: f1soft.com.np → f1soft.com.np, google.com → google.com
    """
    parts = subdomain.lower().strip().split(".")
    # Known two-part ccSLDs
    ccSLD = {"com", "org", "net", "edu", "gov", "co", "ac", "or", "ne", "go"}
    if len(parts) >= 3 and parts[-2] in ccSLD:
        return ".".join(parts[-3:])   # e.g. f1soft.com.np
    elif len(parts) >= 2:
        return ".".join(parts[-2:])   # e.g. google.com
    return subdomain


def _ts(ms) -> str:
    """Convert millisecond epoch to YYYY-MM-DD (mirrors leakChecker.py ts())."""
    try:
        return datetime.fromtimestamp(float(ms) / 1000, timezone.utc).strftime("%Y-%m-%d")
    except Exception:
        return "N/A"


async def query_hackedlist(root_domain: str) -> Dict:
    """
    Query HackedList for a root domain.
    One call returns ALL subdomains with breach data.
    Mirrors leakChecker.py exactly: timeout=8s (15s here for reliability).
    """
    try:
        timeout = aiohttp.ClientTimeout(total=15)
        async with aiohttp.ClientSession(headers=HEADERS, timeout=timeout) as session:
            async with session.get(
                _hackedlist_api(),
                params={"domain": root_domain},
            ) as resp:
                if resp.status != 200:
                    logger.debug("HackedList HTTP %d for %s", resp.status, root_domain)
                    return {}
                return await resp.json()
    except asyncio.TimeoutError:
        logger.warning("[HackedList] Timeout for %s", root_domain)
        return {}
    except Exception as e:
        logger.debug("HackedList error for %s: %s", root_domain, e)
        return {}


def parse_hackedlist_for_subdomain(raw_data: Dict, subdomain: str) -> Dict:
    """
    Extract breach data for a specific subdomain from the root-domain API response.
    HackedList returns all subdomains; we match the one we need.
    """
    if not raw_data:
        return {"compromised": False, "source": "HackedList", "records": 0}

    domain_compromised = raw_data.get("compromised", False)
    all_subs = raw_data.get("subdomains", [])
    subdomain_lower = subdomain.lower().strip()

    sub_data = next(
        (s for s in all_subs if s.get("subdomain", "").lower().strip() == subdomain_lower),
        None
    )

    if sub_data is None:
        return {
            "compromised": False,
            "source": "HackedList",
            "records": 0,
            "domain_compromised": domain_compromised,
        }

    idx_time = sub_data.get("index_time", {})
    return {
        "compromised":        True,
        "source":             "HackedList",
        "records":            sub_data.get("count", 0),
        "first_seen":         _ts(idx_time.get("min", 0)),
        "last_seen":          _ts(idx_time.get("max", 0)),
        "countries":          sub_data.get("countries", []),
        "domain_compromised": domain_compromised,
        "url":                f"https://{subdomain_lower}",
        "sibling_subs": [
            {
                "subdomain":  s.get("subdomain", ""),
                "records":    s.get("count", 0),
                "first_seen": _ts(s.get("index_time", {}).get("min", 0)),
                "last_seen":  _ts(s.get("index_time", {}).get("max", 0)),
                "countries":  s.get("countries", []),
            }
            for s in all_subs
        ],
    }


# ── Secondary sources ─────────────────────────────────────────────────────────

async def check_dehashed(domain: str) -> List[Dict]:
    s = load_settings()
    email = s.get("dehashed_email", "")
    api_key = s.get("dehashed_api_key", "")
    if not email or not api_key:
        return []
    try:
        timeout = aiohttp.ClientTimeout(total=12)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.get(
                "https://api.dehashed.com/search",
                params={"query": f"domain:{domain}", "size": "20"},
                auth=aiohttp.BasicAuth(email, api_key),
                headers={"Accept": "application/json"},
            ) as resp:
                if resp.status != 200:
                    return []
                data = await resp.json()
                return [
                    {
                        "email":           e.get("email", ""),
                        "password":        e.get("password", ""),
                        "hashed_password": e.get("hashed_password", ""),
                        "database":        e.get("database_name", ""),
                        "source":          "Dehashed",
                    }
                    for e in (data.get("entries") or [])[:20]
                ]
    except Exception as e:
        logger.debug("Dehashed error %s: %s", domain, e)
        return []


async def check_leakcheck(domain: str) -> List[Dict]:
    s = load_settings()
    api_key = s.get("leakcheck_api_key", "")
    if not api_key:
        return []
    try:
        timeout = aiohttp.ClientTimeout(total=12)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.get(
                "https://leakcheck.io/api/v2/query",
                params={"query": domain, "type": "domain"},
                headers={"X-API-Key": api_key, "Accept": "application/json"},
            ) as resp:
                if resp.status != 200:
                    return []
                data = await resp.json()
                return [
                    {
                        "email":   e.get("email", ""),
                        "password": e.get("password", ""),
                        "source":  (e.get("sources") or ["LeakCheck"])[0],
                    }
                    for e in (data.get("result") or [])[:20]
                ]
    except Exception as e:
        logger.debug("LeakCheck error %s: %s", domain, e)
        return []


async def scan_github_leaks(domain: str) -> List[Dict]:
    s = load_settings()
    token = s.get("github_token", "")
    if not token:
        return []
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
    }
    findings = []
    timeout = aiohttp.ClientTimeout(total=12)
    async with aiohttp.ClientSession(headers=headers, timeout=timeout) as session:
        for query in [f'"{domain}" password', f'"{domain}" api_key']:
            try:
                async with session.get(
                    "https://api.github.com/search/code",
                    params={"q": query, "per_page": "5"},
                ) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        for item in data.get("items", []):
                            findings.append({
                                "repo":   item.get("repository", {}).get("full_name", ""),
                                "file":   item.get("name", ""),
                                "url":    item.get("html_url", ""),
                                "source": "GitHub",
                                "query":  query,
                            })
                await asyncio.sleep(1)
            except Exception:
                pass
    return findings[:10]


# ── Correlation ───────────────────────────────────────────────────────────────

def correlate_findings(leak_data: Dict, recon_data: Dict) -> Dict:
    correlations = []
    indicators = []

    has_passwords = bool(leak_data.get("passwords"))
    sensitive_eps = [
        ep for ep in recon_data.get("endpoints", [])
        if any(kw in str(ep).lower()
               for kw in ["admin", "login", "api", "dashboard", "config"])
    ]
    if has_passwords and sensitive_eps:
        correlations.append({
            "type": "CRITICAL", "risk": "critical",
            "title": "Leaked passwords + sensitive endpoints",
            "detail": f"Passwords in breach data + {len(sensitive_eps)} sensitive endpoints exposed",
        })
        indicators.append("credential_stuffing_risk")

    emails = leak_data.get("emails", [])
    ports = recon_data.get("ports", [])
    if emails and (80 in ports or 443 in ports):
        correlations.append({
            "type": "HIGH", "risk": "high",
            "title": "Leaked emails + active web services",
            "detail": f"{len(emails)} emails in leaks, service on ports {ports[:5]}",
        })
        indicators.append("account_enumeration_risk")

    secrets = recon_data.get("js_secrets", [])
    if secrets and ports:
        correlations.append({
            "type": "CRITICAL", "risk": "critical",
            "title": "API keys in JavaScript + live service",
            "detail": f"{len(secrets)} secrets in JS files on live service",
        })
        indicators.append("api_key_exposure")

    if recon_data.get("takeover", {}).get("vulnerable") and leak_data.get("compromised"):
        correlations.append({
            "type": "CRITICAL", "risk": "critical",
            "title": "Subdomain takeover + breach data",
            "detail": "Vulnerable to takeover AND has historical breach data",
        })
        indicators.append("compound_takeover_breach")

    return {
        "correlations": correlations,
        "active_risk_indicators": indicators,
        "is_actively_dangerous": any(c["risk"] == "critical" for c in correlations),
    }


# ── Project-level batch check (called by recon_worker.py) ─────────────────────

async def check_project_leaks(pool, project_id: str,
                               job_id: Optional[str] = None) -> Dict:
    """
    Check all live subdomains of a project for leaks.
    Groups by root domain → 1 HackedList call per root domain covers all subs.
    """
    from utils.log import log

    async with pool.acquire() as conn:
        live_rows = await conn.fetch(
            "SELECT subdomain FROM subdomains "
            "WHERE project_id=$1 AND is_alive=1 ORDER BY last_seen DESC",
            project_id,
        )

    if not live_rows:
        await log(pool, f"[LeakIntel] No live subdomains for {project_id}",
                  "warning", "leaks", job_id)
        return {"checked": 0, "compromised": 0}

    subdomains = [r["subdomain"] for r in live_rows]
    await log(pool, f"[LeakIntel] Checking {len(subdomains)} live subdomains",
              "info", "leaks", job_id)

    # Group by root domain → 1 HackedList call per root
    root_to_subs: Dict[str, List[str]] = {}
    for sub in subdomains:
        root = _extract_root_domain(sub)
        root_to_subs.setdefault(root, []).append(sub)

    await log(pool, f"[LeakIntel] {len(root_to_subs)} root domains to query",
              "info", "leaks", job_id)

    # Query HackedList once per root domain
    hl_cache: Dict[str, Dict] = {}
    for root in root_to_subs:
        await log(pool, f"[LeakIntel] HackedList → {root}", "info", "leaks", job_id)
        raw = await query_hackedlist(root)
        hl_cache[root] = raw
        if raw.get("compromised"):
            n = len(raw.get("subdomains", []))
            await log(pool, f"[LeakIntel] ⚠ {root} COMPROMISED — {n} subs with data",
                      "warning", "leaks", job_id)
        else:
            await log(pool, f"[LeakIntel] ✓ {root} clean", "info", "leaks", job_id)
        await asyncio.sleep(0.5)   # respectful rate limiting

    # Process each subdomain
    checked = 0
    compromised = 0
    now = datetime.now().isoformat()

    for root, subs in root_to_subs.items():
        raw_hl = hl_cache.get(root, {})

        # Secondary sources run once per root domain
        dehashed, leakcheck, github = await asyncio.gather(
            check_dehashed(root),
            check_leakcheck(root),
            scan_github_leaks(root),
            return_exceptions=True,
        )
        dehashed  = dehashed  if isinstance(dehashed, list)  else []
        leakcheck = leakcheck if isinstance(leakcheck, list) else []
        github    = github    if isinstance(github, list)    else []

        for sub in subs:
            hl = parse_hackedlist_for_subdomain(raw_hl, sub)

            # Build email list
            all_emails: List[str] = []
            seen_em: Set[str] = set()
            for r in dehashed + leakcheck:
                em = r.get("email", "")
                if em and em not in seen_em:
                    seen_em.add(em)
                    all_emails.append(em)

            # Build password list
            all_passwords: List[Dict] = []
            seen_pw: Set[str] = set()
            for r in dehashed:
                pw = r.get("password") or r.get("hashed_password", "")
                if pw and pw not in seen_pw:
                    seen_pw.add(pw)
                    all_passwords.append({
                        "value":  pw[:6] + "***" if len(pw) > 6 and not r.get("hashed_password") else pw,
                        "hashed": bool(r.get("hashed_password")),
                        "source": r.get("database", "Dehashed"),
                    })

            comp = bool(hl.get("compromised") or dehashed or leakcheck)
            sources = []
            if hl.get("compromised"):   sources.append("HackedList")
            if dehashed:                sources.append("Dehashed")
            if leakcheck:               sources.append("LeakCheck")
            if github:                  sources.append("GitHub")

            timeline = []
            if hl.get("compromised"):
                timeline.append({
                    "event":     f"Breach data — {sub}",
                    "date":      hl.get("first_seen", ""),
                    "records":   hl.get("records", 0),
                    "last_seen": hl.get("last_seen", ""),
                    "countries": hl.get("countries", []),
                })

            result = {
                "subdomain":       sub,
                "domain":          root,
                "compromised":     comp,
                "sources":         sources,
                "emails":          all_emails[:50],
                "passwords":       all_passwords[:20],
                "api_tokens":      [f"GitHub: {g.get('file','')} in {g.get('repo','')}" for g in github],
                "github_leaks":    github[:10],
                "breach_timeline": timeline,
                "hibp_breaches":   [],
                "hackedlist":      hl,
                "total_records":   hl.get("records", 0) + len(dehashed) + len(leakcheck),
                "first_seen":      hl.get("first_seen"),
                "last_seen":       hl.get("last_seen"),
                "checked_at":      now,
            }

            try:
                from db.recon_schema import upsert_leak_intel
                async with pool.acquire() as conn:
                    await upsert_leak_intel(conn, project_id, result)
            except Exception as e:
                logger.error("Failed to save leak intel for %s: %s", sub, e)

            checked += 1
            if comp:
                compromised += 1

    await log(pool, f"[LeakIntel] ✓ Done: {checked} checked, {compromised} compromised",
              "success", "leaks", job_id)
    return {"checked": checked, "compromised": compromised}


# ── Per-subdomain single check (used by API route for inline ↻ button) ────────

async def check_subdomain_leaks(subdomain: str, pool=None) -> Dict:
    """Single subdomain leak check. Used by /recon/{sub}/leak-check endpoint."""
    root = _extract_root_domain(subdomain)
    logger.info("[LeakIntel] Single check: %s (root: %s)", subdomain, root)

    raw_hl, dehashed, leakcheck, github = await asyncio.gather(
        query_hackedlist(root),
        check_dehashed(root),
        check_leakcheck(root),
        scan_github_leaks(root),
        return_exceptions=True,
    )
    raw_hl    = raw_hl    if isinstance(raw_hl, dict)    else {}
    dehashed  = dehashed  if isinstance(dehashed, list)  else []
    leakcheck = leakcheck if isinstance(leakcheck, list) else []
    github    = github    if isinstance(github, list)    else []

    hl = parse_hackedlist_for_subdomain(raw_hl, subdomain)

    all_emails: List[str] = []
    seen: Set[str] = set()
    for r in dehashed + leakcheck:
        em = r.get("email", "")
        if em and em not in seen:
            seen.add(em)
            all_emails.append(em)

    all_passwords: List[Dict] = []
    seen_pw: Set[str] = set()
    for r in dehashed:
        pw = r.get("password") or r.get("hashed_password", "")
        if pw and pw not in seen_pw:
            seen_pw.add(pw)
            all_passwords.append({
                "value":  pw[:6] + "***" if len(pw) > 6 and not r.get("hashed_password") else pw,
                "hashed": bool(r.get("hashed_password")),
                "source": r.get("database", "Dehashed"),
            })

    sources = []
    if hl.get("compromised"): sources.append("HackedList")
    if dehashed:               sources.append("Dehashed")
    if leakcheck:              sources.append("LeakCheck")
    if github:                 sources.append("GitHub")

    comp = bool(hl.get("compromised") or dehashed or leakcheck)

    return {
        "subdomain":       subdomain,
        "domain":          root,
        "compromised":     comp,
        "sources":         sources,
        "emails":          all_emails[:50],
        "passwords":       all_passwords[:20],
        "api_tokens":      [f"GitHub: {g.get('file','')} in {g.get('repo','')}" for g in github],
        "github_leaks":    github[:10],
        "breach_timeline": [{"event": "Breach data", "date": hl.get("first_seen",""),
                              "records": hl.get("records",0), "last_seen": hl.get("last_seen","")}]
                           if hl.get("compromised") else [],
        "hibp_breaches":   [],
        "hackedlist":      hl,
        "total_records":   hl.get("records", 0) + len(dehashed) + len(leakcheck),
        "first_seen":      hl.get("first_seen"),
        "last_seen":       hl.get("last_seen"),
        "checked_at":      datetime.now().isoformat(),
    }
