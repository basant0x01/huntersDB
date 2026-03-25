"""
workers/recon_intelligence.py — Parallel Recon Intelligence Engine v3

NEW in v3 (aligned with feature plan):
  + Email security   → SPF, DMARC, DKIM via dig
  + WAF detection    → wafw00f
  + 403 bypass       → auto-detect 403 endpoints, attempt bypass
  + Origin IP        → Shodan API (requires shodan API key in settings)
  + Hidden params    → arjun (passive mode, no brute-force)
  + HTTP header issues → check for missing security headers
  + JS CVEs          → retire.js (npm global)

Tools ordered by phase:
  Phase 1 — network / crawl / archive (parallel):
    naabu, katana, gau, waybackurls, nuclei-takeover, screenshot,
    wafw00f, email_security

  Phase 2 — content analysis (parallel, uses Phase 1 data):
    linkfinder, trufflehog, gitleaks, ffuf, broken_links,
    arjun (hidden params), header_check, retirejs

  Phase 3 — post-analysis:
    403_bypass (on ffuf 403 hits), origin_ip (Shodan)
"""
import asyncio
import json
import logging
import re
import shutil
import subprocess
import uuid
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import aiohttp

from config.settings import CHAOS_DIR, BASE_DIR
from process_manager.manager import manager
from task_queue.redis_queue import set_scan_progress, get_scan_progress
from utils.log import log
from utils.settings import load_settings

logger = logging.getLogger("workers.recon_intelligence")

# ── Timeouts ───────────────────────────────────────────────────────────────────
NAABU_TIMEOUT      = 120
FFUF_TIMEOUT       = 300
KATANA_TIMEOUT     = 300
HAKRAWLER_TIMEOUT  = 180
LINKFINDER_TIMEOUT = 120
TRUFFLEHOG_TIMEOUT = 180
GAU_TIMEOUT        = 120
WAYBACK_TIMEOUT    = 120
TAKEOVER_TIMEOUT   = 120
SCREENSHOT_TIMEOUT = 30
WAFWOOF_TIMEOUT    = 30
EMAIL_SEC_TIMEOUT  = 15
ARJUN_TIMEOUT      = 120
BYPASS_TIMEOUT     = 30
RETIREJS_TIMEOUT   = 60

TOP_PORTS = "80,443,8080,8443,8000,8888,3000,5000,9000,9090"

SENSITIVE_KW = [
    "admin", "api", "auth", "backup", "config", "console", "dashboard",
    "debug", ".env", "graphql", "internal", "key", "login", "passwd",
    "password", "private", "secret", "swagger", "token", "upload",
]

WORDLIST_PATH = BASE_DIR / "wordlists" / "quickhits.txt"

# Security headers that should be present
REQUIRED_HEADERS = {
    "x-frame-options":           "Clickjacking protection",
    "x-content-type-options":    "MIME sniffing protection",
    "strict-transport-security": "HSTS",
    "content-security-policy":   "CSP",
    "x-xss-protection":          "XSS filter",
    "referrer-policy":           "Referrer policy",
    "permissions-policy":        "Permissions policy",
}


# ── Tool progress reporter ─────────────────────────────────────────────────────

async def _tool_status(project_id: Optional[str], subdomain: str,
                        tool: str, status: str, result_count: int = 0,
                        pool=None) -> None:
    if not project_id:
        return
    try:
        current = await get_scan_progress(project_id) or {}
        tools = current.get("tools", {})
        tools[tool] = {
            "status":  status,
            "count":   result_count,
            "ts":      datetime.now().isoformat(),
            "sub":     subdomain,
        }
        current["tools"] = tools
        current["phase"] = "recon_intel"
        await set_scan_progress(project_id, current)
    except Exception:
        pass


# ── Naabu — Port Scanner ──────────────────────────────────────────────────────

async def run_naabu(subdomain: str, job_id: Optional[str] = None,
                    project_id: Optional[str] = None, pool=None) -> List[int]:
    await _tool_status(project_id, subdomain, "naabu", "running", pool=pool)
    uid      = uuid.uuid4().hex
    out_file = CHAOS_DIR / f"naabu_{uid}.json"
    cmd = [
        "naabu", "-host", subdomain,
        "-p", TOP_PORTS,
        "-json", "-silent",
        "-o", str(out_file),
        "-timeout", "10",
        "-retries", "1",
        "-rate",    "300",
    ]
    try:
        await manager.run(name=f"naabu_{subdomain[:20]}", cmd=cmd,
                          timeout_secs=NAABU_TIMEOUT)
        ports: List[int] = []
        if out_file.exists():
            for line in (await asyncio.to_thread(out_file.read_text, errors="ignore")).splitlines():
                try:
                    d = json.loads(line)
                    p = d.get("port") or d.get("Port")
                    if p:
                        ports.append(int(p))
                except Exception:
                    pass
        ports = sorted(set(ports))
        await _tool_status(project_id, subdomain, "naabu", "done", len(ports), pool)
        return ports
    except Exception as e:
        logger.error("naabu %s: %s", subdomain, e)
        await _tool_status(project_id, subdomain, "naabu", "error", pool=pool)
        return []
    finally:
        try:
            await asyncio.to_thread(out_file.unlink, missing_ok=True)
        except Exception:
            pass


# ── WAF Detection — wafw00f ───────────────────────────────────────────────────

async def run_wafw00f(url: str, job_id: Optional[str] = None,
                      project_id: Optional[str] = None, pool=None) -> Dict:
    """
    Detect WAF using wafw00f.
    Returns {"detected": bool, "waf": str, "manufacturer": str}
    """
    await _tool_status(project_id, url[:30], "waf", "running", pool=pool)
    try:
        rc, stdout, stderr = await manager.run(
            name=f"wafw00f_{url[:20]}",
            cmd=["wafw00f", url, "-a", "-o", "-"],
            timeout_secs=WAFWOOF_TIMEOUT,
            capture_stdout=True,
            capture_stderr=True,
        )
        if rc == -127:
            await _tool_status(project_id, url[:30], "waf", "skipped", pool=pool)
            return {"detected": False, "waf": "", "manufacturer": ""}

        output = stdout.decode("utf-8", errors="replace")
        waf_name = ""
        manufacturer = ""
        detected = False

        for line in output.splitlines():
            line = line.strip()
            # wafw00f output format: "The site <url> is behind <WAF> WAF."
            if "is behind" in line.lower():
                detected = True
                m = re.search(r"is behind (.+?) WAF", line, re.I)
                if m:
                    waf_name = m.group(1).strip()
            if "identified as" in line.lower():
                m = re.search(r"identified as (.+)", line, re.I)
                if m:
                    manufacturer = m.group(1).strip()

        result = {"detected": detected, "waf": waf_name, "manufacturer": manufacturer}
        await _tool_status(project_id, url[:30], "waf",
                           "done", 1 if detected else 0, pool)
        return result
    except Exception as e:
        logger.debug("wafw00f %s: %s", url, e)
        await _tool_status(project_id, url[:30], "waf", "error", pool=pool)
        return {"detected": False, "waf": "", "manufacturer": ""}


# ── Email Security — SPF / DMARC / DKIM via dig ───────────────────────────────

async def check_email_security(subdomain: str,
                                job_id: Optional[str] = None,
                                project_id: Optional[str] = None,
                                pool=None) -> Dict:
    """
    Check SPF, DMARC, and DKIM records for a domain.
    Uses dig (DNS lookup) — no external API required.
    Returns findings dict ready for storage.
    """
    await _tool_status(project_id, subdomain, "email_security", "running", pool=pool)

    # Extract root domain (email security checks are domain-level, not subdomain)
    parts = subdomain.split(".")
    if len(parts) >= 2:
        root_domain = ".".join(parts[-2:])
    else:
        root_domain = subdomain

    result = {
        "domain":        root_domain,
        "spf_record":    "",
        "spf_missing":   True,
        "spf_policy":    "",
        "dmarc_record":  "",
        "dmarc_missing": True,
        "dmarc_policy":  "none",
        "dkim_found":    False,
        "issues":        [],
    }

    async def _dig(query_type: str, name: str) -> str:
        try:
            rc, stdout, _ = await manager.run(
                name=f"dig_{name[:20]}",
                cmd=["dig", "+short", query_type, name],
                timeout_secs=10,
                capture_stdout=True,
            )
            return stdout.decode("utf-8", errors="replace").strip()
        except Exception:
            return ""

    try:
        # SPF check
        txt_records = await _dig("TXT", root_domain)
        for line in txt_records.splitlines():
            if "v=spf1" in line.lower():
                result["spf_record"] = line.strip().strip('"')
                result["spf_missing"] = False
                # Extract policy (all mechanism)
                m = re.search(r"([~\-\+\?])all", line, re.I)
                if m:
                    policy_map = {"-": "fail", "~": "softfail", "+": "pass", "?": "neutral"}
                    result["spf_policy"] = policy_map.get(m.group(1), "")
                break

        if result["spf_missing"]:
            result["issues"].append("SPF record missing — domain vulnerable to email spoofing")
        elif result["spf_policy"] in ("", "pass", "neutral"):
            result["issues"].append(f"SPF policy too permissive: '{result['spf_policy']}'")

        # DMARC check
        dmarc_records = await _dig("TXT", f"_dmarc.{root_domain}")
        for line in dmarc_records.splitlines():
            if "v=dmarc1" in line.lower():
                result["dmarc_record"] = line.strip().strip('"')
                result["dmarc_missing"] = False
                m = re.search(r"p=(\w+)", line, re.I)
                if m:
                    result["dmarc_policy"] = m.group(1).lower()
                break

        if result["dmarc_missing"]:
            result["issues"].append("DMARC record missing — no email authentication policy")
        elif result["dmarc_policy"] == "none":
            result["issues"].append("DMARC policy is 'none' — emails not rejected/quarantined")

        # DKIM check (common selectors)
        dkim_selectors = ["default", "google", "mail", "k1", "s1", "s2", "selector1", "selector2"]
        for selector in dkim_selectors:
            dkim_record = await _dig("TXT", f"{selector}._domainkey.{root_domain}")
            if "v=dkim1" in dkim_record.lower() or "p=" in dkim_record:
                result["dkim_found"] = True
                break

        if not result["dkim_found"]:
            result["issues"].append("DKIM not detected (common selectors checked)")

        count = len(result["issues"])
        await _tool_status(project_id, subdomain, "email_security",
                           "done", count, pool)
        return result

    except Exception as e:
        logger.debug("email_security %s: %s", subdomain, e)
        await _tool_status(project_id, subdomain, "email_security", "error", pool=pool)
        return result


# ── HTTP Security Headers Check ───────────────────────────────────────────────

async def check_security_headers(url: str,
                                  job_id: Optional[str] = None,
                                  project_id: Optional[str] = None,
                                  pool=None) -> List[Dict]:
    """
    Check for missing/misconfigured HTTP security headers.
    Returns list of issues: [{header, issue, severity}]
    """
    await _tool_status(project_id, url[:30], "headers", "running", pool=pool)
    issues: List[Dict] = []
    try:
        timeout = aiohttp.ClientTimeout(total=10)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.get(url, ssl=False, allow_redirects=True) as resp:
                headers = {k.lower(): v for k, v in resp.headers.items()}

                for header, description in REQUIRED_HEADERS.items():
                    if header not in headers:
                        issues.append({
                            "header":      header,
                            "issue":       f"Missing: {description}",
                            "severity":    "medium",
                            "present":     False,
                        })

                # Check for information-leaking headers
                for leak_header in ("server", "x-powered-by", "x-aspnet-version",
                                    "x-aspnetmvc-version"):
                    if leak_header in headers:
                        issues.append({
                            "header":   leak_header,
                            "issue":    f"Exposes server info: {headers[leak_header][:80]}",
                            "severity": "low",
                            "present":  True,
                            "value":    headers[leak_header][:80],
                        })

        await _tool_status(project_id, url[:30], "headers",
                           "done", len(issues), pool)
        return issues
    except Exception as e:
        logger.debug("header_check %s: %s", url, e)
        await _tool_status(project_id, url[:30], "headers", "error", pool=pool)
        return []


# ── 403 Bypass ────────────────────────────────────────────────────────────────

async def attempt_403_bypass(url: str, paths: List[str],
                              job_id: Optional[str] = None,
                              project_id: Optional[str] = None,
                              pool=None) -> List[Dict]:
    """
    For each path that returned 403, attempt common bypass techniques.
    Returns list of bypassed paths: [{path, bypass_method, status}]
    """
    await _tool_status(project_id, url[:30], "bypass_403", "running", pool=pool)
    if not paths:
        await _tool_status(project_id, url[:30], "bypass_403", "skipped", pool=pool)
        return []

    bypassed: List[Dict] = []
    base = url.rstrip("/")

    # Common bypass payloads
    BYPASS_VARIANTS = [
        lambda p: f"{p}%20",
        lambda p: f"{p}/..",
        lambda p: f"{p}//",
        lambda p: f"/{p[1:]}",           # remove leading slash variant
        lambda p: f"{p}%2f",
        lambda p: f"{p};/",
        lambda p: f"{p}..;/",
    ]
    BYPASS_HEADERS = [
        {"X-Original-URL": "{path}"},
        {"X-Rewrite-URL": "{path}"},
        {"X-Custom-IP-Authorization": "127.0.0.1"},
        {"X-Forwarded-For": "127.0.0.1"},
        {"X-Remote-IP": "127.0.0.1"},
        {"X-Originating-IP": "127.0.0.1"},
    ]

    timeout = aiohttp.ClientTimeout(total=8)
    sem = asyncio.Semaphore(5)

    async def _try(path: str, bypass_url: str, method_name: str,
                   extra_headers: Dict = None) -> Optional[Dict]:
        async with sem:
            try:
                hdrs = extra_headers or {}
                async with aiohttp.ClientSession(timeout=timeout) as session:
                    async with session.get(
                        bypass_url, headers=hdrs, ssl=False, allow_redirects=False
                    ) as resp:
                        if resp.status == 200:
                            return {
                                "path":           path,
                                "bypass_method":  method_name,
                                "bypass_url":     bypass_url,
                                "status":         resp.status,
                                "content_length": resp.headers.get("content-length", "?"),
                            }
            except Exception:
                pass
            return None

    tasks = []
    for path in paths[:20]:  # cap at 20 paths
        for variant_fn in BYPASS_VARIANTS:
            try:
                variant_path = variant_fn(path)
                bypass_url = f"{base}{variant_path}"
                tasks.append(_try(path, bypass_url, f"path_variant:{variant_path}"))
            except Exception:
                pass
        for hdr_template in BYPASS_HEADERS:
            hdrs = {k: v.replace("{path}", path) for k, v in hdr_template.items()}
            method_name = f"header:{list(hdr_template.keys())[0]}"
            tasks.append(_try(path, f"{base}{path}", method_name, hdrs))

    results = await asyncio.gather(*tasks, return_exceptions=True)
    for r in results:
        if r and isinstance(r, dict):
            bypassed.append(r)

    await _tool_status(project_id, url[:30], "bypass_403",
                       "done", len(bypassed), pool)
    return bypassed


# ── Origin IP Detection — Shodan ──────────────────────────────────────────────

async def get_origin_ip(subdomain: str,
                         job_id: Optional[str] = None,
                         project_id: Optional[str] = None,
                         pool=None) -> str:
    """
    Detect real origin IP behind CDN using Shodan API.
    Requires shodan API key in settings.
    Returns IP string or empty string.
    """
    await _tool_status(project_id, subdomain, "origin_ip", "running", pool=pool)
    s = load_settings()
    shodan_key = s.get("shodan_api_key", "") or s.get("censys_api_id", "")  # fallback

    if not shodan_key:
        await _tool_status(project_id, subdomain, "origin_ip", "skipped", pool=pool)
        return ""

    try:
        timeout = aiohttp.ClientTimeout(total=10)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.get(
                f"https://api.shodan.io/dns/resolve?hostnames={subdomain}&key={shodan_key}"
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    ip = data.get(subdomain, "")
                    if ip:
                        await _tool_status(project_id, subdomain, "origin_ip",
                                           "done", 1, pool)
                        return str(ip)

        await _tool_status(project_id, subdomain, "origin_ip", "done", 0, pool)
        return ""
    except Exception as e:
        logger.debug("origin_ip %s: %s", subdomain, e)
        await _tool_status(project_id, subdomain, "origin_ip", "error", pool=pool)
        return ""


# ── Hidden Params — arjun ─────────────────────────────────────────────────────

async def run_arjun(url: str, job_id: Optional[str] = None,
                    project_id: Optional[str] = None,
                    pool=None) -> List[str]:
    """
    Discover hidden HTTP parameters using arjun (passive/light mode).
    Returns list of parameter names.
    """
    await _tool_status(project_id, url[:30], "arjun", "running", pool=pool)
    uid      = uuid.uuid4().hex
    out_file = CHAOS_DIR / f"arjun_{uid}.json"
    cmd = [
        "arjun",
        "-u", url,
        "-oJ", str(out_file),
        "--passive",      # passive — no brute force, uses wayback
        "-t", "5",
        "--timeout", "10",
    ]
    try:
        rc, _, _ = await manager.run(
            name=f"arjun_{url[:20]}", cmd=cmd, timeout_secs=ARJUN_TIMEOUT)
        if rc == -127:
            await _tool_status(project_id, url[:30], "arjun", "skipped", pool=pool)
            return []

        params: List[str] = []
        if out_file.exists():
            try:
                data = json.loads(await asyncio.to_thread(
                    out_file.read_text, errors="ignore"))
                # arjun outputs: {url: [params...]} or {url: {params: [...]}}
                for v in data.values():
                    if isinstance(v, list):
                        params.extend(v)
                    elif isinstance(v, dict):
                        params.extend(v.get("params", []))
            except Exception:
                pass

        params = list(dict.fromkeys(params))[:50]
        await _tool_status(project_id, url[:30], "arjun", "done", len(params), pool)
        return params
    except Exception as e:
        logger.debug("arjun %s: %s", url, e)
        await _tool_status(project_id, url[:30], "arjun", "error", pool=pool)
        return []
    finally:
        try:
            await asyncio.to_thread(out_file.unlink, missing_ok=True)
        except Exception:
            pass


# ── Retire.js — JS Library CVEs ───────────────────────────────────────────────

async def run_retirejs(js_urls: List[str], subdomain: str,
                        job_id: Optional[str] = None,
                        project_id: Optional[str] = None,
                        pool=None) -> List[Dict]:
    """
    Check JS libraries for known CVEs using retire.js.
    Requires: npm install -g retire
    """
    await _tool_status(project_id, subdomain, "retirejs", "running", pool=pool)
    if not js_urls:
        await _tool_status(project_id, subdomain, "retirejs", "skipped", pool=pool)
        return []

    uid    = uuid.uuid4().hex
    js_dir = CHAOS_DIR / f"retire_{uid}"
    js_dir.mkdir(parents=True, exist_ok=True)
    vulns: List[Dict] = []

    try:
        # Download JS files
        timeout = aiohttp.ClientTimeout(total=10)
        async with aiohttp.ClientSession(timeout=timeout) as sess:
            for js_url in js_urls[:10]:
                try:
                    fname = re.sub(r"[^a-z0-9_]", "_", js_url[-30:].lower()) + ".js"
                    fpath = js_dir / fname
                    async with sess.get(js_url, ssl=False) as resp:
                        if resp.status == 200:
                            content = await resp.read()
                            await asyncio.to_thread(fpath.write_bytes, content)
                except Exception:
                    pass

        js_files = list(js_dir.glob("*.js"))
        if not js_files:
            await _tool_status(project_id, subdomain, "retirejs", "skipped", pool=pool)
            return []

        rc, stdout, _ = await manager.run(
            name=f"retire_{subdomain[:15]}",
            cmd=["retire", "--path", str(js_dir), "--outputformat", "json",
                 "--exitwith", "0"],
            timeout_secs=RETIREJS_TIMEOUT,
            capture_stdout=True,
        )
        if rc == -127:
            await _tool_status(project_id, subdomain, "retirejs", "skipped", pool=pool)
            return []

        if stdout:
            try:
                data = json.loads(stdout.decode("utf-8", errors="replace"))
                for entry in data:
                    for result in entry.get("results", []):
                        for vuln in result.get("vulnerabilities", []):
                            vulns.append({
                                "component": result.get("component", ""),
                                "version":   result.get("version", ""),
                                "severity":  vuln.get("severity", "unknown"),
                                "summary":   vuln.get("identifiers", {}).get("summary", ""),
                                "cve":       vuln.get("identifiers", {}).get("CVE", []),
                            })
            except Exception:
                pass

        await _tool_status(project_id, subdomain, "retirejs", "done", len(vulns), pool)
        return vulns
    except Exception as e:
        logger.debug("retirejs %s: %s", subdomain, e)
        await _tool_status(project_id, subdomain, "retirejs", "error", pool=pool)
        return []
    finally:
        try:
            shutil.rmtree(js_dir, ignore_errors=True)
        except Exception:
            pass


# ── ffuf — Directory & File Discovery ────────────────────────────────────────

async def run_ffuf(url: str, job_id: Optional[str] = None,
                   project_id: Optional[str] = None, pool=None) -> Tuple[List[Dict], List[str]]:
    """
    Dir/file fuzzing. Returns (all_results, forbidden_paths).
    Forbidden paths (403) are returned separately for bypass attempts.
    """
    await _tool_status(project_id, url[:30], "ffuf", "running", pool=pool)

    wordlist = WORDLIST_PATH
    if not wordlist.exists():
        wordlist.parent.mkdir(parents=True, exist_ok=True)
        builtin = [
            "admin", "api", "backup", "config", "dashboard", ".env", ".git",
            "login", "swagger", "actuator", "actuator/health", "actuator/env",
            "graphql", "graphiql", "console", "phpmyadmin", "robots.txt",
            "sitemap.xml", ".well-known", "server-status", "health",
        ]
        await asyncio.to_thread(wordlist.write_text, "\n".join(builtin))

    uid      = uuid.uuid4().hex
    out_file = CHAOS_DIR / f"ffuf_{uid}.json"
    cmd = [
        "ffuf",
        "-u",  f"{url.rstrip('/')}/FUZZ",
        "-w",  str(wordlist),
        "-o",  str(out_file), "-of", "json",
        # Include 403 hits so we can attempt bypass
        "-mc", "200,403",
        "-ac",
        "-fs", "0",
        "-t",  "8",
        "-timeout", "8",
        "-maxtime", "240",
        "-silent", "-ic",
        "-r",
    ]
    try:
        await manager.run(name=f"ffuf_{url[:20]}", cmd=cmd,
                          timeout_secs=FFUF_TIMEOUT)
        results: List[Dict] = []
        forbidden_paths: List[str] = []

        if out_file.exists():
            try:
                data = json.loads(await asyncio.to_thread(
                    out_file.read_text, errors="ignore"))
                for r in data.get("results", []):
                    path   = r.get("input", {}).get("FUZZ", "")
                    status = r.get("status", 0)
                    entry = {
                        "path":      path,
                        "status":    status,
                        "length":    r.get("length"),
                        "url":       r.get("url", ""),
                        "sensitive": any(kw in path.lower() for kw in SENSITIVE_KW),
                    }
                    results.append(entry)
                    if status == 403:
                        forbidden_paths.append(f"/{path}")
            except Exception as e:
                logger.debug("ffuf parse %s: %s", url, e)

        await _tool_status(project_id, url[:30], "ffuf", "done", len(results), pool)
        return results, forbidden_paths
    except Exception as e:
        logger.error("ffuf %s: %s", url, e)
        await _tool_status(project_id, url[:30], "ffuf", "error", pool=pool)
        return [], []
    finally:
        try:
            await asyncio.to_thread(out_file.unlink, missing_ok=True)
        except Exception:
            pass


# ── Playwright Screenshot ─────────────────────────────────────────────────────

async def take_screenshot(url: str, subdomain: str,
                           job_id: Optional[str] = None,
                           project_id: Optional[str] = None,
                           pool=None) -> Optional[str]:
    s = load_settings()
    if s.get("httpx_screenshot", True) is False:
        await _tool_status(project_id, subdomain, "screenshot", "skipped", pool=pool)
        return None

    await _tool_status(project_id, subdomain, "screenshot", "running", pool=pool)

    screenshots_dir = BASE_DIR / "screenshots"
    screenshots_dir.mkdir(parents=True, exist_ok=True)
    safe     = re.sub(r"[^a-z0-9\-]", "_", subdomain.lower())
    out_path = screenshots_dir / f"{safe}.png"

    def _capture() -> Optional[str]:
        try:
            from playwright.sync_api import sync_playwright, TimeoutError as PWTimeout
            with sync_playwright() as pw:
                browser = pw.chromium.launch(
                    headless=True,
                    args=[
                        "--no-sandbox", "--disable-setuid-sandbox",
                        "--disable-dev-shm-usage", "--disable-gpu",
                        "--ignore-certificate-errors",
                    ],
                )
                ctx  = browser.new_context(
                    ignore_https_errors=True,
                    viewport={"width": 1280, "height": 800},
                    user_agent=(
                        "Mozilla/5.0 (X11; Linux x86_64) "
                        "AppleWebKit/537.36 (KHTML, like Gecko) "
                        "Chrome/120.0.0.0 Safari/537.36"
                    ),
                )
                page = ctx.new_page()
                try:
                    page.goto(url, wait_until="domcontentloaded", timeout=15000)
                    page.wait_for_timeout(1500)
                    page.screenshot(path=str(out_path), full_page=False, timeout=8000)
                    return str(out_path)
                except PWTimeout:
                    return None
                except Exception:
                    return None
                finally:
                    browser.close()
        except Exception:
            return None

    try:
        result = await asyncio.wait_for(
            asyncio.to_thread(_capture),
            timeout=SCREENSHOT_TIMEOUT,
        )
        await _tool_status(project_id, subdomain, "screenshot",
                           "done" if result else "error", pool=pool)
        return result
    except asyncio.TimeoutError:
        await _tool_status(project_id, subdomain, "screenshot", "error", pool=pool)
        return None
    except Exception:
        await _tool_status(project_id, subdomain, "screenshot", "error", pool=pool)
        return None


# ── Nuclei Takeover Detection ─────────────────────────────────────────────────

async def run_takeover_check(subdomain: str, job_id: Optional[str] = None,
                              project_id: Optional[str] = None,
                              pool=None) -> Dict:
    await _tool_status(project_id, subdomain, "takeover", "running", pool=pool)

    uid      = uuid.uuid4().hex
    out_file = CHAOS_DIR / f"takeover_{uid}.json"
    cmd = [
        "nuclei",
        "-target", f"https://{subdomain}",
        "-t",      "dns/takeovers",
        "-jsonl",
        "-o",      str(out_file),
        "-silent",
        "-timeout", "10",
        "-retries", "1",
        "-rl",     "10",
    ]
    try:
        rc, _, _ = await manager.run(
            name=f"nuclei_takeover_{subdomain[:20]}",
            cmd=cmd,
            timeout_secs=TAKEOVER_TIMEOUT,
        )

        if out_file.exists():
            content = await asyncio.to_thread(out_file.read_text, errors="ignore")
            for line in content.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    d = json.loads(line)
                    if d.get("severity") in ("high", "critical", "medium"):
                        result = {
                            "vulnerable":   True,
                            "service":      d.get("template-id", ""),
                            "cname":        d.get("host", subdomain),
                            "fingerprint":  d.get("matcher-name", ""),
                            "severity":     d.get("severity", "high"),
                        }
                        await _tool_status(project_id, subdomain, "takeover", "done", 1, pool)
                        return result
                except Exception:
                    pass

        await _tool_status(project_id, subdomain, "takeover", "done", 0, pool)
        return {"vulnerable": False}

    except Exception as e:
        logger.debug("takeover check %s: %s", subdomain, e)
        await _tool_status(project_id, subdomain, "takeover", "error", pool=pool)
        return {"vulnerable": False}
    finally:
        try:
            await asyncio.to_thread(out_file.unlink, missing_ok=True)
        except Exception:
            pass


# ── Katana + Hakrawler ────────────────────────────────────────────────────────

async def run_katana(url: str, job_id: Optional[str] = None,
                     project_id: Optional[str] = None,
                     pool=None) -> Tuple[List[str], int]:
    await _tool_status(project_id, url[:30], "katana", "running", pool=pool)
    uid      = uuid.uuid4().hex
    out_file = CHAOS_DIR / f"katana_{uid}.txt"
    cmd = [
        "katana", "-u", url,
        "-o", str(out_file),
        "-silent", "-no-color",
        "-depth", "2",
        "-timeout", "15",
        "-c", "5",
        "-js-crawl",
    ]
    try:
        rc, _, _ = await manager.run(
            name=f"katana_{url[:20]}", cmd=cmd, timeout_secs=KATANA_TIMEOUT)
        urls: List[str] = []
        if out_file.exists():
            urls = [l.strip() for l in
                    (await asyncio.to_thread(out_file.read_text, errors="ignore"))
                    .splitlines() if l.strip()]
        await _tool_status(project_id, url[:30], "katana", "done", len(urls), pool)
        return urls, rc
    except Exception as e:
        logger.debug("katana %s: %s", url, e)
        await _tool_status(project_id, url[:30], "katana", "error", pool=pool)
        return [], -1
    finally:
        try:
            await asyncio.to_thread(out_file.unlink, missing_ok=True)
        except Exception:
            pass


async def run_hakrawler(url: str, job_id: Optional[str] = None,
                        project_id: Optional[str] = None,
                        pool=None) -> List[str]:
    await _tool_status(project_id, url[:30], "hakrawler", "running", pool=pool)
    try:
        rc, stdout, _ = await manager.run(
            name=f"hakrawler_{url[:20]}",
            cmd=["hakrawler", "-d", "2", "-t", "5", "-insecure"],
            timeout_secs=HAKRAWLER_TIMEOUT,
            stdin_data=f"{url}\n".encode(),
            capture_stdout=True,
        )
        if rc == -127:
            await _tool_status(project_id, url[:30], "hakrawler", "skipped", pool=pool)
            return []
        urls = [l.strip() for l in
                stdout.decode("utf-8", errors="replace").splitlines()
                if l.strip() and l.startswith("http")]
        await _tool_status(project_id, url[:30], "hakrawler", "done", len(urls), pool)
        return urls
    except Exception as e:
        logger.debug("hakrawler %s: %s", url, e)
        await _tool_status(project_id, url[:30], "hakrawler", "error", pool=pool)
        return []


async def run_crawler(url: str, job_id: Optional[str] = None,
                      project_id: Optional[str] = None,
                      pool=None) -> List[str]:
    urls, rc = await run_katana(url, job_id, project_id, pool)
    if rc == -127:
        urls = await run_hakrawler(url, job_id, project_id, pool)
    return urls


# ── Trufflehog ────────────────────────────────────────────────────────────────

async def run_trufflehog_on_js(js_urls: List[str], subdomain: str,
                                job_id: Optional[str] = None,
                                project_id: Optional[str] = None,
                                pool=None) -> List[Dict]:
    await _tool_status(project_id, subdomain, "trufflehog", "running", pool=pool)
    if not js_urls:
        await _tool_status(project_id, subdomain, "trufflehog", "skipped", pool=pool)
        return []

    uid    = uuid.uuid4().hex
    js_dir = CHAOS_DIR / f"js_{uid}"
    js_dir.mkdir(parents=True, exist_ok=True)
    secrets: List[Dict] = []

    try:
        timeout = aiohttp.ClientTimeout(total=10)
        async with aiohttp.ClientSession(timeout=timeout) as sess:
            for js_url in js_urls[:10]:
                try:
                    fname = re.sub(r"[^a-z0-9_]", "_", js_url[-30:].lower()) + ".js"
                    fpath = js_dir / fname
                    async with sess.get(js_url, ssl=False) as resp:
                        if resp.status == 200:
                            content = await resp.read()
                            await asyncio.to_thread(fpath.write_bytes, content)
                except Exception:
                    pass

        js_files = list(js_dir.glob("*.js"))
        if not js_files:
            await _tool_status(project_id, subdomain, "trufflehog", "skipped", pool=pool)
            return []

        rc, stdout, _ = await manager.run(
            name=f"trufflehog_{subdomain[:15]}",
            cmd=["trufflehog", "filesystem", str(js_dir), "--json", "--no-update"],
            timeout_secs=TRUFFLEHOG_TIMEOUT,
            capture_stdout=True,
        )
        if stdout:
            for line in stdout.decode("utf-8", errors="replace").splitlines():
                try:
                    d = json.loads(line)
                    raw = d.get("Raw") or d.get("raw", "")
                    if raw:
                        secrets.append({
                            "type":   d.get("DetectorName") or d.get("type", "secret"),
                            "raw":    raw[:120],
                            "source": d.get("SourceName") or d.get("source", ""),
                        })
                except Exception:
                    pass

        await _tool_status(project_id, subdomain, "trufflehog", "done", len(secrets), pool)
        return secrets
    except Exception as e:
        logger.debug("trufflehog %s: %s", subdomain, e)
        await _tool_status(project_id, subdomain, "trufflehog", "error", pool=pool)
        return []
    finally:
        try:
            shutil.rmtree(js_dir, ignore_errors=True)
        except Exception:
            pass


# ── Gitleaks Regex ────────────────────────────────────────────────────────────

async def run_gitleaks_regex(js_urls: List[str],
                              job_id: Optional[str] = None,
                              project_id: Optional[str] = None,
                              pool=None) -> List[Dict]:
    await _tool_status(project_id, "", "gitleaks", "running", pool=pool)
    PATTERNS = [
        (r"(?i)(api[_\-]?key|apikey|secret|token|password|passwd|auth)['\"]?\s*[:=]\s*['\"]([a-z0-9\-_]{16,})['\"]", "api_key"),
        (r"AKIA[0-9A-Z]{16}", "aws_access_key"),
        (r"(?i)bearer\s+([a-zA-Z0-9\-_.]{20,})", "bearer_token"),
        (r"-----BEGIN (RSA|EC|DSA|OPENSSH) PRIVATE KEY-----", "private_key"),
        (r"(?i)(ghp|gho|ghu|ghs|ghr)_[a-zA-Z0-9]{36}", "github_token"),
    ]
    secrets: List[Dict] = []
    seen: set = set()
    timeout = aiohttp.ClientTimeout(total=8)
    try:
        async with aiohttp.ClientSession(timeout=timeout) as sess:
            for url in js_urls[:8]:
                try:
                    async with sess.get(url, ssl=False) as resp:
                        if resp.status == 200:
                            text = await resp.text(errors="ignore")
                            for pattern, stype in PATTERNS:
                                for m in re.finditer(pattern, text):
                                    raw = m.group(0)[:80]
                                    if raw not in seen:
                                        seen.add(raw)
                                        secrets.append({"type": stype, "raw": raw, "source": url})
                except Exception:
                    pass
    except Exception:
        pass
    await _tool_status(project_id, "", "gitleaks", "done", len(secrets), pool)
    return secrets


# ── LinkFinder ────────────────────────────────────────────────────────────────

async def run_linkfinder(url: str, crawled_urls: List[str],
                          job_id: Optional[str] = None,
                          project_id: Optional[str] = None,
                          pool=None) -> List[str]:
    await _tool_status(project_id, url[:30], "linkfinder", "running", pool=pool)
    endpoints: List[str] = []
    js_urls = [u for u in crawled_urls if ".js" in u and "?" not in u][:5]

    for js_url in js_urls:
        try:
            rc, stdout, _ = await manager.run(
                name=f"lf_{url[:15]}",
                cmd=["python3", "-m", "linkfinder", "-i", js_url, "-o", "cli", "-d"],
                timeout_secs=LINKFINDER_TIMEOUT,
                capture_stdout=True,
            )
            if stdout:
                for ep in stdout.decode("utf-8", errors="replace").splitlines():
                    ep = ep.strip()
                    if ep and ep.startswith("/") and len(ep) > 1:
                        endpoints.append(ep)
        except Exception:
            pass

    # Regex fallback
    pattern = re.compile(
        r"""(?:["'])((?:[a-z]{4,5}://|//|/)[^"'<>\s]{5,}?)(?:["'])""",
        re.IGNORECASE
    )
    timeout = aiohttp.ClientTimeout(total=8)
    try:
        async with aiohttp.ClientSession(timeout=timeout) as sess:
            for js_url in js_urls[:3]:
                try:
                    async with sess.get(js_url, ssl=False) as resp:
                        if resp.status == 200:
                            text = await resp.text(errors="ignore")
                            for m in pattern.finditer(text):
                                ep = m.group(1)
                                if ep.startswith("/") and len(ep) > 1:
                                    endpoints.append(ep)
                except Exception:
                    pass
    except Exception:
        pass

    endpoints = list(dict.fromkeys(endpoints))[:50]
    await _tool_status(project_id, url[:30], "linkfinder", "done", len(endpoints), pool)
    return endpoints


# ── GAU + Waybackurls ─────────────────────────────────────────────────────────

async def run_gau(subdomain: str, job_id: Optional[str] = None,
                  project_id: Optional[str] = None, pool=None) -> List[str]:
    await _tool_status(project_id, subdomain, "gau", "running", pool=pool)
    try:
        rc, stdout, _ = await manager.run(
            name=f"gau_{subdomain[:20]}",
            cmd=["gau", "--subs", subdomain],
            timeout_secs=GAU_TIMEOUT,
            capture_stdout=True,
        )
        if rc == -127:
            await _tool_status(project_id, subdomain, "gau", "skipped", pool=pool)
            return []
        urls = [l.strip() for l in
                stdout.decode("utf-8", errors="replace").splitlines()
                if l.strip().startswith("http")][:100]
        await _tool_status(project_id, subdomain, "gau", "done", len(urls), pool)
        return urls
    except Exception as e:
        logger.debug("gau %s: %s", subdomain, e)
        await _tool_status(project_id, subdomain, "gau", "error", pool=pool)
        return []


async def run_waybackurls(subdomain: str, job_id: Optional[str] = None,
                           project_id: Optional[str] = None,
                           pool=None) -> List[str]:
    await _tool_status(project_id, subdomain, "wayback", "running", pool=pool)
    try:
        rc, stdout, _ = await manager.run(
            name=f"wayback_{subdomain[:20]}",
            cmd=["waybackurls", subdomain],
            timeout_secs=WAYBACK_TIMEOUT,
            capture_stdout=True,
        )
        if rc == -127:
            await _tool_status(project_id, subdomain, "wayback", "skipped", pool=pool)
            return []
        urls = [l.strip() for l in
                stdout.decode("utf-8", errors="replace").splitlines()
                if l.strip().startswith("http")][:100]
        await _tool_status(project_id, subdomain, "wayback", "done", len(urls), pool)
        return urls
    except Exception as e:
        logger.debug("waybackurls %s: %s", subdomain, e)
        await _tool_status(project_id, subdomain, "wayback", "error", pool=pool)
        return []


# ── Broken Link Checker ───────────────────────────────────────────────────────

async def check_broken_links(crawled_urls: List[str], base_domain: str,
                               job_id: Optional[str] = None,
                               project_id: Optional[str] = None,
                               pool=None) -> List[Dict]:
    await _tool_status(project_id, base_domain, "broken_links", "running", pool=pool)
    same_domain = [u for u in crawled_urls if base_domain in u][:30]
    if not same_domain:
        await _tool_status(project_id, base_domain, "broken_links", "skipped", pool=pool)
        return []
    timeout = aiohttp.ClientTimeout(total=8)
    _bl_sem = asyncio.Semaphore(5)

    async def _check(url: str) -> Optional[Dict]:
        async with _bl_sem:
            try:
                async with aiohttp.ClientSession(timeout=timeout) as session:
                    async with session.head(url, allow_redirects=True, ssl=False) as resp:
                        if resp.status in (404, 410, 500, 502, 503, 504):
                            return {"url": url, "status": resp.status}
            except aiohttp.ClientConnectorError:
                return {"url": url, "status": 0, "reason": "connection_refused"}
            except asyncio.TimeoutError:
                return {"url": url, "status": 0, "reason": "timeout"}
            except Exception:
                pass
            return None

    raw = await asyncio.gather(*[_check(u) for u in same_domain], return_exceptions=True)
    results = [r for r in raw if r and isinstance(r, dict)]
    await _tool_status(project_id, base_domain, "broken_links", "done", len(results), pool)
    return results


# ── Risk Score ────────────────────────────────────────────────────────────────

def calculate_risk_score(data: Dict) -> Dict:
    score   = 0
    factors = []

    js_secrets    = data.get("js_secrets",     [])
    endpoints     = data.get("endpoints",      [])
    directories   = data.get("directories",    [])
    takeover      = data.get("takeover",       {})
    ports         = data.get("ports",          [])
    broken        = data.get("broken_links",   [])
    email_sec     = data.get("email_security", {})
    header_issues = data.get("header_issues",  [])
    waf           = data.get("waf",            {})
    bypassed      = data.get("bypass_403",     [])
    js_lib_vulns  = data.get("js_lib_vulns",   [])

    if takeover.get("vulnerable"):
        score += 60
        factors.append({"name": "Subdomain takeover", "score": 60, "severity": "critical"})
    if js_secrets:
        score += min(35, len(js_secrets) * 5)
        factors.append({"name": f"{len(js_secrets)} potential secrets in JS",
                         "score": min(35, len(js_secrets)*5), "severity": "high"})
    if email_sec.get("spf_missing"):
        score += 15
        factors.append({"name": "SPF record missing", "score": 15, "severity": "high"})
    if email_sec.get("dmarc_missing"):
        score += 15
        factors.append({"name": "DMARC record missing", "score": 15, "severity": "high"})
    if bypassed:
        score += min(25, len(bypassed) * 8)
        factors.append({"name": f"{len(bypassed)} 403 bypass(es) found",
                         "score": min(25, len(bypassed)*8), "severity": "high"})
    if js_lib_vulns:
        crit_cve = [v for v in js_lib_vulns if v.get("severity") in ("critical", "high")]
        if crit_cve:
            score += min(20, len(crit_cve) * 5)
            factors.append({"name": f"{len(crit_cve)} critical JS CVEs (retire.js)",
                             "score": min(20, len(crit_cve)*5), "severity": "high"})
    if not waf.get("detected"):
        score += 5
        factors.append({"name": "No WAF detected", "score": 5, "severity": "low"})
    sens_eps = [e for e in endpoints if any(kw in str(e).lower() for kw in SENSITIVE_KW)]
    if sens_eps:
        score += min(25, len(sens_eps) * 3)
        factors.append({"name": f"{len(sens_eps)} sensitive endpoints",
                         "score": min(25, len(sens_eps)*3), "severity": "medium"})
    missing_hdrs = [h for h in header_issues if not h.get("present")]
    if missing_hdrs:
        score += min(10, len(missing_hdrs) * 2)
        factors.append({"name": f"{len(missing_hdrs)} missing security headers",
                         "score": min(10, len(missing_hdrs)*2), "severity": "low"})
    if broken:
        score += min(10, len(broken))
        factors.append({"name": f"{len(broken)} broken links", "score": min(10, len(broken)), "severity": "low"})

    score = min(100, score)
    if score >= 60:
        severity = "critical"
    elif score >= 40:
        severity = "high"
    elif score >= 20:
        severity = "medium"
    else:
        severity = "low"

    return {"score": score, "severity": severity, "factors": factors}


# ── Full Recon Orchestrator ────────────────────────────────────────────────────

async def run_full_recon(
    subdomain: str,
    url: str,
    job_id: Optional[str] = None,
    pool=None,
    project_id: Optional[str] = None,
) -> Dict:
    """
    Run ALL recon modules for a single live subdomain in parallel phases.

    Phase 1 (parallel): naabu, katana/hakrawler, gau, wayback, takeover,
                        screenshot, wafw00f, email_security
    Phase 2 (parallel, needs Phase 1 crawl data): linkfinder, trufflehog,
                        gitleaks, ffuf, broken_links, arjun, header_check, retirejs
    Phase 3 (parallel, needs Phase 2 data): 403_bypass, origin_ip
    """
    logger.info("[ReconIntel] %s start", subdomain)

    # Mark all tools as queued for frontend progress bars
    if project_id:
        all_tools = [
            "naabu", "katana", "gau", "wayback", "takeover", "screenshot",
            "waf", "email_security", "linkfinder", "trufflehog", "gitleaks",
            "ffuf", "broken_links", "arjun", "headers", "retirejs",
            "bypass_403", "origin_ip",
        ]
        for t in all_tools:
            await _tool_status(project_id, subdomain, t, "queued", pool=pool)

    # ── Phase 1: network / crawl / archive / waf / email (run in parallel) ───
    p1_results = await asyncio.gather(
        run_naabu(subdomain, job_id, project_id, pool),
        run_crawler(url, job_id, project_id, pool),
        run_gau(subdomain, job_id, project_id, pool),
        run_waybackurls(subdomain, job_id, project_id, pool),
        run_takeover_check(subdomain, job_id, project_id, pool),
        take_screenshot(url, subdomain, job_id, project_id, pool),
        run_wafw00f(url, job_id, project_id, pool),
        check_email_security(subdomain, job_id, project_id, pool),
        return_exceptions=True,
    )
    await asyncio.sleep(0.3)

    defaults1 = [[], [], [], [], {"vulnerable": False}, None,
                 {"detected": False, "waf": "", "manufacturer": ""},
                 {"spf_missing": True, "dmarc_missing": True, "dkim_found": False, "issues": []}]

    (ports, crawled, gau_u, wayb_u, takeover, screenshot, waf_result, email_sec) = (
        r if not isinstance(r, Exception) else d
        for r, d in zip(p1_results, defaults1)
    )
    ports        = ports        if isinstance(ports, list)    else []
    crawled      = crawled      if isinstance(crawled, list)  else []
    gau_u        = gau_u        if isinstance(gau_u, list)    else []
    wayb_u       = wayb_u       if isinstance(wayb_u, list)   else []
    takeover     = takeover     if isinstance(takeover, dict)  else {"vulnerable": False}
    screenshot   = screenshot   if isinstance(screenshot, str) else None
    waf_result   = waf_result   if isinstance(waf_result, dict) else {"detected": False}
    email_sec    = email_sec    if isinstance(email_sec, dict)  else {}

    archive_urls = list(dict.fromkeys(gau_u + wayb_u))
    js_urls      = [u for u in crawled if ".js" in u and "?" not in u]

    # ── Phase 2: content analysis (needs Phase 1 data) ────────────────────────
    await asyncio.sleep(0.3)
    p2_results = await asyncio.gather(
        run_linkfinder(url, crawled, job_id, project_id, pool),
        run_trufflehog_on_js(js_urls, subdomain, job_id, project_id, pool),
        run_gitleaks_regex(js_urls, job_id, project_id, pool),
        run_ffuf(url, job_id, project_id, pool),
        check_broken_links(crawled, subdomain, job_id, project_id, pool),
        run_arjun(url, job_id, project_id, pool),
        check_security_headers(url, job_id, project_id, pool),
        run_retirejs(js_urls, subdomain, job_id, project_id, pool),
        return_exceptions=True,
    )
    defaults2 = [[], [], [], ([], []), [], [], [], []]

    (js_endpoints, th_secrets, re_secrets, ffuf_result,
     broken_links, hidden_params, header_issues, js_lib_vulns) = (
        r if not isinstance(r, Exception) else d
        for r, d in zip(p2_results, defaults2)
    )
    js_endpoints = js_endpoints if isinstance(js_endpoints, list) else []
    th_secrets   = th_secrets   if isinstance(th_secrets, list)   else []
    re_secrets   = re_secrets   if isinstance(re_secrets, list)   else []
    # ffuf now returns (results, forbidden_paths)
    if isinstance(ffuf_result, tuple):
        directories, forbidden_paths = ffuf_result
    else:
        directories, forbidden_paths = [], []
    broken_links  = broken_links  if isinstance(broken_links, list)  else []
    hidden_params = hidden_params if isinstance(hidden_params, list) else []
    header_issues = header_issues if isinstance(header_issues, list) else []
    js_lib_vulns  = js_lib_vulns  if isinstance(js_lib_vulns, list)  else []

    # ── Phase 3: post-analysis (403 bypass + origin IP) ───────────────────────
    await asyncio.sleep(0.2)
    p3_results = await asyncio.gather(
        attempt_403_bypass(url, forbidden_paths, job_id, project_id, pool),
        get_origin_ip(subdomain, job_id, project_id, pool),
        return_exceptions=True,
    )
    bypass_403_results = p3_results[0] if not isinstance(p3_results[0], Exception) else []
    origin_ip          = p3_results[1] if not isinstance(p3_results[1], Exception) else ""
    bypass_403_results = bypass_403_results if isinstance(bypass_403_results, list) else []
    origin_ip          = origin_ip          if isinstance(origin_ip, str)           else ""

    # Merge secrets (deduplicate)
    seen_raw: set = set()
    all_secrets: List[Dict] = []
    for sec in th_secrets + re_secrets:
        key = sec.get("raw", "")[:40]
        if key not in seen_raw:
            seen_raw.add(key)
            all_secrets.append(sec)

    all_endpoints = list(dict.fromkeys(
        js_endpoints + [d.get("path", "") for d in directories if d.get("path")]
    ))

    result: Dict = {
        "subdomain":      subdomain,
        "url":            url,
        "ports":          ports,
        "crawled_urls":   crawled[:100],
        "archive_urls":   archive_urls[:100],
        "endpoints":      all_endpoints[:100],
        "js_files":       js_urls[:30],
        "js_secrets":     all_secrets[:50],
        "js_endpoints":   js_endpoints[:50],
        "js_lib_vulns":   js_lib_vulns[:20],
        "directories":    directories[:50],
        "broken_links":   broken_links[:20],
        "takeover":       takeover,
        "s3_buckets":     [],
        "origin_ip":      origin_ip,
        "screenshot":     screenshot,
        "waf":            waf_result,
        "email_security": email_sec,
        "header_issues":  header_issues[:20],
        "hidden_params":  hidden_params[:50],
        "bypass_403":     bypass_403_results[:20],
        "scanned_at":     datetime.now().isoformat(),
    }
    result["risk"] = calculate_risk_score(result)

    logger.info(
        "[ReconIntel] ✓ %s | ports=%s secrets=%d takeover=%s waf=%s score=%s/%d",
        subdomain, ports, len(all_secrets),
        takeover.get("vulnerable"),
        waf_result.get("waf", "none"),
        result["risk"]["severity"], result["risk"]["score"],
    )
    return result
