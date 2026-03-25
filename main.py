"""
main.py — Hunter's DB v8.0 | FastAPI entry point (API server only).

This process handles HTTP requests ONLY.
All heavy scanning/sync work is dispatched to the Redis queue
and consumed by: python -m workers.queue_consumer

Architecture:
  main.py (this file)         — FastAPI, serves API + UI, NO scanning
  workers/queue_consumer.py   — Pulls jobs from Redis, runs scans
  queue/redis_task_queue.py        — Job queue (Redis ZSET)
  db/pool.py                  — asyncpg pool → PostgreSQL
  process_manager/manager.py  — Subprocess slots (used by WORKER only)

Run:
  # Terminal 1 — API server
  uvicorn main:app --host 0.0.0.0 --port 5000 --workers 1

  # Terminal 2 — Worker (separate process)
  python -m workers.queue_consumer

  # Or use run.sh which starts both
"""
import asyncio
import hashlib
import logging
import os
import signal
import sys
from datetime import datetime, timedelta
from pathlib import Path

import uvicorn
from contextlib import asynccontextmanager
from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from api.auth import (
    SESSION_COOKIE, check_credentials,
    create_session_token, get_current_user, require_auth,
)
from api.routes_projects import router as projects_router
from api.routes_server import router as server_router
from api.routes_recon import router as recon_router
from api.routes_garbage import router as garbage_router
from config.settings import BASE_DIR, SECRET_KEY
from db.migrations import run_migrations
from db.pool import close_pool, get_pool

# Ensure log directory exists
(BASE_DIR / "logs").mkdir(parents=True, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(str(BASE_DIR / "logs" / f"api_{datetime.now().strftime('%Y%m%d')}.log")),
    ],
)
logger = logging.getLogger("main")

# ── App ────────────────────────────────────────────────────────────────────────
_BASE_DIR = Path(__file__).parent

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    logger.info("=" * 62)
    logger.info("  Hunter's DB v8.0 — Production | FastAPI + asyncpg + Redis")
    logger.info("=" * 62)
    await get_pool()
    await run_migrations()
    # BUG-16 FIX: run recon migrations ONCE at startup instead of on every
    # recon API request (which would acquire a schema lock on every call).
    try:
        from db.recon_schema import run_recon_migrations
        from db.pool import get_pool as _gp
        _pool = await _gp()
        await run_recon_migrations(_pool)
        logger.info("Recon intelligence schema ready")
    except Exception as _e:
        logger.warning("Recon migrations skipped: %s", _e)
    logger.info("Database ready")
    logger.info("API server ready — Workers: python -m workers.queue_consumer")
    yield
    # Shutdown
    logger.info("API server shutting down...")
    await close_pool()
    logger.info("Shutdown complete")


app = FastAPI(
    title="Hunter's DB",
    version="8.0",
    docs_url=None,   # Disable Swagger UI in production
    redoc_url=None,
    lifespan=lifespan,
)

app.add_middleware(GZipMiddleware, minimum_size=1000)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Static files + templates ──────────────────────────────────────────────────
_static_dir = _BASE_DIR / "static"
_templates_dir = _BASE_DIR / "templates"

if _static_dir.exists():
    app.mount("/static", StaticFiles(directory=str(_static_dir)), name="static")

templates = Jinja2Templates(directory=str(_templates_dir)) if _templates_dir.exists() else None


# ── Lifespan — defined above near app instantiation ──────────────────────────


# ── Routers ───────────────────────────────────────────────────────────────────
app.include_router(projects_router)
app.include_router(server_router)
app.include_router(recon_router)
app.include_router(garbage_router)



# ── Auth routes ────────────────────────────────────────────────────────────────
@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request, error: str = ""):
    user = get_current_user(request)
    if user:
        return RedirectResponse(url="/", status_code=302)
    if templates:
        return templates.TemplateResponse(request, "login.html", {"error": error})
    # Fallback inline login page
    return HTMLResponse(_INLINE_LOGIN_HTML)


@app.post("/login")
async def login_submit(request: Request):
    form = await request.form()
    username = form.get("username", "")
    password = form.get("password", "")
    if not check_credentials(username, password):
        if templates:
            return templates.TemplateResponse(request, "login.html", {"error": "Invalid credentials"}, status_code=401)
        return HTMLResponse(_INLINE_LOGIN_HTML.replace(
            "</form>", '<div class="error-msg">Invalid credentials</div></form>'), status_code=401)

    token = create_session_token(username)
    response = RedirectResponse(url="/", status_code=302)
    response.set_cookie(
        key=SESSION_COOKIE, value=token,
        max_age=86400, httponly=True, samesite="lax",
    )
    return response


@app.get("/logout")
async def logout():
    response = RedirectResponse(url="/login", status_code=302)
    response.delete_cookie(SESSION_COOKIE)
    return response


# ── Main UI ────────────────────────────────────────────────────────────────────


@app.get("/projects/{pid}/recon-intel")
async def recon_intel_redirect(pid: str, _: str = Depends(require_auth)):
    """Redirect old recon_intel.html URL to main app (Recon Intel is now the 4th tab in project detail)."""
    return RedirectResponse(url=f"/#project/{pid}/recon", status_code=302)

@app.get("/", response_class=HTMLResponse)
async def index(request: Request, _: str = Depends(require_auth)):
    if templates:
        return templates.TemplateResponse(request, "index.html", {})
    return HTMLResponse("<h1>Hunter's DB v8.0</h1><p>Template not found. Check templates/ directory.</p>")


# ── Health check (no auth — for load balancers / k8s) ────────────────────────
@app.get("/health")
async def health():
    try:
        pool = await get_pool()
        async with pool.acquire() as conn:
            await conn.fetchval("SELECT 1")
        return {"status": "ok", "db": "ok", "ts": datetime.now().isoformat()}
    except Exception as e:
        return JSONResponse(
            status_code=503,
            content={"status": "error", "db": str(e)})


# ── Inline fallback login page ────────────────────────────────────────────────
_INLINE_LOGIN_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Hunter's DB — Login</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{min-height:100vh;display:flex;align-items:center;justify-content:center;
     background:#0a0e17;font-family:-apple-system,sans-serif;color:#e2e8f0}
.card{background:#111827;border:1px solid #1e293b;border-radius:16px;padding:48px 40px;
      width:420px;box-shadow:0 25px 60px rgba(0,0,0,.5)}
.logo{text-align:center;margin-bottom:32px}
.logo .icon{font-size:48px}
.logo h1{font-size:24px;font-weight:700;letter-spacing:1px;color:#fff}
.logo .ver{font-size:12px;color:#64748b;margin-top:4px}
.fg{margin-bottom:20px}
.fg label{display:block;font-size:13px;font-weight:600;color:#94a3b8;margin-bottom:8px}
.fg input{width:100%;padding:14px 16px;background:#0f172a;border:1px solid #1e293b;
          border-radius:10px;color:#e2e8f0;font-size:15px}
.fg input:focus{outline:none;border-color:#3b82f6}
.btn{width:100%;padding:14px;background:linear-gradient(135deg,#3b82f6,#2563eb);
     color:#fff;border:none;border-radius:10px;font-size:15px;font-weight:600;
     cursor:pointer;margin-top:8px}
.error-msg{background:#1e1215;border:1px solid #7f1d1d;color:#fca5a5;
           padding:12px 16px;border-radius:8px;font-size:13px;margin-bottom:20px;text-align:center}
</style>
</head>
<body>
<div class="card">
  <div class="logo">
    <div class="icon">🎯</div>
    <h1>Hunter's DB</h1>
    <div class="ver">v8.0 — Bug Bounty Intelligence</div>
  </div>
  <form method="POST" action="/login">
    <div class="fg"><label>USERNAME</label>
      <input type="text" name="username" placeholder="Enter username" autofocus required></div>
    <div class="fg"><label>PASSWORD</label>
      <input type="password" name="password" placeholder="Enter password" required></div>
    <button type="submit" class="btn">🔐 Sign In</button>
  </form>
</div>
</body>
</html>
"""


# ── Entry point ───────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import socket

    def find_port(start=5000):
        for p in range(start, start + 50):
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                    s.bind(("0.0.0.0", p))
                    return p
            except OSError:
                continue
        raise RuntimeError(f"No port available in range {start}-{start+49}")

    port = find_port(5000)
    print("=" * 62)
    print("  Hunter's DB v8.0 — FastAPI | asyncpg | Redis Queue")
    print("=" * 62)
    print(f"  API URL:  http://localhost:{port}")
    print(f"  Worker:   python -m workers.queue_consumer")
    print(f"  DB:       PostgreSQL (asyncpg)")
    print(f"  Queue:    Redis")
    print("=" * 62)
    print("  ⚠  Start the worker in a separate terminal!")
    print("=" * 62)

    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=port,
        log_level="info",
        access_log=True,
        loop="uvloop",        # Fastest event loop
        http="httptools",     # Fastest HTTP parser
        workers=1,            # Single worker — event loop is async, no GIL issues
    )
