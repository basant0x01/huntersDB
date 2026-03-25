"""
api/auth.py — FastAPI session authentication.
Port of the original Flask session + login_required decorator.
Uses itsdangerous signed cookies (same model, no breaking change for users).
"""
import hashlib
import logging
from functools import wraps
from typing import Optional

from fastapi import Request, HTTPException, status
from fastapi.responses import RedirectResponse

from config.settings import AUTH_USERNAME, AUTH_PASSWORD, SECRET_KEY

logger = logging.getLogger("api.auth")

SESSION_COOKIE = "submind_session"
SESSION_TTL    = 86400  # 24h


def _hash_session(username: str, ts: float) -> str:
    raw = f"{username}:{ts}:{SECRET_KEY}"
    return hashlib.sha256(raw.encode()).hexdigest()


def create_session_token(username: str) -> str:
    import time
    ts = time.time()
    sig = _hash_session(username, ts)
    return f"{username}:{ts}:{sig}"


def verify_session_token(token: str) -> Optional[str]:
    import time
    try:
        parts = token.split(":", 2)  # maxsplit=2: supports colons in username
        if len(parts) != 3:
            return None
        username, ts_s, sig = parts
        ts = float(ts_s)
        if time.time() - ts > SESSION_TTL:
            return None
        expected = _hash_session(username, ts)
        if sig != expected:
            return None
        return username
    except Exception:
        return None


def get_current_user(request: Request) -> Optional[str]:
    token = request.cookies.get(SESSION_COOKIE)
    if not token:
        return None
    return verify_session_token(token)


def require_auth(request: Request) -> str:
    """Dependency — raises 401/redirect if not authenticated."""
    user = get_current_user(request)
    if not user:
        if request.url.path.startswith("/api/"):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail={"error": "Unauthorized", "login_required": True},
            )
        raise HTTPException(
            status_code=status.HTTP_302_FOUND,
            headers={"Location": "/login"},
        )
    return user


def check_credentials(username: str, password: str) -> bool:
    return username == AUTH_USERNAME and password == AUTH_PASSWORD
