"""Authentication: server-side sessions, CSRF protection, role checks.

Sessions live in the database and are looked up on every request. That is the
whole of "revocation is immediate": deactivating a user, changing their role,
resetting their password or logging out deletes their session rows, and the
very next request finds nothing.
"""
import threading
import time
from collections import defaultdict, deque
from datetime import datetime, timedelta
from functools import wraps
from urllib.parse import urlsplit

from flask import current_app, g, request

from . import audit
from .db import get_db, iso, utcnow
from .errors import ApiError
from .security import constant_time_equal, new_token, token_hash

SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}


def cfg():
    return current_app.config["TV"]


def _parse(ts: str) -> datetime:
    return datetime.strptime(ts, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=utcnow().tzinfo)


# ---------------------------------------------------------------------------
# Session lifecycle
# ---------------------------------------------------------------------------
def create_session(db, user_row) -> tuple[str, str]:
    """Create a new session. Returns (token, csrf_token). Always a fresh token,
    so a token planted before login (session fixation) is never upgraded."""
    token = new_token()
    csrf = new_token()
    now = utcnow()
    db.execute(
        "INSERT INTO sessions (token_hash, user_id, csrf_token, created_at, last_seen_at, expires_at, ip, user_agent) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (token_hash(token), user_row["id"], csrf, iso(now), iso(now),
         iso(now + timedelta(hours=cfg().SESSION_ABSOLUTE_HOURS)),
         request.remote_addr, request.headers.get("User-Agent", "")[:300]),
    )
    return token, csrf


def revoke_user_sessions(db, user_id: str, except_token_hash: str | None = None) -> int:
    if except_token_hash:
        cur = db.execute("DELETE FROM sessions WHERE user_id = ? AND token_hash != ?", (user_id, except_token_hash))
    else:
        cur = db.execute("DELETE FROM sessions WHERE user_id = ?", (user_id,))
    return cur.rowcount


def set_session_cookie(response, token: str):
    c = cfg()
    response.set_cookie(
        c.cookie_name, token,
        max_age=c.SESSION_ABSOLUTE_HOURS * 3600,
        secure=c.SECURE_COOKIES, httponly=True, samesite="Strict", path="/",
    )


def clear_session_cookie(response):
    c = cfg()
    response.delete_cookie(c.cookie_name, path="/", secure=c.SECURE_COOKIES, httponly=True, samesite="Strict")


def load_session():
    """before_request: resolve the cookie to a user, or to nobody."""
    g.user = None
    g.session = None
    token = request.cookies.get(cfg().cookie_name)
    if not token or len(token) > 128:
        return
    th = token_hash(token)
    db = get_db()
    row = db.execute(
        """SELECT s.token_hash, s.csrf_token, s.last_seen_at, s.expires_at,
                  u.id, u.email, u.name, u.role, u.is_active, u.is_demo
             FROM sessions s JOIN users u ON u.id = s.user_id
            WHERE s.token_hash = ?""",
        (th,),
    ).fetchone()
    if row is None:
        return
    now = utcnow()
    idle_limit = _parse(row["last_seen_at"]) + timedelta(minutes=cfg().SESSION_IDLE_MINUTES)
    if not row["is_active"] or _parse(row["expires_at"]) <= now or idle_limit <= now:
        db.execute("DELETE FROM sessions WHERE token_hash = ?", (th,))
        return
    if now - _parse(row["last_seen_at"]) > timedelta(seconds=60):
        db.execute("UPDATE sessions SET last_seen_at = ? WHERE token_hash = ?", (iso(now), th))
    g.user = {k: row[k] for k in ("id", "email", "name", "role", "is_demo")}
    g.session = {"token_hash": th, "csrf_token": row["csrf_token"]}


# ---------------------------------------------------------------------------
# CSRF and origin checks
# ---------------------------------------------------------------------------
def _same_origin(origin: str) -> bool:
    if origin == "null":
        return False
    o = urlsplit(origin)
    h = urlsplit(request.host_url)
    return (o.scheme, o.netloc) == (h.scheme, h.netloc)


def csrf_protect():
    """before_request, after load_session.

    1. Any state-changing API request that carries an Origin header must come
       from our own origin.
    2. Authenticated state-changing requests must echo the per-session CSRF
       token in X-CSRF-Token. A cross-site form cannot set custom headers.
    3. Login must be JSON, which a cross-site HTML form cannot send without a
       CORS preflight that we never approve.
    The session cookie is also SameSite=Strict; these are layers, not
    alternatives.
    """
    if request.method in SAFE_METHODS or not request.path.startswith("/api/"):
        return
    origin = request.headers.get("Origin")
    if origin is not None and not _same_origin(origin):
        audit.append("security.bad_origin", "denied", details={"path": request.path, "origin": origin[:200]})
        raise ApiError(403, "Cross-origin request refused.")
    if request.path == "/api/auth/login":
        if not request.is_json:
            raise ApiError(415, "Login must be sent as JSON.")
        return
    if g.user is None:
        return  # the route's own login check will answer 401
    if not constant_time_equal(request.headers.get("X-CSRF-Token"), g.session["csrf_token"]):
        audit.append("security.csrf_rejected", "denied", details={"path": request.path, "method": request.method})
        raise ApiError(403, "Missing or invalid CSRF token.")


# ---------------------------------------------------------------------------
# Route decorators
# ---------------------------------------------------------------------------
def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if g.user is None:
            raise ApiError(401, "Please sign in.")
        return fn(*args, **kwargs)
    return wrapper


def roles_required(*roles):
    def decorator(fn):
        @wraps(fn)
        @login_required
        def wrapper(*args, **kwargs):
            if g.user["role"] not in roles:  # AUTHZ-CHECK:role
                audit.append("access.denied", "denied",
                             details={"reason": "role", "required": list(roles), "path": request.path,
                                      "method": request.method})
                raise ApiError(403, "Your role does not allow this.")
            return fn(*args, **kwargs)
        return wrapper
    return decorator


# ---------------------------------------------------------------------------
# Login throttling (per IP, in memory) - the per-account lockout is in the DB
# ---------------------------------------------------------------------------
class IpRateLimiter:
    def __init__(self, window_seconds=300):
        self.window = window_seconds
        self.hits = defaultdict(deque)
        self.lock = threading.Lock()

    def allow(self, key: str, limit: int) -> bool:
        now = time.monotonic()
        with self.lock:
            q = self.hits[key]
            while q and now - q[0] > self.window:
                q.popleft()
            if len(q) >= limit:
                return False
            q.append(now)
            return True

    def reset(self):
        with self.lock:
            self.hits.clear()


login_limiter = IpRateLimiter()
