from datetime import timedelta

from flask import Blueprint, g, jsonify, request

from .. import audit
from ..auth import (cfg, clear_session_cookie, create_session, login_limiter, login_required,
                    revoke_user_sessions, set_session_cookie)
from ..db import get_db, iso, now_iso, transaction, utcnow
from ..errors import ApiError
from ..security import hash_password, password_problem, verify_password
from . import json_body

bp = Blueprint("auth", __name__, url_prefix="/api/auth")

GENERIC_FAILURE = "Email or password is incorrect, or the account is temporarily locked."


def _public_user(u):
    return {"id": u["id"], "email": u["email"], "name": u["name"], "role": u["role"]}


@bp.post("/login")
def login():
    c = cfg()
    if not login_limiter.allow(request.remote_addr or "?", c.LOGIN_RATE_PER_IP):
        audit.append("auth.login", "denied", details={"reason": "ip_rate_limited"})
        raise ApiError(429, "Too many sign-in attempts from this address. Try again in a few minutes.")

    data = json_body({"email", "password"}, {"email", "password"})
    email, password = data["email"], data["password"]
    if not isinstance(email, str) or not isinstance(password, str) or len(email) > 254 or len(password) > 256:
        raise ApiError(400, "Invalid email or password format.")
    email = email.strip()

    db = get_db()
    user = db.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
    # Always run the password check, even for unknown emails (timing).
    ok = verify_password(user["password_hash"] if user else None, password)
    now = now_iso()

    if user is None:
        audit.append("auth.login", "denied", actor_email=email[:254], details={"reason": "unknown_email"})
        raise ApiError(401, GENERIC_FAILURE)
    if user["locked_until"] and user["locked_until"] > now:
        audit.append("auth.login", "denied", target_user_id=user["id"], actor_email=user["email"],
                     details={"reason": "locked"})
        raise ApiError(401, GENERIC_FAILURE)
    if not user["is_active"]:
        audit.append("auth.login", "denied", target_user_id=user["id"], actor_email=user["email"],
                     details={"reason": "deactivated"})
        raise ApiError(401, GENERIC_FAILURE)

    if not ok:
        with transaction(db):
            failures = user["failed_logins"] + 1
            locked = failures >= c.LOGIN_MAX_FAILURES
            db.execute(
                "UPDATE users SET failed_logins = ?, locked_until = ?, updated_at = ? WHERE id = ?",
                (0 if locked else failures,
                 iso(utcnow() + timedelta(minutes=c.LOGIN_LOCK_MINUTES)) if locked else user["locked_until"],
                 now, user["id"]),
            )
            audit.append("auth.login", "denied", target_user_id=user["id"], actor_email=user["email"],
                         details={"reason": "bad_password", "failures": failures, "locked": locked})
        raise ApiError(401, GENERIC_FAILURE)

    with transaction(db):
        db.execute("UPDATE users SET failed_logins = 0, locked_until = NULL WHERE id = ?", (user["id"],))
        token, csrf = create_session(db, user)
        audit.append("auth.login", "success", actor=user)
    resp = jsonify(user=_public_user(user), csrfToken=csrf)
    set_session_cookie(resp, token)
    return resp


@bp.post("/logout")
@login_required
def logout():
    db = get_db()
    with transaction(db):
        db.execute("DELETE FROM sessions WHERE token_hash = ?", (g.session["token_hash"],))
        audit.append("auth.logout")
    resp = jsonify(ok=True)
    clear_session_cookie(resp)
    return resp


@bp.get("/me")
@login_required
def me():
    return jsonify(user=_public_user(g.user), csrfToken=g.session["csrf_token"])


@bp.post("/password")
@login_required
def change_password():
    if cfg().DEMO_MODE and g.user["is_demo"]:
        raise ApiError(403, "Shared demo accounts cannot change their password.")
    data = json_body({"current_password", "new_password"}, {"current_password", "new_password"})
    db = get_db()
    row = db.execute("SELECT password_hash FROM users WHERE id = ?", (g.user["id"],)).fetchone()
    if not verify_password(row["password_hash"], str(data["current_password"])):
        audit.append("auth.password_change", "denied", details={"reason": "bad_current_password"})
        raise ApiError(403, "Current password is incorrect.")
    problem = password_problem(data["new_password"])
    if problem:
        raise ApiError(400, problem)
    with transaction(db):
        db.execute("UPDATE users SET password_hash = ?, updated_at = ? WHERE id = ?",
                   (hash_password(data["new_password"]), now_iso(), g.user["id"]))
        ended = revoke_user_sessions(db, g.user["id"], except_token_hash=g.session["token_hash"])
        audit.append("auth.password_change", details={"other_sessions_ended": ended})
    return jsonify(ok=True)
