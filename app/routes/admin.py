"""Administration: accounts, ownership transfer, the audit trail and alerts.

The administrator manages people and watches activity. The administrator does
NOT read documents: there is no admin route that returns file content, and
authorize() ignores roles. An admin can see document metadata (title, owner,
category, grant count), because overseeing sharing is impossible without it.
"""
import json
from datetime import timedelta

from flask import Blueprint, Response, current_app, g, jsonify, request

from .. import audit
from ..auth import revoke_user_sessions, roles_required
from ..db import get_db, iso, now_iso, transaction, utcnow
from ..errors import ApiError
from ..security import hash_password, new_id, password_problem
from . import id_param, json_body, like_escape, page_params, parse_date, text_field

bp = Blueprint("admin", __name__, url_prefix="/api/admin")

ROLES = ("admin", "owner", "viewer")


def _user_json(u):
    return {"id": u["id"], "email": u["email"], "name": u["name"], "role": u["role"],
            "active": bool(u["is_active"]), "locked_until": u["locked_until"],
            "failed_logins": u["failed_logins"], "created_at": u["created_at"]}


def _get_user(db, user_id):
    u = db.execute("SELECT * FROM users WHERE id = ?", (id_param(user_id, "user id"),)).fetchone()
    if u is None:
        raise ApiError(404, "No such user.")
    return u


# ---------------------------------------------------------------------------
# Users
# ---------------------------------------------------------------------------
@bp.get("/users")
@roles_required("admin")
def list_users():
    db = get_db()
    rows = db.execute("SELECT * FROM users ORDER BY role, name").fetchall()
    return jsonify(users=[_user_json(u) for u in rows])


@bp.post("/users")
@roles_required("admin")
def create_user():
    data = json_body({"email", "name", "role", "password"}, {"email", "name", "role", "password"})
    email = text_field(data["email"], "email", 254).lower()
    if "@" not in email or " " in email:
        raise ApiError(400, "email is not valid.")
    name = text_field(data["name"], "name", 120)
    if data["role"] not in ROLES:
        raise ApiError(400, "role must be admin, owner or viewer.")
    problem = password_problem(data["password"])
    if problem:
        raise ApiError(400, problem)
    db = get_db()
    uid = new_id()
    now = now_iso()
    with transaction(db):
        if db.execute("SELECT 1 FROM users WHERE email = ?", (email,)).fetchone():
            raise ApiError(409, "A user with that email already exists.")
        db.execute("INSERT INTO users (id, email, name, role, password_hash, created_at, updated_at) "
                   "VALUES (?, ?, ?, ?, ?, ?, ?)",
                   (uid, email, name, data["role"], hash_password(data["password"]), now, now))
        audit.append("admin.user_create", target_user_id=uid, details={"email": email, "role": data["role"]})
    return jsonify(user=_user_json(_get_user(db, uid))), 201


@bp.patch("/users/<user_id>")
@roles_required("admin")
def update_user(user_id):
    data = json_body({"role", "active", "name"})
    if not data:
        raise ApiError(400, "Nothing to change.")
    db = get_db()
    with transaction(db):
        u = _get_user(db, user_id)
        if u["id"] == g.user["id"] and ("role" in data or "active" in data):
            raise ApiError(400, "You cannot change your own role or deactivate yourself.")
        changes, diff = {}, {}
        if "role" in data:
            if data["role"] not in ROLES:
                raise ApiError(400, "role must be admin, owner or viewer.")
            changes["role"] = data["role"]
        if "active" in data:
            if not isinstance(data["active"], bool):
                raise ApiError(400, "active must be true or false.")
            changes["is_active"] = 1 if data["active"] else 0
        if "name" in data:
            changes["name"] = text_field(data["name"], "name", 120)
        for k, v in changes.items():
            if u[k] != v:
                diff[k] = {"from": u[k], "to": v}
        if diff:
            sets = ", ".join(f"{k} = ?" for k in changes)
            db.execute(f"UPDATE users SET {sets}, updated_at = ? WHERE id = ?", (*changes.values(), now_iso(), u["id"]))
            ended = 0
            # Any change to what a person is allowed to be ends their sessions now.
            if "role" in diff or "is_active" in diff:
                ended = revoke_user_sessions(db, u["id"])
            audit.append("admin.user_update", target_user_id=u["id"],
                         details={"email": u["email"], "changes": diff, "sessions_ended": ended})
    return jsonify(user=_user_json(_get_user(db, user_id)))


@bp.post("/users/<user_id>/reset-password")
@roles_required("admin")
def reset_password(user_id):
    data = json_body({"new_password"}, {"new_password"})
    problem = password_problem(data["new_password"])
    if problem:
        raise ApiError(400, problem)
    db = get_db()
    with transaction(db):
        u = _get_user(db, user_id)
        if u["id"] == g.user["id"]:
            raise ApiError(400, "Use 'change password' for your own account.")
        db.execute("UPDATE users SET password_hash = ?, failed_logins = 0, locked_until = NULL, updated_at = ? "
                   "WHERE id = ?", (hash_password(data["new_password"]), now_iso(), u["id"]))
        ended = revoke_user_sessions(db, u["id"])
        audit.append("admin.password_reset", target_user_id=u["id"],
                     details={"email": u["email"], "sessions_ended": ended})
    return jsonify(ok=True)


@bp.post("/users/<user_id>/unlock")
@roles_required("admin")
def unlock_user(user_id):
    db = get_db()
    with transaction(db):
        u = _get_user(db, user_id)
        db.execute("UPDATE users SET failed_logins = 0, locked_until = NULL WHERE id = ?", (u["id"],))
        audit.append("admin.user_unlock", target_user_id=u["id"], details={"email": u["email"]})
    return jsonify(ok=True)


# ---------------------------------------------------------------------------
# Documents (metadata only) and ownership transfer
# ---------------------------------------------------------------------------
@bp.get("/documents")
@roles_required("admin")
def list_documents():
    db = get_db()
    now = now_iso()
    rows = db.execute(
        """SELECT d.id, d.title, d.category, d.created_at, d.deleted_at, d.purged_at, d.current_version,
                  u.name AS owner_name, u.email AS owner_email, u.is_active AS owner_active,
                  (SELECT COUNT(*) FROM grants gr WHERE gr.document_id = d.id AND gr.revoked_at IS NULL
                      AND (gr.expires_at IS NULL OR gr.expires_at > ?)) AS live_grants
             FROM documents d JOIN users u ON u.id = d.owner_id
            ORDER BY d.created_at DESC LIMIT 500""", (now,)).fetchall()
    return jsonify(documents=[dict(r) for r in rows])


@bp.post("/documents/<doc_id>/transfer")
@roles_required("admin")
def transfer_ownership(doc_id):
    """For when an owner leaves. Guard rails: an admin cannot transfer a
    document to themselves (that would be a quiet way to read it), the new
    owner must be an active 'owner'-role user, and it is flagged in alerts."""
    data = json_body({"new_owner_id"}, {"new_owner_id"})
    db = get_db()
    with transaction(db):
        doc = db.execute("SELECT * FROM documents WHERE id = ? AND purged_at IS NULL",
                         (id_param(doc_id, "document id"),)).fetchone()
        if doc is None:
            raise ApiError(404, "Document not found.")
        new_owner = _get_user(db, data["new_owner_id"])
        if new_owner["id"] == g.user["id"]:  # AUTHZ-CHECK:transfer-self
            audit.append("admin.ownership_transfer", "denied", document_id=doc["id"],
                         details={"reason": "self_transfer"})
            raise ApiError(403, "An administrator cannot transfer a document to themselves.")
        if not new_owner["is_active"] or new_owner["role"] != "owner":
            raise ApiError(400, "The new owner must be an active user with the 'owner' role.")
        if new_owner["id"] == doc["owner_id"]:
            raise ApiError(400, "That user already owns this document.")
        old = db.execute("SELECT email FROM users WHERE id = ?", (doc["owner_id"],)).fetchone()
        # The new owner's old grant (if any) is redundant now - close it.
        db.execute("UPDATE grants SET revoked_at = ?, revoked_by = ? WHERE document_id = ? AND user_id = ? "
                   "AND revoked_at IS NULL", (now_iso(), g.user["id"], doc["id"], new_owner["id"]))
        db.execute("UPDATE documents SET owner_id = ?, updated_at = ? WHERE id = ?",
                   (new_owner["id"], now_iso(), doc["id"]))
        audit.append("admin.ownership_transfer", document_id=doc["id"], target_user_id=new_owner["id"],
                     details={"from": old["email"], "to": new_owner["email"], "title": doc["title"]})
    return jsonify(ok=True)


@bp.post("/purge-expired")
@roles_required("admin")
def purge_expired():
    """Destroy the content of documents that have been in the trash longer than
    the retention period. Metadata and the audit trail are kept."""
    from ..retention import purge_expired as do_purge
    purged = do_purge(get_db(), current_app.config["TV"].TRASH_RETENTION_DAYS)
    return jsonify(purged=purged)


# ---------------------------------------------------------------------------
# Audit trail
# ---------------------------------------------------------------------------
def _audit_filters():
    where, params = [], []
    for arg, col in (("action", "action"), ("outcome", "outcome"), ("document_id", "document_id"),
                     ("actor_id", "actor_id"), ("target_user_id", "target_user_id")):
        v = request.args.get(arg)
        if v:
            if arg == "action" and v.endswith("*"):
                where.append("action LIKE ? ESCAPE '\\'")
                params.append(like_escape(v[:-1][:60]) + "%")
            else:
                where.append(f"{col} = ?")
                params.append(v[:100])
    actor = request.args.get("actor")
    if actor:
        where.append("actor_email LIKE ? ESCAPE '\\'")
        params.append(f"%{like_escape(actor[:100])}%")
    f = parse_date(request.args.get("from"), "from")
    t = parse_date(request.args.get("to"), "to", end_of_day=True)
    if f:
        where.append("ts >= ?")
        params.append(f)
    if t:
        where.append("ts <= ?")
        params.append(t)
    return (" WHERE " + " AND ".join(where)) if where else "", params


@bp.get("/audit")
@roles_required("admin")
def audit_list():
    db = get_db()
    where, params = _audit_filters()
    page, size = page_params(200)
    total = db.execute(f"SELECT COUNT(*) FROM audit_log{where}", params).fetchone()[0]
    rows = db.execute(
        f"""SELECT a.seq, a.ts, a.actor_id, a.actor_email, a.action, a.outcome, a.document_id,
                   a.target_user_id, a.ip, a.details, a.hash,
                   d.title AS document_title, tu.email AS target_email
              FROM (SELECT * FROM audit_log{where}) a
              LEFT JOIN documents d ON d.id = a.document_id
              LEFT JOIN users tu ON tu.id = a.target_user_id
             ORDER BY a.seq DESC LIMIT ? OFFSET ?""", params + [size, (page - 1) * size]).fetchall()
    return jsonify(entries=[dict(r) for r in rows], total=total, page=page, page_size=size)


@bp.get("/audit/verify")
@roles_required("admin")
def audit_verify():
    result = audit.verify_chain(get_db(), current_app.config["TV"].AUDIT_KEY)
    return jsonify(result)


@bp.get("/audit/export")
@roles_required("admin")
def audit_export():
    """Full log as JSON lines, including hashes, so a copy can be kept off the
    server and later compared against it."""
    db = get_db()
    audit.append("admin.audit_export")
    lines = (json.dumps(dict(r)) + "\n" for r in db.execute("SELECT * FROM audit_log ORDER BY seq").fetchall())
    return Response(lines, mimetype="application/x-ndjson",
                    headers={"Content-Disposition": f'attachment; filename="trustvault-audit-{now_iso()[:10]}.jsonl"'})


@bp.get("/alerts")
@roles_required("admin")
def alerts():
    """Things worth a human's attention, computed from the audit log."""
    db = get_db()
    now = utcnow()
    day = iso(now - timedelta(hours=24))
    hour = iso(now - timedelta(hours=1))
    week = iso(now - timedelta(days=7))
    out = []

    chain = audit.verify_chain(db, current_app.config["TV"].AUDIT_KEY)
    if not chain["valid"]:
        out.append({"severity": "critical", "title": "Audit trail integrity check failed",
                    "detail": f"Record {chain['broken_at']}: {chain['reason']}"})

    for r in db.execute(
            """SELECT actor_email, COUNT(*) n, COUNT(DISTINCT document_id) docs FROM audit_log
                WHERE outcome = 'denied' AND action LIKE 'document.%' AND ts >= ? AND actor_id IS NOT NULL
                GROUP BY actor_id HAVING n >= 5 ORDER BY n DESC""", (day,)):
        out.append({"severity": "high", "title": "Repeated refused document access",
                    "detail": f"{r['actor_email']} was refused {r['n']} times on {r['docs']} document id(s) "
                              "in 24h - possible probing.", "actor": r["actor_email"]})

    for r in db.execute(
            """SELECT actor_email, COUNT(*) n FROM audit_log
                WHERE action = 'auth.login' AND outcome = 'denied' AND ts >= ?
                GROUP BY actor_email HAVING n >= 5 ORDER BY n DESC""", (day,)):
        out.append({"severity": "medium", "title": "Repeated failed sign-ins",
                    "detail": f"{r['n']} failed sign-ins for {r['actor_email']} in 24h.", "actor": r["actor_email"]})

    for r in db.execute(
            """SELECT ip, COUNT(DISTINCT actor_email) accounts, COUNT(*) n FROM audit_log
                WHERE action = 'auth.login' AND outcome = 'denied' AND ts >= ?
                GROUP BY ip HAVING accounts >= 3 ORDER BY n DESC""", (day,)):
        out.append({"severity": "high", "title": "One address trying many accounts",
                    "detail": f"{r['ip']} failed to sign in to {r['accounts']} different accounts in 24h."})

    for r in db.execute(
            """SELECT actor_email, COUNT(*) n, COUNT(DISTINCT document_id) docs FROM audit_log
                WHERE action = 'document.download' AND outcome = 'success' AND ts >= ?
                GROUP BY actor_id HAVING n >= 20 ORDER BY n DESC""", (hour,)):
        out.append({"severity": "high", "title": "Unusual download volume",
                    "detail": f"{r['actor_email']} downloaded {r['n']} times ({r['docs']} documents) in the last hour.",
                    "actor": r["actor_email"]})

    for r in db.execute(
            """SELECT actor_email, COUNT(*) n FROM audit_log
                WHERE action = 'permission.grant' AND outcome = 'success' AND ts >= ?
                GROUP BY actor_id HAVING n >= 10""", (hour,)):
        out.append({"severity": "medium", "title": "Burst of sharing",
                    "detail": f"{r['actor_email']} granted access {r['n']} times in the last hour."})

    for r in db.execute(
            """SELECT ts, actor_email, action, details FROM audit_log
                WHERE (action IN ('admin.ownership_transfer', 'admin.password_reset')
                       OR (action = 'admin.user_update' AND details LIKE '%"role"%'))
                  AND outcome = 'success' AND ts >= ? ORDER BY seq DESC LIMIT 20""", (week,)):
        out.append({"severity": "info", "title": "Privileged administrator action",
                    "detail": f"{r['ts'][:16].replace('T', ' ')} - {r['actor_email']}: {r['action']} {r['details']}"})

    for r in db.execute(
            """SELECT action, COUNT(*) n FROM audit_log
                WHERE action IN ('security.csrf_rejected', 'security.bad_origin') AND ts >= ? GROUP BY action""",
            (day,)):
        out.append({"severity": "medium", "title": "Forged-request attempts",
                    "detail": f"{r['n']} request(s) refused by {r['action']} in 24h."})

    stale = db.execute(
        """SELECT COUNT(*) FROM documents d JOIN users u ON u.id = d.owner_id
            WHERE u.is_active = 0 AND d.deleted_at IS NULL""").fetchone()[0]
    if stale:
        out.append({"severity": "medium", "title": "Documents owned by deactivated users",
                    "detail": f"{stale} document(s) have no active owner. Transfer them so someone can manage access."})

    return jsonify(alerts=out, audit_chain=chain)
