"""Sharing: grants, revocation and access suggestions.

Only a document's owner can see or change who has access (action 'share').
A user with 'edit' can change the document but cannot pass access on.

Suggestions are advisory. Producing one writes a row to access_suggestions and
an audit record; it never writes to `grants`. The only way a grant is created
is a POST from the owner, either here directly or by accepting a suggestion -
and both paths are audited with who decided.
"""
from datetime import timedelta

from flask import Blueprint, g, jsonify

from .. import audit
from ..auth import login_required
from ..authz import authorize
from ..db import get_db, iso, now_iso, transaction, utcnow
from ..errors import ApiError
from ..security import new_id
from . import id_param, json_body, parse_date

bp = Blueprint("grants", __name__, url_prefix="/api/documents")

MAX_GRANT_DAYS = 366


def _grant_json(db, gr) -> dict:
    u = db.execute("SELECT name, email, is_active FROM users WHERE id = ?", (gr["user_id"],)).fetchone()
    return {
        "id": gr["id"], "user": {"id": gr["user_id"], "name": u["name"], "email": u["email"],
                                 "active": bool(u["is_active"])},
        "permission": gr["permission"], "source": gr["source"], "created_at": gr["created_at"],
        "expires_at": gr["expires_at"], "revoked_at": gr["revoked_at"],
        "expired": bool(gr["expires_at"] and gr["expires_at"] <= now_iso()),
    }


def _permission(value) -> str:
    if value not in ("read", "edit"):
        raise ApiError(400, "permission must be 'read' or 'edit'.")
    return value


def _expiry(value) -> str | None:
    if value in (None, ""):
        return None
    if not isinstance(value, str):
        raise ApiError(400, "expires_at must be a date.")
    ts = parse_date(value, "expires_at", end_of_day=len(value) == 10)
    if ts <= now_iso():
        raise ApiError(400, "expires_at must be in the future.")
    if ts > iso(utcnow() + timedelta(days=MAX_GRANT_DAYS)):
        raise ApiError(400, f"expires_at can be at most {MAX_GRANT_DAYS} days away.")
    return ts


def _grantee(db, doc, user_id) -> dict:
    user_id = id_param(user_id, "user_id")
    if user_id == doc["owner_id"]:
        raise ApiError(400, "The owner already has full access.")
    u = db.execute("SELECT id, email, is_active FROM users WHERE id = ?", (user_id,)).fetchone()
    if u is None or not u["is_active"]:
        raise ApiError(400, "That user does not exist or is deactivated.")
    return u


def _create_grant(db, doc, user, permission, expires_at, source, suggestion_id=None):
    if db.execute("SELECT 1 FROM grants WHERE document_id = ? AND user_id = ? AND revoked_at IS NULL",
                  (doc["id"], user["id"])).fetchone():
        raise ApiError(409, "That person already has access. Change or revoke the existing grant instead.")
    gid = new_id()
    db.execute(
        "INSERT INTO grants (id, document_id, user_id, permission, granted_by, source, created_at, expires_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (gid, doc["id"], user["id"], permission, g.user["id"], source, now_iso(), expires_at))
    details = {"grantee": user["email"], "permission": permission, "expires_at": expires_at, "source": source}
    if suggestion_id:
        details["suggestion_id"] = suggestion_id
    audit.append("permission.grant", document_id=doc["id"], target_user_id=user["id"], details=details)
    return db.execute("SELECT * FROM grants WHERE id = ?", (gid,)).fetchone()


def _live_grant(db, doc, grant_id):
    # Looked up by grant id AND this document's id: a grant id from another
    # document cannot be revoked or changed through this URL.
    gr = db.execute(
        "SELECT * FROM grants WHERE id = ? AND document_id = ? AND revoked_at IS NULL",  # AUTHZ-CHECK:grant-doc
        (grant_id, doc["id"])).fetchone()
    if gr is None:
        raise ApiError(404, "No such active grant on this document.")
    return gr


# ---------------------------------------------------------------------------
@bp.get("/<doc_id>/grants")
@login_required
def list_grants(doc_id):
    doc = authorize(doc_id, "share")
    db = get_db()
    live = db.execute("SELECT * FROM grants WHERE document_id = ? AND revoked_at IS NULL ORDER BY created_at",
                      (doc["id"],)).fetchall()
    revoked = db.execute("SELECT * FROM grants WHERE document_id = ? AND revoked_at IS NOT NULL "
                         "ORDER BY revoked_at DESC LIMIT 20", (doc["id"],)).fetchall()
    return jsonify(grants=[_grant_json(db, r) for r in live], revoked=[_grant_json(db, r) for r in revoked])


@bp.post("/<doc_id>/grants")
@login_required
def create_grant(doc_id):
    data = json_body({"user_id", "permission", "expires_at"}, {"user_id", "permission"})
    permission = _permission(data["permission"])
    expires_at = _expiry(data.get("expires_at"))
    db = get_db()
    with transaction(db):
        doc = authorize(doc_id, "share")
        user = _grantee(db, doc, data["user_id"])
        gr = _create_grant(db, doc, user, permission, expires_at, "manual")
    return jsonify(grant=_grant_json(db, gr)), 201


@bp.patch("/<doc_id>/grants/<grant_id>")
@login_required
def change_grant(doc_id, grant_id):
    grant_id = id_param(grant_id, "grant id")
    data = json_body({"permission", "expires_at"})
    if not data:
        raise ApiError(400, "Nothing to change.")
    db = get_db()
    with transaction(db):
        doc = authorize(doc_id, "share")
        gr = _live_grant(db, doc, grant_id)
        new_perm = _permission(data["permission"]) if "permission" in data else gr["permission"]
        new_exp = _expiry(data["expires_at"]) if "expires_at" in data else gr["expires_at"]
        db.execute("UPDATE grants SET permission = ?, expires_at = ? WHERE id = ?", (new_perm, new_exp, gr["id"]))
        audit.append("permission.change", document_id=doc["id"], target_user_id=gr["user_id"],
                     details={"permission": {"from": gr["permission"], "to": new_perm},
                              "expires_at": {"from": gr["expires_at"], "to": new_exp}})
        gr = db.execute("SELECT * FROM grants WHERE id = ?", (gr["id"],)).fetchone()
    return jsonify(grant=_grant_json(db, gr))


@bp.delete("/<doc_id>/grants/<grant_id>")
@login_required
def revoke_grant(doc_id, grant_id):
    """Revocation is immediate because nothing that grants access is ever
    issued to the client: no signed URLs, no tokens that carry permissions.
    Every request re-reads `grants`, and this row is now revoked."""
    grant_id = id_param(grant_id, "grant id")
    db = get_db()
    with transaction(db):
        doc = authorize(doc_id, "share")
        gr = _live_grant(db, doc, grant_id)
        db.execute("UPDATE grants SET revoked_at = ?, revoked_by = ? WHERE id = ?",
                   (now_iso(), g.user["id"], gr["id"]))
        grantee = db.execute("SELECT email FROM users WHERE id = ?", (gr["user_id"],)).fetchone()
        audit.append("permission.revoke", document_id=doc["id"], target_user_id=gr["user_id"],
                     details={"grantee": grantee["email"], "permission": gr["permission"]})
    return jsonify(ok=True)


# ---------------------------------------------------------------------------
# Access suggestions (advisory only)
# ---------------------------------------------------------------------------
@bp.post("/<doc_id>/suggestions")  # POST: it writes suggestion rows and an audit record
@login_required
def suggestions(doc_id):
    """Suggest people who already hold access to this owner's other documents
    in the same category. Rule-based on purpose: no document data leaves the
    system, and the reasoning can be shown to the owner in one sentence."""
    db = get_db()
    with transaction(db):
        doc = authorize(doc_id, "share")
        rows = db.execute(
            """SELECT gr.user_id, COUNT(DISTINCT gr.document_id) AS n
                 FROM grants gr
                 JOIN documents d ON d.id = gr.document_id
                 JOIN users u ON u.id = gr.user_id
                WHERE d.owner_id = ? AND d.category = ? AND d.id != ?
                  AND d.deleted_at IS NULL AND gr.revoked_at IS NULL AND u.is_active = 1
                  AND gr.user_id != ?
                  AND gr.user_id NOT IN (SELECT user_id FROM grants
                                          WHERE document_id = ? AND revoked_at IS NULL)
                GROUP BY gr.user_id ORDER BY n DESC LIMIT 5""",
            (doc["owner_id"], doc["category"], doc["id"], doc["owner_id"], doc["id"])).fetchall()
        out = []
        for r in rows:
            existing = db.execute(
                "SELECT * FROM access_suggestions WHERE document_id = ? AND suggested_user_id = ? AND status = 'pending'",
                (doc["id"], r["user_id"])).fetchone()
            reason = f"Has access to {r['n']} other {doc['category']} document(s) you own."
            if existing:
                sid = existing["id"]
            else:
                sid = new_id()
                db.execute("INSERT INTO access_suggestions (id, document_id, suggested_user_id, reason, created_at) "
                           "VALUES (?, ?, ?, ?, ?)", (sid, doc["id"], r["user_id"], reason, now_iso()))
            u = db.execute("SELECT name, email FROM users WHERE id = ?", (r["user_id"],)).fetchone()
            out.append({"id": sid, "user": {"id": r["user_id"], "name": u["name"], "email": u["email"]},
                        "reason": reason})
        if out:
            audit.append("suggestion.shown", document_id=doc["id"],
                         details={"suggested": [s["user"]["email"] for s in out]})
    return jsonify(suggestions=out,
                   note="Suggestions never change access. Nothing happens unless you accept one.")


def _pending_suggestion(db, doc, suggestion_id):
    s = db.execute("SELECT * FROM access_suggestions WHERE id = ? AND document_id = ? AND status = 'pending'",
                   (id_param(suggestion_id, "suggestion id"), doc["id"])).fetchone()
    if s is None:
        raise ApiError(404, "No such pending suggestion on this document.")
    return s


@bp.post("/<doc_id>/suggestions/<suggestion_id>/accept")
@login_required
def accept_suggestion(doc_id, suggestion_id):
    data = json_body({"permission", "expires_at"}, {"permission"})
    permission = _permission(data["permission"])
    expires_at = _expiry(data.get("expires_at"))
    db = get_db()
    with transaction(db):
        doc = authorize(doc_id, "share")  # a person - the owner - is making this decision
        s = _pending_suggestion(db, doc, suggestion_id)
        user = _grantee(db, doc, s["suggested_user_id"])
        gr = _create_grant(db, doc, user, permission, expires_at, "suggestion", suggestion_id=s["id"])
        db.execute("UPDATE access_suggestions SET status = 'accepted', decided_at = ?, decided_by = ? WHERE id = ?",
                   (now_iso(), g.user["id"], s["id"]))
        audit.append("suggestion.accepted", document_id=doc["id"], target_user_id=user["id"],
                     details={"suggestion_id": s["id"], "reason": s["reason"], "permission": permission})
    return jsonify(grant=_grant_json(db, gr)), 201


@bp.post("/<doc_id>/suggestions/<suggestion_id>/dismiss")
@login_required
def dismiss_suggestion(doc_id, suggestion_id):
    db = get_db()
    with transaction(db):
        doc = authorize(doc_id, "share")
        s = _pending_suggestion(db, doc, suggestion_id)
        db.execute("UPDATE access_suggestions SET status = 'dismissed', decided_at = ?, decided_by = ? WHERE id = ?",
                   (now_iso(), g.user["id"], s["id"]))
        audit.append("suggestion.dismissed", document_id=doc["id"], target_user_id=s["suggested_user_id"],
                     details={"suggestion_id": s["id"], "reason": s["reason"]})
    return jsonify(ok=True)
