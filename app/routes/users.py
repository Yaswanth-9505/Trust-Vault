from flask import Blueprint, g, jsonify, request

from ..auth import roles_required
from ..db import get_db
from . import like_escape

bp = Blueprint("users", __name__, url_prefix="/api/users")


@bp.get("/directory")
@roles_required("owner", "admin")
def directory():
    """People an owner can share with. Viewers cannot list colleagues; owners
    see name and email of active accounts only - no roles, no status."""
    q = (request.args.get("q") or "").strip()[:100]
    db = get_db()
    params = [g.user["id"]]
    where = "is_active = 1 AND id != ?"
    if q:
        where += " AND (name LIKE ? ESCAPE '\\' OR email LIKE ? ESCAPE '\\')"
        params += [f"%{like_escape(q)}%"] * 2
    rows = db.execute(f"SELECT id, name, email FROM users WHERE {where} ORDER BY name LIMIT 25", params).fetchall()
    return jsonify(users=[dict(r) for r in rows])
