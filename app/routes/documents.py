"""Document routes. Every handler that receives a document id calls
authorize(id, action) before it reads or changes anything about that document."""
import hashlib
from urllib.parse import quote

from flask import Blueprint, Response, current_app, g, jsonify, request

from .. import audit
from ..auth import login_required, roles_required
from ..authz import VISIBLE_DOCUMENTS_SQL, authorize
from ..db import get_db, now_iso, transaction
from ..errors import ApiError
from ..security import decrypt_blob, encrypt_blob, new_id
from ..uploads import validate_upload
from . import CATEGORIES, category_field, json_body, like_escape, page_params, parse_date, text_field

bp = Blueprint("documents", __name__, url_prefix="/api/documents")


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------
def _read_upload():
    f = request.files.get("file")
    if f is None:
        raise ApiError(400, "No file was attached (form field 'file').")
    limit = current_app.config["TV"].MAX_UPLOAD_BYTES
    data = f.stream.read(limit + 1)
    meta = validate_upload(f.filename, data, limit)
    return data, meta


def _store_version(db, document_id: str, version_no: int, data: bytes, meta: dict) -> dict:
    blob_id = new_id()
    enc = encrypt_blob(current_app.config["TV"].MASTER_KEY, blob_id, data)
    db.execute("INSERT INTO blobs (id, nonce, ciphertext, key_nonce, wrapped_key) VALUES (?, ?, ?, ?, ?)",
               (blob_id, enc["nonce"], enc["ciphertext"], enc["key_nonce"], enc["wrapped_key"]))
    version = {
        "id": new_id(), "document_id": document_id, "version_no": version_no, "blob_id": blob_id,
        "filename": meta["filename"], "mime": meta["mime"], "size_bytes": len(data),
        "sha256": hashlib.sha256(data).hexdigest(), "uploaded_by": g.user["id"], "created_at": now_iso(),
    }
    db.execute(
        f"INSERT INTO document_versions ({', '.join(version)}) VALUES ({', '.join('?' * len(version))})",
        tuple(version.values()),
    )
    return version


def _doc_json(db, doc, level: str | None = None, include_versions=False) -> dict:
    owner = db.execute("SELECT name, email FROM users WHERE id = ?", (doc["owner_id"],)).fetchone()
    cur = db.execute(
        "SELECT filename, mime, size_bytes FROM document_versions WHERE document_id = ? AND version_no = ?",
        (doc["id"], doc["current_version"]),
    ).fetchone()
    out = {
        "id": doc["id"], "title": doc["title"], "description": doc["description"],
        "category": doc["category"], "owner": {"id": doc["owner_id"], "name": owner["name"], "email": owner["email"]},
        "current_version": doc["current_version"], "created_at": doc["created_at"],
        "updated_at": doc["updated_at"], "deleted_at": doc["deleted_at"],
        "filename": cur["filename"] if cur else None, "mime": cur["mime"] if cur else None,
        "size_bytes": cur["size_bytes"] if cur else None,
    }
    if level is not None:
        out["my_access"] = level
    if include_versions:
        out["versions"] = [
            dict(r) for r in db.execute(
                """SELECT v.version_no, v.filename, v.mime, v.size_bytes, v.sha256, v.created_at,
                          u.name AS uploaded_by
                     FROM document_versions v JOIN users u ON u.id = v.uploaded_by
                    WHERE v.document_id = ? ORDER BY v.version_no DESC""",
                (doc["id"],),
            )
        ]
    return out


# ---------------------------------------------------------------------------
# create / list / search
# ---------------------------------------------------------------------------
@bp.post("")
@roles_required("owner")
def upload_document():
    title = text_field(request.form.get("title"), "title", 200)
    description = text_field(request.form.get("description"), "description", 2000, required=False)
    category = category_field(request.form.get("category"))
    data, meta = _read_upload()

    db = get_db()
    doc_id = new_id()
    now = now_iso()
    with transaction(db):
        db.execute(
            "INSERT INTO documents (id, title, description, category, owner_id, current_version, created_at, updated_at) "
            "VALUES (?, ?, ?, ?, ?, 1, ?, ?)",
            (doc_id, title, description, category, g.user["id"], now, now),
        )
        v = _store_version(db, doc_id, 1, data, meta)
        audit.append("document.upload", document_id=doc_id,
                     details={"title": title, "category": category, "filename": v["filename"],
                              "size": v["size_bytes"], "sha256": v["sha256"], "version": 1})
    doc = db.execute("SELECT * FROM documents WHERE id = ?", (doc_id,)).fetchone()
    return jsonify(document=_doc_json(db, doc, "owner")), 201


@bp.get("")
@login_required
def list_documents():
    """List / search. Only ever returns documents the caller can open: the
    access rule is part of the WHERE clause, not a filter applied afterwards."""
    db = get_db()
    uid = g.user["id"]
    where = [VISIBLE_DOCUMENTS_SQL]
    params: list = [uid, uid, now_iso()]

    q = (request.args.get("q") or "").strip()[:200]
    if q:
        where.append("(d.title LIKE ? ESCAPE '\\' OR d.description LIKE ? ESCAPE '\\')")
        params += [f"%{like_escape(q)}%"] * 2
    owner = (request.args.get("owner") or "").strip()[:200]
    if owner:
        where.append("(o.name LIKE ? ESCAPE '\\' OR o.email LIKE ? ESCAPE '\\')")
        params += [f"%{like_escape(owner)}%"] * 2
    category = request.args.get("category")
    if category:
        where.append("d.category = ?")
        params.append(category_field(category))
    date_from = parse_date(request.args.get("from"), "from")
    date_to = parse_date(request.args.get("to"), "to", end_of_day=True)
    if date_from:
        where.append("d.created_at >= ?")
        params.append(date_from)
    if date_to:
        where.append("d.created_at <= ?")
        params.append(date_to)
    scope = request.args.get("scope", "all")
    if scope == "mine":
        where.append("d.owner_id = ?")
        params.append(uid)
    elif scope == "shared":
        where.append("d.owner_id != ?")
        params.append(uid)
    elif scope != "all":
        raise ApiError(400, "scope must be all, mine or shared.")

    order = {"newest": "d.created_at DESC", "oldest": "d.created_at ASC",
             "title": "d.title COLLATE NOCASE ASC", "updated": "d.updated_at DESC"}.get(
        request.args.get("sort", "newest"))
    if order is None:
        raise ApiError(400, "sort must be newest, oldest, title or updated.")

    page, size = page_params()
    base = f"FROM documents d JOIN users o ON o.id = d.owner_id WHERE {' AND '.join(where)}"
    total = db.execute(f"SELECT COUNT(*) {base}", params).fetchone()[0]
    rows = db.execute(f"SELECT d.* {base} ORDER BY {order} LIMIT ? OFFSET ?",
                      params + [size, (page - 1) * size]).fetchall()

    docs = []
    for d in rows:
        if d["owner_id"] == uid:
            level = "owner"
        else:
            g_row = db.execute(
                "SELECT permission FROM grants WHERE document_id = ? AND user_id = ? AND revoked_at IS NULL "
                "AND (expires_at IS NULL OR expires_at > ?)", (d["id"], uid, now_iso())).fetchone()
            level = g_row["permission"] if g_row else None
        docs.append(_doc_json(db, d, level))
    return jsonify(documents=docs, total=total, page=page, page_size=size, categories=list(CATEGORIES))


@bp.get("/trash")
@login_required
def list_trash():
    db = get_db()
    rows = db.execute(
        "SELECT * FROM documents WHERE owner_id = ? AND deleted_at IS NOT NULL AND purged_at IS NULL "
        "ORDER BY deleted_at DESC", (g.user["id"],)).fetchall()
    return jsonify(documents=[_doc_json(db, d, "owner") for d in rows],
                   retention_days=current_app.config["TV"].TRASH_RETENTION_DAYS)


# ---------------------------------------------------------------------------
# single document
# ---------------------------------------------------------------------------
@bp.get("/<doc_id>")
@login_required
def get_document(doc_id):
    doc = authorize(doc_id, "read")
    db = get_db()
    return jsonify(document=_doc_json(db, doc, g.doc_level, include_versions=True))


@bp.get("/<doc_id>/download")
@login_required
def download(doc_id):
    """THE download path. authorize() is the decision; the record of the
    download is committed in the same locked transaction, before any byte is
    sent. If the audit write fails, the download fails."""
    db = get_db()
    raw_version = request.args.get("version")
    with transaction(db):
        doc = authorize(doc_id, "download")  # <- the authorisation decision
        version_no = doc["current_version"]
        if raw_version is not None:
            if not raw_version.isdigit() or not (1 <= int(raw_version) <= doc["current_version"]):
                raise ApiError(404, "No such version.")
            version_no = int(raw_version)
        # The version is looked up *by this document's id*, so a version number
        # can never point at another document's file.
        v = db.execute(
            "SELECT * FROM document_versions WHERE document_id = ? AND version_no = ?",
            (doc["id"], version_no)).fetchone()
        blob = db.execute("SELECT * FROM blobs WHERE id = ?", (v["blob_id"],)).fetchone() if v else None
        if blob is None:
            raise ApiError(404, "No such version.")
        data = decrypt_blob(current_app.config["TV"].MASTER_KEY, blob["id"], blob)
        audit.append("document.download", document_id=doc["id"],
                     details={"version": version_no, "filename": v["filename"], "sha256": v["sha256"],
                              "access": g.doc_level})

    ascii_name = "".join(c if 32 <= ord(c) < 127 and c not in '"\\;' else "_" for c in v["filename"])
    headers = {
        # Always a download, never rendered: nothing a user uploads runs on our origin.
        "Content-Disposition": f"attachment; filename=\"{ascii_name}\"; filename*=UTF-8''{quote(v['filename'])}",
        "Content-Security-Policy": "default-src 'none'; sandbox",
        "X-Content-Type-Options": "nosniff",
        "Cache-Control": "no-store, private",
        "Content-Length": str(len(data)),
    }
    return Response(data, mimetype="application/octet-stream", headers=headers)


@bp.patch("/<doc_id>")
@login_required
def update_metadata(doc_id):
    data = json_body({"title", "description", "category"})
    if not data:
        raise ApiError(400, "Nothing to change.")
    changes = {}
    if "title" in data:
        changes["title"] = text_field(data["title"], "title", 200)
    if "description" in data:
        changes["description"] = text_field(data["description"], "description", 2000, required=False)
    if "category" in data:
        changes["category"] = category_field(data["category"])

    db = get_db()
    with transaction(db):
        doc = authorize(doc_id, "edit")
        diff = {k: {"from": doc[k], "to": v} for k, v in changes.items() if doc[k] != v}
        if diff:
            sets = ", ".join(f"{k} = ?" for k in changes)
            db.execute(f"UPDATE documents SET {sets}, updated_at = ? WHERE id = ?",
                       (*changes.values(), now_iso(), doc["id"]))
            audit.append("document.update", document_id=doc["id"], details={"changes": diff})
        level = g.doc_level
    doc = db.execute("SELECT * FROM documents WHERE id = ?", (doc_id,)).fetchone()
    return jsonify(document=_doc_json(db, doc, level, include_versions=True))


@bp.post("/<doc_id>/versions")
@login_required
def upload_version(doc_id):
    data, meta = _read_upload()
    db = get_db()
    with transaction(db):
        doc = authorize(doc_id, "edit")
        version_no = doc["current_version"] + 1
        v = _store_version(db, doc["id"], version_no, data, meta)
        db.execute("UPDATE documents SET current_version = ?, updated_at = ? WHERE id = ?",
                   (version_no, now_iso(), doc["id"]))
        audit.append("document.new_version", document_id=doc["id"],
                     details={"version": version_no, "filename": v["filename"], "size": v["size_bytes"],
                              "sha256": v["sha256"]})
        level = g.doc_level
    doc = db.execute("SELECT * FROM documents WHERE id = ?", (doc_id,)).fetchone()
    return jsonify(document=_doc_json(db, doc, level, include_versions=True)), 201


@bp.delete("/<doc_id>")
@login_required
def delete_document(doc_id):
    db = get_db()
    with transaction(db):
        doc = authorize(doc_id, "delete")
        db.execute("UPDATE documents SET deleted_at = ?, deleted_by = ? WHERE id = ?",
                   (now_iso(), g.user["id"], doc["id"]))
        audit.append("document.delete", document_id=doc["id"], details={"title": doc["title"], "soft": True})
    return jsonify(ok=True, message="Moved to trash. It can be restored for "
                   f"{current_app.config['TV'].TRASH_RETENTION_DAYS} days.")


@bp.post("/<doc_id>/restore")
@login_required
def restore_document(doc_id):
    db = get_db()
    with transaction(db):
        doc = authorize(doc_id, "restore")
        db.execute("UPDATE documents SET deleted_at = NULL, deleted_by = NULL, updated_at = ? WHERE id = ?",
                   (now_iso(), doc["id"]))
        audit.append("document.restore", document_id=doc["id"], details={"title": doc["title"]})
    doc = db.execute("SELECT * FROM documents WHERE id = ?", (doc_id,)).fetchone()
    return jsonify(document=_doc_json(db, doc, "owner"))


@bp.get("/<doc_id>/activity")
@login_required
def document_activity(doc_id):
    doc = authorize(doc_id, "view_activity")
    db = get_db()
    rows = db.execute(
        "SELECT seq, ts, actor_email, action, outcome, target_user_id, details FROM audit_log "
        "WHERE document_id = ? ORDER BY seq DESC LIMIT 200", (doc["id"],)).fetchall()
    return jsonify(activity=[dict(r) for r in rows])
