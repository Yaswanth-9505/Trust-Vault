"""THE authorisation decision for documents.

Every route that touches a document - metadata, download, versions, edit,
delete, restore, sharing, activity - calls `authorize()` first and uses the
document row it returns. There is no other path to a document row in the route
code, and nothing here trusts anything the client says about itself.

Rules, in order:
  1. The caller must be signed in (the route decorator guarantees this; the
     session lookup already refused deactivated users and expired sessions).
  2. The document must exist. A deleted (trashed) document is reachable for
     exactly one action: `restore`, by its owner. A purged one, for nothing.
  3. The caller's level on that document is decided from the database, now:
       - 'owner'  if documents.owner_id is the caller;
       - 'edit' / 'read' if there is a grant to the caller that is not revoked
         and not expired;
       - nothing otherwise.
     Role does not appear here. An administrator with no grant has no access
     to the content of a document - administration is about accounts and the
     audit trail, not about reading people's files.
  4. The level must allow the action (ACTION_LEVELS below).

If the caller has no level at all the answer is 404, identical to "no such
document", so document IDs cannot be probed. If they have some level but not
enough, the answer is 403 (they can already see the document exists). Both
are written to the audit log as denied attempts.
"""
from flask import g, request

from . import audit
from .db import get_db, now_iso
from .errors import ApiError

ACTION_LEVELS = {
    "read":          {"owner", "edit", "read"},   # metadata + version list
    "download":      {"owner", "edit", "read"},
    "edit":          {"owner", "edit"},           # change metadata, upload a new version
    "delete":        {"owner"},
    "restore":       {"owner"},
    "share":         {"owner"},                   # see / create / change / revoke grants
    "view_activity": {"owner"},                   # the document's audit history
}


def access_level(db, user_id: str, doc) -> str | None:
    """The caller's level on `doc`, computed from the database right now."""
    if doc["owner_id"] == user_id:  # AUTHZ-CHECK:owner
        return "owner"
    grant = db.execute(
        """SELECT permission FROM grants
            WHERE document_id = ?
              AND user_id = ?                                        -- AUTHZ-CHECK:grant-user
              AND revoked_at IS NULL                                 -- AUTHZ-CHECK:revoked
              AND (expires_at IS NULL OR expires_at > ?)             -- AUTHZ-CHECK:expiry
            LIMIT 1""",
        (doc["id"], user_id, now_iso()),
    ).fetchone()
    return grant["permission"] if grant else None


def _deny(status: int, action: str, document_id: str, reason: str):
    # If we are inside a write transaction it is about to be rolled back by the
    # exception below, which would take the denial record with it. So in that
    # case the record is queued and written by the error handler after the
    # rollback (audit.flush_deferred). Refused attempts are always recorded.
    record = dict(action=f"document.{action}", outcome="denied", document_id=document_id,
                  details={"reason": reason, "method": request.method, "path": request.path})
    if get_db().in_transaction:
        audit.defer(**record)
    else:
        audit.append(record.pop("action"), record.pop("outcome"), **record)
    if status == 404:
        raise ApiError(404, "Document not found.")
    raise ApiError(403, "You do not have permission to do that with this document.")


def authorize(document_id: str, action: str):
    """Return the document row if the signed-in user may perform `action` on it.
    Otherwise audit the attempt and raise 404 / 403. Must be called outside a
    write transaction, so the denial record is never rolled back."""
    if action not in ACTION_LEVELS:
        raise ValueError(f"unknown action {action!r}")
    user = g.user
    if user is None:
        raise ApiError(401, "Please sign in.")
    db = get_db()

    doc = None
    if isinstance(document_id, str) and 0 < len(document_id) <= 64:
        doc = db.execute("SELECT * FROM documents WHERE id = ?", (document_id,)).fetchone()
    if doc is None:
        _deny(404, action, document_id if _plausible_id(document_id) else None, "no_such_document")

    if doc["purged_at"] is not None:  # AUTHZ-CHECK:purged
        _deny(404, action, doc["id"], "purged")
    if action == "restore":
        if doc["deleted_at"] is None:
            _deny(404, action, doc["id"], "not_in_trash")
    elif doc["deleted_at"] is not None:  # AUTHZ-CHECK:deleted
        _deny(404, action, doc["id"], "deleted")

    level = access_level(db, user["id"], doc)
    if level is None:  # AUTHZ-CHECK:no-level
        _deny(404, action, doc["id"], "no_access")
    if level not in ACTION_LEVELS[action]:  # AUTHZ-CHECK:action-level
        _deny(403, action, doc["id"], f"level_{level}_insufficient")

    g.doc_level = level
    return doc


def _plausible_id(value) -> bool:
    return isinstance(value, str) and len(value) == 32 and all(c in "0123456789abcdef" for c in value)


# SQL fragment used by list/search. It encodes exactly the same rule as
# access_level(), so a document never appears in a list the caller could not
# open. Parameters: (user_id, user_id, now).
VISIBLE_DOCUMENTS_SQL = """
    d.deleted_at IS NULL AND d.purged_at IS NULL AND (
        d.owner_id = ?
        OR EXISTS (SELECT 1 FROM grants gr
                    WHERE gr.document_id = d.id
                      AND gr.user_id = ?
                      AND gr.revoked_at IS NULL
                      AND (gr.expires_at IS NULL OR gr.expires_at > ?))
    )
"""
