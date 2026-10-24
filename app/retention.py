"""Retention: content of documents left in the trash past the retention period
is destroyed. Metadata, version records (with their SHA-256) and the audit
trail stay, so "who read this, and what exactly was it" can still be answered.
"""
from datetime import timedelta

from . import audit
from .db import iso, now_iso, transaction, utcnow


def purge_expired(db, retention_days: int, actor=None) -> list[str]:
    cutoff = iso(utcnow() - timedelta(days=retention_days))
    purged = []
    rows = db.execute("SELECT id, title FROM documents WHERE deleted_at IS NOT NULL AND deleted_at < ? "
                      "AND purged_at IS NULL", (cutoff,)).fetchall()
    for doc in rows:
        with transaction(db):
            blob_ids = [r["blob_id"] for r in db.execute(
                "SELECT blob_id FROM document_versions WHERE document_id = ? AND blob_id IS NOT NULL", (doc["id"],))]
            for bid in blob_ids:
                db.execute("DELETE FROM blobs WHERE id = ?", (bid,))  # FK sets version.blob_id to NULL
            db.execute("UPDATE documents SET purged_at = ? WHERE id = ?", (now_iso(), doc["id"]))
            audit.append("document.purge", document_id=doc["id"], actor=actor,
                         actor_email=None if actor else "system:retention",
                         details={"title": doc["title"], "blobs_destroyed": len(blob_ids),
                                  "retention_days": retention_days}, db=db)
        purged.append(doc["id"])
    return purged
