"""Append-only, HMAC-chained audit log.

Every row stores `hash = HMAC(audit_key, prev_hash | canonical_json(row))`.
Changing, deleting, inserting or reordering any row breaks every hash after
it, and recomputing the chain requires the audit key, which lives in the
environment and never in the database.

Each appended row is also written as one JSON line to stdout. On a hosted
platform those logs are kept by a separate system, so they act as an outside
witness of the chain head: rewriting the database does not rewrite them.
"""
import json
import logging
import sys

from flask import current_app, g, has_request_context, request

from .db import get_db, now_iso, transaction
from .security import GENESIS_HASH, audit_hmac, canonical_json

_witness = logging.getLogger("trustvault.audit")
if not _witness.handlers:
    _h = logging.StreamHandler(sys.stdout)
    _h.setFormatter(logging.Formatter("%(message)s"))
    _witness.addHandler(_h)
    _witness.setLevel(logging.INFO)
    _witness.propagate = False

RECORD_FIELDS = (
    "seq", "ts", "actor_id", "actor_email", "action", "outcome",
    "document_id", "target_user_id", "ip", "user_agent", "details",
)


def client_ip() -> str | None:
    if not has_request_context():
        return None
    return request.remote_addr  # ProxyFix (app/__init__.py) sets this correctly


def append(action: str, outcome: str = "success", *, document_id=None, target_user_id=None,
           details: dict | None = None, actor=None, actor_email=None, db=None) -> int:
    """Append one audit record. Joins the caller's transaction if there is one,
    so the action and its record commit or roll back together."""
    db = db or get_db()
    if actor is None and has_request_context():
        actor = getattr(g, "user", None)
    actor_id = actor["id"] if actor else None
    if actor is not None:
        actor_email = actor["email"]

    ua = request.headers.get("User-Agent", "")[:300] if has_request_context() else None
    audit_key = current_app.config["TV"].AUDIT_KEY

    with transaction(db):
        last = db.execute("SELECT seq, hash FROM audit_log ORDER BY seq DESC LIMIT 1").fetchone()
        seq = (last["seq"] + 1) if last else 1
        prev_hash = last["hash"] if last else GENESIS_HASH
        record = {
            "seq": seq,
            "ts": now_iso(),
            "actor_id": actor_id,
            "actor_email": actor_email,
            "action": action,
            "outcome": outcome,
            "document_id": document_id,
            "target_user_id": target_user_id,
            "ip": client_ip(),
            "user_agent": ua,
            "details": canonical_json(details or {}),
        }
        digest = audit_hmac(audit_key, prev_hash, record)
        db.execute(
            f"INSERT INTO audit_log ({', '.join(RECORD_FIELDS)}, prev_hash, hash) "
            f"VALUES ({', '.join('?' * len(RECORD_FIELDS))}, ?, ?)",
            tuple(record[f] for f in RECORD_FIELDS) + (prev_hash, digest),
        )
    if not current_app.config["TV"].TESTING:
        _witness.info(json.dumps({"audit": seq, "action": action, "outcome": outcome, "hash": digest}))
    return seq


def defer(**record):
    """Queue a record to be written after the current transaction has ended."""
    g.setdefault("deferred_audit", []).append(record)


def flush_deferred():
    """Called by the error handlers, after any transaction has rolled back."""
    pending = g.pop("deferred_audit", [])
    db = get_db()
    if db.in_transaction:  # defensive: never write a denial into a doomed transaction
        db.execute("ROLLBACK")
    for record in pending:
        append(record.pop("action"), record.pop("outcome"), **record)


def verify_chain(db, audit_key: bytes) -> dict:
    """Recompute the whole chain. Returns where it first breaks, if anywhere."""
    prev_hash = GENESIS_HASH
    expected_seq = 1
    count = 0
    for row in db.execute(
        f"SELECT {', '.join(RECORD_FIELDS)}, prev_hash, hash FROM audit_log ORDER BY seq"
    ):
        record = {f: row[f] for f in RECORD_FIELDS}
        if row["seq"] != expected_seq:
            return {"valid": False, "count": count, "broken_at": row["seq"],
                    "reason": f"sequence gap: expected {expected_seq}, found {row['seq']}"}
        if row["prev_hash"] != prev_hash:
            return {"valid": False, "count": count, "broken_at": row["seq"],
                    "reason": "prev_hash does not match the previous record"}
        if audit_hmac(audit_key, prev_hash, record) != row["hash"]:
            return {"valid": False, "count": count, "broken_at": row["seq"],
                    "reason": "record contents do not match its hash"}
        prev_hash = row["hash"]
        expected_seq += 1
        count += 1
    return {"valid": True, "count": count, "head_hash": prev_hash, "broken_at": None, "reason": None}
