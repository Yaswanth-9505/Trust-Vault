"""SQLite access.

One connection per request. Autocommit mode is on (isolation_level=None) and
every write goes through `transaction()`, which issues BEGIN IMMEDIATE. That
takes SQLite's write lock up front, so two workers can never interleave writes
- which is what keeps the audit hash chain gapless and correctly ordered.
"""
import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone

from flask import current_app, g


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def iso(dt: datetime) -> str:
    """Fixed-width UTC timestamp, so string comparison == time comparison."""
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def now_iso() -> str:
    return iso(utcnow())


def connect(path: str) -> sqlite3.Connection:
    if path != ":memory:":
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    conn = sqlite3.connect(path, isolation_level=None, timeout=15)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    # DELETE (SQLite's default) is safe on network file systems such as
    # PythonAnywhere's home directories; WAL is faster but needs local disk.
    journal = os.environ.get("TV_SQLITE_JOURNAL", "DELETE").upper()
    if journal not in ("DELETE", "WAL", "TRUNCATE"):
        journal = "DELETE"
    conn.execute(f"PRAGMA journal_mode = {journal}")
    conn.execute("PRAGMA busy_timeout = 15000")
    conn.execute("PRAGMA secure_delete = ON")  # overwrite freed pages (purged files)
    return conn


def get_db() -> sqlite3.Connection:
    if "db" not in g:
        g.db = connect(current_app.config["TV"].DATABASE_PATH)
    return g.db


def close_db(_exc=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


@contextmanager
def transaction(db: sqlite3.Connection | None = None):
    db = db or get_db()
    if db.in_transaction:
        # Nested use joins the outer transaction.
        yield db
        return
    db.execute("BEGIN IMMEDIATE")
    try:
        yield db
        db.execute("COMMIT")
    except BaseException:
        db.execute("ROLLBACK")
        raise


def init_schema(db: sqlite3.Connection):
    schema_path = os.path.join(os.path.dirname(__file__), "schema.sql")
    with open(schema_path, encoding="utf-8") as f:
        db.executescript(f.read())


def one(db, sql, params=()):
    return db.execute(sql, params).fetchone()


def all_rows(db, sql, params=()):
    return db.execute(sql, params).fetchall()
