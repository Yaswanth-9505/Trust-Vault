"""Test harness: a fresh database per test, real HTTP requests through Flask's
test client (so every decorator, before_request hook and error handler runs),
and one cookie jar per person."""
import io
import logging
import os
import secrets
import shutil
import tempfile
import unittest
import zipfile

import app.security as _security
from app import create_app
from app.auth import login_limiter
from app.config import Config
from app.db import connect, now_iso
from app.security import hash_password, new_id

PASSWORD = "Correct-Horse-9!"
_security.HASH_METHOD = "pbkdf2:sha256:1000"  # fast hashes for tests only
logging.getLogger("trustvault").setLevel(logging.CRITICAL)  # expected 500s in tests are not noise


def pdf_bytes(text="hello"):
    return b"%PDF-1.4\n%" + text.encode() + b"\n%%EOF\n"


def docx_bytes(text="hello"):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("[Content_Types].xml", "<Types/>")
        z.writestr("word/document.xml", f"<d>{text}</d>")
    return buf.getvalue()


class Person:
    """A signed-in user with their own cookie jar and CSRF token."""

    def __init__(self, app, user_id, email, password=PASSWORD):
        self.app = app
        self.id = user_id
        self.email = email
        self.client = app.test_client()
        self.csrf = None
        r = self.login(password)
        assert r.status_code == 200, (email, r.get_json())

    def login(self, password=PASSWORD):
        r = self.client.post("/api/auth/login", json={"email": self.email, "password": password})
        if r.status_code == 200:
            self.csrf = r.get_json()["csrfToken"]
        return r

    def _h(self, csrf=True):
        return {"X-CSRF-Token": self.csrf} if csrf and self.csrf else {}

    def get(self, path, **kw):
        return self.client.get(path, **kw)

    def post(self, path, json=None, data=None, csrf=True, headers=None, **kw):
        hdrs = {**self._h(csrf), **(headers or {})}
        if data is not None:
            return self.client.post(path, data=data, headers=hdrs, content_type="multipart/form-data", **kw)
        return self.client.post(path, json=json if json is not None else {}, headers=hdrs, **kw)

    def patch(self, path, json=None, csrf=True):
        return self.client.patch(path, json=json if json is not None else {}, headers=self._h(csrf))

    def delete(self, path, csrf=True):
        return self.client.delete(path, headers=self._h(csrf))

    def upload(self, title="Doc", filename="doc.pdf", content=None, category="HR"):
        r = self.post("/api/documents", data={
            "title": title, "category": category, "description": "",
            "file": (io.BytesIO(content if content is not None else pdf_bytes(title)), filename)})
        assert r.status_code == 201, r.get_json()
        return r.get_json()["document"]["id"]

    def grant(self, doc_id, person, permission="read", expires_at=None):
        body = {"user_id": person.id, "permission": permission}
        if expires_at:
            body["expires_at"] = expires_at
        r = self.post(f"/api/documents/{doc_id}/grants", json=body)
        assert r.status_code == 201, r.get_json()
        return r.get_json()["grant"]["id"]


class TrustVaultTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="tv-test-")
        self.cfg = Config(TESTING=True, DATABASE_PATH=os.path.join(self.tmp, "t.db"),
                          MASTER_KEY=secrets.token_bytes(32), AUDIT_KEY=secrets.token_bytes(32),
                          SECURE_COOKIES=False)
        self.app = create_app(self.cfg)
        login_limiter.reset()

        self.admin = self.make("admin")
        self.alice = self.make("owner")     # owns documents
        self.bob = self.make("owner")       # another owner - a stranger to Alice's documents
        self.vera = self.make("viewer")     # will be granted things
        self.mallory = self.make("viewer")  # never granted anything

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    # -- helpers -----------------------------------------------------------
    def db(self):
        return connect(self.cfg.DATABASE_PATH)

    def make(self, role, sign_in=True):
        uid = new_id()
        email = f"{role}-{uid[:6]}@test.local"
        now = now_iso()
        db = self.db()
        db.execute("INSERT INTO users (id, email, name, role, password_hash, created_at, updated_at) "
                   "VALUES (?, ?, ?, ?, ?, ?, ?)", (uid, email, f"{role} {uid[:4]}", role, hash_password(PASSWORD), now, now))
        db.close()
        return Person(self.app, uid, email) if sign_in else (uid, email)

    def audit_rows(self, **where):
        db = self.db()
        clause = " AND ".join(f"{k} = ?" for k in where) or "1=1"
        rows = db.execute(f"SELECT * FROM audit_log WHERE {clause} ORDER BY seq", tuple(where.values())).fetchall()
        db.close()
        return rows

    def assertRefused(self, resp, statuses=(403, 404)):
        self.assertIn(resp.status_code, statuses, resp.get_data(as_text=True)[:300])
        # A refusal never carries document content.
        self.assertNotIn(b"%PDF", resp.data)
