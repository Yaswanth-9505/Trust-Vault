"""Create demo users and documents.

    python -m scripts.seed            # seed an empty database
    python -m scripts.seed --reset    # delete the database file first (demo resets)

Passwords for the demo accounts are printed in README.md. They are public on
purpose (the judges need them); the accounts are marked is_demo so that, with
TV_DEMO_MODE=1, nobody can change their password and lock the others out.
"""
import hashlib
import io
import os
import sys
import zipfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import create_app  # noqa: E402
from app import audit  # noqa: E402
from app.db import get_db, now_iso, transaction  # noqa: E402
from app.security import encrypt_blob, hash_password, new_id  # noqa: E402

DEMO_USERS = [
    # email,                    name,              role,     password
    ("admin@trustvault.test",   "Asha Admin",      "admin",  "Admin-Demo-2026!"),
    ("olivia@trustvault.test",  "Olivia Owner",    "owner",  "Olivia-Demo-2026!"),
    ("oscar@trustvault.test",   "Oscar Owner",     "owner",  "Oscar-Demo-2026!"),
    ("vera@trustvault.test",    "Vera Viewer",     "viewer", "Vera-Demo-2026!"),
    ("victor@trustvault.test",  "Victor Viewer",   "viewer", "Victor-Demo-2026!"),
    ("ext@partner.test",        "Pat Partner (external)", "viewer", "Partner-Demo-2026!"),
]


def _docx(text: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("[Content_Types].xml", '<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"/>')
        z.writestr("word/document.xml", f'<?xml version="1.0"?><w:document xmlns:w="x"><w:body><w:p><w:r><w:t>{text}</w:t></w:r></w:p></w:body></w:document>')
    return buf.getvalue()


def _pdf(text: str) -> bytes:
    return (b"%PDF-1.4\n1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n2 0 obj<</Type/Pages/Count 0>>endobj\n"
            b"% " + text.encode() + b"\ntrailer<</Root 1 0 R>>\n%%EOF\n")


DEMO_DOCS = [
    # owner,   title,                                category,  filename,                 content
    ("olivia", "Salary letter - Vera",               "HR",      "salary-vera.pdf",        _pdf("CONFIDENTIAL salary letter for Vera Viewer: INR 18,00,000")),
    ("olivia", "Salary letter - Victor",             "HR",      "salary-victor.pdf",      _pdf("CONFIDENTIAL salary letter for Victor Viewer: INR 21,00,000")),
    ("olivia", "Q3 board financials",                "Finance", "q3-financials.csv",      b"quarter,revenue,cost\nQ3,4200000,3100000\n"),
    ("olivia", "Master services agreement - Partner","Legal",   "msa-partner.docx",       _docx("MSA between TrustVault Demo Co and Partner Ltd")),
    ("oscar",  "Bridge drawings rev B",              "Engineering", "bridge-rev-b.txt",   b"Load calculations for span 3. Internal only.\n"),
    ("oscar",  "Statutory audit working papers",     "Audit",   "audit-papers.md",        b"# FY26 audit\n\nSample of 40 invoices tested.\n"),
    ("oscar",  "Oscar's private notes",              "General", "notes.txt",              b"Nobody else should be able to read this.\n"),
]

DEMO_GRANTS = [
    # doc title,                         grantee,   permission
    ("Salary letter - Vera",             "vera",    "read"),
    ("Salary letter - Victor",           "victor",  "read"),
    ("Q3 board financials",              "oscar",   "read"),
    ("Q3 board financials",              "vera",    "edit"),
    ("Master services agreement - Partner", "ext",  "read"),
    ("Bridge drawings rev B",            "victor",  "edit"),
    ("Statutory audit working papers",   "vera",    "read"),
]


def seed(app):
    with app.app_context():
        db = get_db()
        if db.execute("SELECT COUNT(*) FROM users").fetchone()[0]:
            print("Database already has users; not seeding. Use --reset to start over.")
            return
        cfg = app.config["TV"]
        ids = {}
        now = now_iso()
        with transaction(db):
            for email, name, role, pw in DEMO_USERS:
                uid = new_id()
                ids[email.split("@")[0]] = uid
                db.execute("INSERT INTO users (id, email, name, role, password_hash, is_demo, created_at, updated_at) "
                           "VALUES (?, ?, ?, ?, ?, 1, ?, ?)", (uid, email, name, role, hash_password(pw), now, now))
                audit.append("admin.user_create", actor_email="system:seed", target_user_id=uid,
                             details={"email": email, "role": role}, db=db)
            doc_ids = {}
            for owner, title, category, filename, content in DEMO_DOCS:
                did, bid = new_id(), new_id()
                doc_ids[title] = did
                enc = encrypt_blob(cfg.MASTER_KEY, bid, content)
                db.execute("INSERT INTO documents (id, title, description, category, owner_id, created_at, updated_at) "
                           "VALUES (?, ?, ?, ?, ?, ?, ?)", (did, title, "Demo document", category, ids[owner], now, now))
                db.execute("INSERT INTO blobs (id, nonce, ciphertext, key_nonce, wrapped_key) VALUES (?, ?, ?, ?, ?)",
                           (bid, enc["nonce"], enc["ciphertext"], enc["key_nonce"], enc["wrapped_key"]))
                db.execute("INSERT INTO document_versions (id, document_id, version_no, blob_id, filename, mime, "
                           "size_bytes, sha256, uploaded_by, created_at) VALUES (?, ?, 1, ?, ?, ?, ?, ?, ?, ?)",
                           (new_id(), did, bid, filename, "application/octet-stream", len(content),
                            hashlib.sha256(content).hexdigest(), ids[owner], now))
                audit.append("document.upload", actor_email="system:seed", document_id=did,
                             details={"title": title, "owner": owner}, db=db)
            for title, grantee, perm in DEMO_GRANTS:
                did = doc_ids[title]
                owner = next(o for o, t, *_ in DEMO_DOCS if t == title)
                db.execute("INSERT INTO grants (id, document_id, user_id, permission, granted_by, created_at) "
                           "VALUES (?, ?, ?, ?, ?, ?)", (new_id(), did, ids[grantee], perm, ids[owner], now))
                audit.append("permission.grant", actor_email="system:seed", document_id=did,
                             target_user_id=ids[grantee], details={"permission": perm}, db=db)
        print(f"Seeded {len(DEMO_USERS)} users, {len(DEMO_DOCS)} documents, {len(DEMO_GRANTS)} grants.")


if __name__ == "__main__":
    app = create_app()
    if "--reset" in sys.argv:
        path = app.config["TV"].DATABASE_PATH
        for suffix in ("", "-wal", "-shm"):
            if os.path.exists(path + suffix):
                os.remove(path + suffix)
        app = create_app()
    seed(app)
