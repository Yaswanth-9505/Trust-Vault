"""You can prove who reached a document, and the record cannot be quietly changed.

THREATS.md: AU-1 (row edited), AU-2 (row deleted), AU-3 (refusals recorded),
AU-4 (forged/reordered rows), AU-5 (action without record).
"""
import sqlite3
import unittest

from app.audit import verify_chain
from tests.base import TrustVaultTestCase, pdf_bytes


class AuditCoverage(TrustVaultTestCase):
    def test_every_required_event_is_recorded_with_actor(self):
        doc = self.alice.upload("Doc", "d.pdf", pdf_bytes())
        gid = self.alice.grant(doc, self.vera, "edit")
        self.vera.get(f"/api/documents/{doc}/download")
        self.vera.patch(f"/api/documents/{doc}", {"title": "Doc 2"})
        self.alice.patch(f"/api/documents/{doc}/grants/{gid}", {"permission": "read"})
        self.alice.delete(f"/api/documents/{doc}/grants/{gid}")
        self.alice.delete(f"/api/documents/{doc}")
        expected = [
            ("document.upload", self.alice.id), ("permission.grant", self.alice.id),
            ("document.download", self.vera.id), ("document.update", self.vera.id),
            ("permission.change", self.alice.id), ("permission.revoke", self.alice.id),
            ("document.delete", self.alice.id),
        ]
        got = [(r["action"], r["actor_id"]) for r in self.audit_rows(document_id=doc, outcome="success")]
        self.assertEqual(got, expected)

    def test_download_record_names_the_exact_file(self):
        doc = self.alice.upload("Doc", "d.pdf", pdf_bytes("CONTENT"))
        self.alice.grant(doc, self.vera)
        self.vera.get(f"/api/documents/{doc}/download")
        row = self.audit_rows(action="document.download", document_id=doc)[0]
        import hashlib
        import json
        self.assertEqual(json.loads(row["details"])["sha256"], hashlib.sha256(pdf_bytes("CONTENT")).hexdigest())
        self.assertEqual(row["actor_id"], self.vera.id)
        self.assertIsNotNone(row["ip"])

    def test_refusals_inside_transactions_are_still_recorded(self):
        """AU-3: a denial raised inside a write transaction must survive the rollback."""
        doc = self.alice.upload()
        self.mallory.delete(f"/api/documents/{doc}")
        self.mallory.post(f"/api/documents/{doc}/grants", {"user_id": self.mallory.id, "permission": "edit"})
        actions = {r["action"] for r in self.audit_rows(actor_id=self.mallory.id, outcome="denied")}
        self.assertIn("document.delete", actions)
        self.assertIn("document.share", actions)

    def test_failed_logins_are_recorded(self):
        self.app.test_client().post("/api/auth/login", json={"email": self.vera.email, "password": "wrong-wrong-wrong"})
        rows = self.audit_rows(action="auth.login", outcome="denied", target_user_id=self.vera.id)
        self.assertEqual(len(rows), 1)


class AuditTamperResistance(TrustVaultTestCase):
    def setUp(self):
        super().setUp()
        self.doc = self.alice.upload("Doc", "d.pdf", pdf_bytes())
        self.alice.grant(self.doc, self.vera)
        self.vera.get(f"/api/documents/{self.doc}/download")

    def verify(self):
        db = self.db()
        try:
            return verify_chain(db, self.cfg.AUDIT_KEY)
        finally:
            db.close()

    def test_chain_is_valid_after_normal_use(self):
        res = self.verify()
        self.assertTrue(res["valid"], res)
        r = self.admin.get("/api/admin/audit/verify").get_json()
        self.assertTrue(r["valid"])

    def test_database_refuses_update_and_delete(self):
        """AU-1 / AU-2, first layer."""
        db = self.db()
        with self.assertRaises(sqlite3.IntegrityError):
            db.execute("UPDATE audit_log SET actor_email = 'someone-else' WHERE action = 'document.download'")
        with self.assertRaises(sqlite3.IntegrityError):
            db.execute("DELETE FROM audit_log WHERE action = 'document.download'")
        db.close()

    def _without_triggers(self, sql, params=()):
        db = self.db()
        db.execute("DROP TRIGGER audit_log_no_update")
        db.execute("DROP TRIGGER audit_log_no_delete")
        db.execute(sql, params)
        db.close()

    def test_edited_row_is_detected_even_if_triggers_are_dropped(self):
        """AU-1, second layer: an attacker with the database file but not the key."""
        self._without_triggers("UPDATE audit_log SET actor_email = 'nobody@x' WHERE action = 'document.download'")
        res = self.verify()
        self.assertFalse(res["valid"])
        alerts = self.admin.get("/api/admin/alerts").get_json()["alerts"]
        self.assertEqual(alerts[0]["severity"], "critical")

    def test_deleted_row_is_detected(self):
        """AU-2: removing a record from the middle of the chain (here: the grant
        that explains why Vera could download) breaks every hash after it."""
        self._without_triggers("DELETE FROM audit_log WHERE action = 'permission.grant'")
        self.assertFalse(self.verify()["valid"])

    def test_deleting_the_tail_is_detected_by_comparing_with_an_export(self):
        """AU-2 (tail truncation): the chain alone cannot see the last rows vanish;
        an earlier export (or the stdout witness) can."""
        export = self.admin.get("/api/admin/audit/export").get_data(as_text=True).splitlines()
        import json
        last = json.loads(export[-1])
        self._without_triggers("DELETE FROM audit_log WHERE seq >= ?", (last["seq"],))
        self.assertTrue(self.verify()["valid"])  # truncation alone looks consistent...
        db = self.db()
        row = db.execute("SELECT hash FROM audit_log WHERE seq = ?", (last["seq"],)).fetchone()
        db.close()
        self.assertIsNone(row)  # ...but the export proves a record is missing

    def test_forged_row_without_key_is_detected(self):
        """AU-4"""
        db = self.db()
        last = db.execute("SELECT seq, hash FROM audit_log ORDER BY seq DESC LIMIT 1").fetchone()
        db.execute("INSERT INTO audit_log (seq, ts, action, outcome, details, prev_hash, hash) "
                   "VALUES (?, '2026-01-01T00:00:00.000000Z', 'document.download', 'success', '{}', ?, ?)",
                   (last["seq"] + 1, last["hash"], "f" * 64))
        db.close()
        self.assertFalse(self.verify()["valid"])

    def test_audit_failure_blocks_the_download(self):
        """AU-5: no record, no download (fail closed)."""
        db = self.db()
        db.execute("CREATE TRIGGER block_audit BEFORE INSERT ON audit_log BEGIN SELECT RAISE(ABORT, 'disk full'); END")
        db.close()
        r = self.vera.get(f"/api/documents/{self.doc}/download")
        self.assertEqual(r.status_code, 500)
        self.assertNotIn(b"%PDF", r.data)


if __name__ == "__main__":
    unittest.main()
