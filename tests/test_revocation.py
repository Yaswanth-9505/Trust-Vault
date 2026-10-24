"""Taking access away works immediately - for everything issued before that moment.

THREATS.md: RV-1 (revoked grant), RV-2 (expired grant), RV-3 (deactivated user),
RV-4 (role change), RV-5 (password reset), RV-6 (logout replay).
"""
import unittest
from datetime import timedelta

from app.db import iso, utcnow
from tests.base import TrustVaultTestCase, pdf_bytes


class RevokedGrant(TrustVaultTestCase):
    def test_revocation_stops_the_very_next_request_on_the_same_session(self):
        doc = self.alice.upload("Plan", "p.pdf", pdf_bytes("PLAN"))
        gid = self.alice.grant(doc, self.vera)
        # Vera has an open page and a working download link...
        self.assertEqual(self.vera.get(f"/api/documents/{doc}/download").status_code, 200)
        self.assertEqual(self.alice.delete(f"/api/documents/{doc}/grants/{gid}").status_code, 200)
        # ...and the same session, same URL, is now refused everywhere.
        self.assertEqual(self.vera.get(f"/api/documents/{doc}/download").status_code, 404)
        self.assertEqual(self.vera.get(f"/api/documents/{doc}/download?version=1").status_code, 404)
        self.assertEqual(self.vera.get(f"/api/documents/{doc}").status_code, 404)
        self.assertEqual(self.vera.get("/api/documents?q=Plan").get_json()["total"], 0)
        self.assertTrue(self.audit_rows(action="permission.revoke", document_id=doc))

    def test_downgrade_from_edit_to_read_is_immediate(self):
        doc = self.alice.upload()
        gid = self.alice.grant(doc, self.vera, "edit")
        self.assertEqual(self.vera.patch(f"/api/documents/{doc}", {"title": "a"}).status_code, 200)
        self.alice.patch(f"/api/documents/{doc}/grants/{gid}", {"permission": "read"})
        self.assertEqual(self.vera.patch(f"/api/documents/{doc}", {"title": "b"}).status_code, 403)

    def test_regranting_after_revoke_creates_a_new_grant(self):
        doc = self.alice.upload()
        gid = self.alice.grant(doc, self.vera)
        self.alice.delete(f"/api/documents/{doc}/grants/{gid}")
        gid2 = self.alice.grant(doc, self.vera)
        self.assertNotEqual(gid, gid2)
        # the old grant id cannot be "un-revoked" or modified
        self.assertEqual(self.alice.patch(f"/api/documents/{doc}/grants/{gid}", {"permission": "edit"}).status_code, 404)


class ExpiredGrant(TrustVaultTestCase):
    def test_expired_grant_gives_nothing(self):
        doc = self.alice.upload("Temp", "t.pdf", pdf_bytes("TEMP"))
        gid = self.alice.grant(doc, self.vera, expires_at=iso(utcnow() + timedelta(days=1)))
        self.assertEqual(self.vera.get(f"/api/documents/{doc}/download").status_code, 200)
        db = self.db()  # move the clock: set the expiry into the past
        db.execute("UPDATE grants SET expires_at = ? WHERE id = ?", (iso(utcnow() - timedelta(seconds=1)), gid))
        db.close()
        self.assertEqual(self.vera.get(f"/api/documents/{doc}/download").status_code, 404)
        self.assertEqual(self.vera.get("/api/documents").get_json()["total"], 0)

    def test_expiry_must_be_in_the_future(self):
        doc = self.alice.upload()
        r = self.alice.post(f"/api/documents/{doc}/grants",
                            {"user_id": self.vera.id, "permission": "read", "expires_at": "2001-01-01"})
        self.assertEqual(r.status_code, 400)


class AccountChanges(TrustVaultTestCase):
    def setUp(self):
        super().setUp()
        self.doc = self.alice.upload("Shared", "s.pdf", pdf_bytes("SHARED"))
        self.alice.grant(self.doc, self.vera)
        self.assertEqual(self.vera.get(f"/api/documents/{self.doc}/download").status_code, 200)

    def test_deactivated_user_is_cut_off_mid_session(self):
        r = self.admin.patch(f"/api/admin/users/{self.vera.id}", {"active": False})
        self.assertEqual(r.status_code, 200)
        self.assertEqual(self.vera.get(f"/api/documents/{self.doc}/download").status_code, 401)
        self.assertEqual(self.vera.login().status_code, 401)

    def test_deactivation_is_enforced_even_if_session_rows_survived(self):
        """Defence in depth: the session lookup itself checks is_active."""
        db = self.db()
        db.execute("UPDATE users SET is_active = 0 WHERE id = ?", (self.vera.id,))
        db.close()
        self.assertEqual(self.vera.get(f"/api/documents/{self.doc}/download").status_code, 401)

    def test_role_change_ends_sessions(self):
        self.admin.patch(f"/api/admin/users/{self.vera.id}", {"role": "owner"})
        self.assertEqual(self.vera.get("/api/documents").status_code, 401)

    def test_admin_password_reset_ends_sessions(self):
        self.admin.post(f"/api/admin/users/{self.vera.id}/reset-password", {"new_password": "Another-Long-Pass-1"})
        self.assertEqual(self.vera.get(f"/api/documents/{self.doc}/download").status_code, 401)

    def test_logout_kills_the_session_server_side(self):
        cookie = self.vera.client.get_cookie("tv_session").value
        self.vera.post("/api/auth/logout")
        replay = self.app.test_client()
        replay.set_cookie("tv_session", cookie)
        self.assertEqual(replay.get(f"/api/documents/{self.doc}/download").status_code, 401)

    def test_own_password_change_ends_other_sessions(self):
        laptop = self.vera
        from tests.base import Person
        phone = Person(self.app, self.vera.id, self.vera.email)
        r = laptop.post("/api/auth/password", {"current_password": "Correct-Horse-9!", "new_password": "Brand-New-Pass-2026"})
        self.assertEqual(r.status_code, 200)
        self.assertEqual(laptop.get("/api/documents").status_code, 200)
        self.assertEqual(phone.get("/api/documents").status_code, 401)

    def test_idle_session_expires(self):
        db = self.db()
        db.execute("UPDATE sessions SET last_seen_at = ? WHERE user_id = ?",
                   (iso(utcnow() - timedelta(minutes=31)), self.vera.id))
        db.close()
        self.assertEqual(self.vera.get("/api/documents").status_code, 401)

    def test_absolute_session_lifetime(self):
        db = self.db()
        db.execute("UPDATE sessions SET expires_at = ? WHERE user_id = ?",
                   (iso(utcnow() - timedelta(seconds=1)), self.vera.id))
        db.close()
        self.assertEqual(self.vera.get("/api/documents").status_code, 401)


if __name__ == "__main__":
    unittest.main()
