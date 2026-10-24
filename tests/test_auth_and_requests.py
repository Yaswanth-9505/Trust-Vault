"""Authentication, sessions and forged requests.

THREATS.md: AN-1 (brute force), AN-2 (user enumeration), AN-3 (session theft from DB),
AN-4 (session fixation), RQ-1 (CSRF), RQ-2 (cross-origin), RQ-3 (XSS via stored content).
"""
import unittest

from app.security import token_hash
from tests.base import PASSWORD, TrustVaultTestCase


class Login(TrustVaultTestCase):
    def test_lockout_after_repeated_failures(self):
        c = self.app.test_client()
        for _ in range(self.cfg.LOGIN_MAX_FAILURES):
            c.post("/api/auth/login", json={"email": self.vera.email, "password": "nope-nope-nope"})
        # even the right password is refused while locked
        r = c.post("/api/auth/login", json={"email": self.vera.email, "password": PASSWORD})
        self.assertEqual(r.status_code, 401)
        self.admin.post(f"/api/admin/users/{self.vera.id}/unlock")
        r = c.post("/api/auth/login", json={"email": self.vera.email, "password": PASSWORD})
        self.assertEqual(r.status_code, 200)

    def test_unknown_email_and_wrong_password_look_the_same(self):
        c = self.app.test_client()
        a = c.post("/api/auth/login", json={"email": "nobody@test.local", "password": "x" * 12})
        b = c.post("/api/auth/login", json={"email": self.vera.email, "password": "x" * 12})
        self.assertEqual((a.status_code, a.get_json()), (b.status_code, b.get_json()))

    def test_ip_rate_limit(self):
        c = self.app.test_client()
        codes = [c.post("/api/auth/login", json={"email": f"x{i}@t.l", "password": "x" * 12}).status_code
                 for i in range(self.cfg.LOGIN_RATE_PER_IP + 2)]
        self.assertEqual(codes[-1], 429)

    def test_login_requires_json(self):
        c = self.app.test_client()
        r = c.post("/api/auth/login", data={"email": self.vera.email, "password": PASSWORD})
        self.assertEqual(r.status_code, 415)


class Sessions(TrustVaultTestCase):
    def test_database_holds_only_token_hashes(self):
        cookie = self.vera.client.get_cookie("tv_session").value
        db = self.db()
        rows = [r[0] for r in db.execute("SELECT token_hash FROM sessions")]
        db.close()
        self.assertNotIn(cookie, rows)
        self.assertIn(token_hash(cookie), rows)

    def test_login_issues_a_fresh_token(self):
        """AN-4: a cookie planted before login is not upgraded."""
        c = self.app.test_client()
        c.set_cookie("tv_session", "planted-token-value")
        c.post("/api/auth/login", json={"email": self.vera.email, "password": PASSWORD})
        self.assertNotEqual(c.get_cookie("tv_session").value, "planted-token-value")

    def test_cookie_flags(self):
        c = self.app.test_client()
        r = c.post("/api/auth/login", json={"email": self.vera.email, "password": PASSWORD})
        header = r.headers["Set-Cookie"]
        self.assertIn("HttpOnly", header)
        self.assertIn("SameSite=Strict", header)


class ForgedRequests(TrustVaultTestCase):
    def test_state_change_without_csrf_token_is_refused(self):
        doc = self.alice.upload()
        self.assertEqual(self.alice.delete(f"/api/documents/{doc}", csrf=False).status_code, 403)
        self.assertEqual(self.alice.post(f"/api/documents/{doc}/grants",
                                         {"user_id": self.mallory.id, "permission": "read"}, csrf=False).status_code, 403)
        self.assertEqual(self.mallory.get(f"/api/documents/{doc}").status_code, 404)

    def test_wrong_csrf_token_is_refused(self):
        doc = self.alice.upload()
        self.alice.csrf = self.vera.csrf  # someone else's token
        self.assertEqual(self.alice.delete(f"/api/documents/{doc}").status_code, 403)

    def test_cross_origin_request_is_refused_even_with_token(self):
        doc = self.alice.upload()
        r = self.alice.post(f"/api/documents/{doc}/grants", {"user_id": self.mallory.id, "permission": "read"},
                            headers={"Origin": "https://evil.example"})
        self.assertEqual(r.status_code, 403)
        self.assertTrue(self.audit_rows(action="security.bad_origin"))

    def test_security_headers(self):
        r = self.app.test_client().get("/")
        self.assertIn("script-src 'self'", r.headers["Content-Security-Policy"])
        self.assertEqual(r.headers["X-Frame-Options"], "DENY")
        self.assertEqual(r.headers["X-Content-Type-Options"], "nosniff")

    def test_api_responses_are_not_cached(self):
        self.assertEqual(self.vera.get("/api/documents").headers["Cache-Control"], "no-store")


class Directory(TrustVaultTestCase):
    def test_viewers_cannot_list_people(self):
        self.assertEqual(self.vera.get("/api/users/directory").status_code, 403)

    def test_directory_hides_deactivated_and_reveals_no_roles(self):
        self.admin.patch(f"/api/admin/users/{self.mallory.id}", {"active": False})
        users = self.alice.get("/api/users/directory").get_json()["users"]
        self.assertNotIn(self.mallory.id, [u["id"] for u in users])
        self.assertTrue(all(set(u) == {"id", "name", "email"} for u in users))


class AdminSelfProtection(TrustVaultTestCase):
    def test_admin_cannot_demote_or_deactivate_self(self):
        self.assertEqual(self.admin.patch(f"/api/admin/users/{self.admin.id}", {"active": False}).status_code, 400)
        self.assertEqual(self.admin.patch(f"/api/admin/users/{self.admin.id}", {"role": "viewer"}).status_code, 400)

    def test_cannot_create_user_with_weak_password_or_bad_role(self):
        r = self.admin.post("/api/admin/users", {"email": "a@b.c", "name": "A", "role": "viewer", "password": "short"})
        self.assertEqual(r.status_code, 400)
        r = self.admin.post("/api/admin/users", {"email": "a@b.c", "name": "A", "role": "root", "password": "x" * 14})
        self.assertEqual(r.status_code, 400)


if __name__ == "__main__":
    unittest.main()
