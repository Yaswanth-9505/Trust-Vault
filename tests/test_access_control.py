"""One user cannot reach another user's documents - through any route.

THREATS.md: AC-1 (IDOR), AC-2 (level escalation), AC-3 (admin bypass),
AC-4 (version / grant id confusion), AC-5 (deleted documents), AC-6 (unauthenticated).
"""
import io
import unittest

from tests.base import TrustVaultTestCase, pdf_bytes


class EveryRouteRefusesStrangers(TrustVaultTestCase):
    """AC-1: walk every route that takes a document id, as someone with no grant."""

    def routes(self, doc_id, grant_id):
        return [
            ("GET",    f"/api/documents/{doc_id}", None),
            ("GET",    f"/api/documents/{doc_id}/download", None),
            ("GET",    f"/api/documents/{doc_id}/download?version=1", None),
            ("PATCH",  f"/api/documents/{doc_id}", {"title": "pwned"}),
            ("POST",   f"/api/documents/{doc_id}/versions", "FILE"),
            ("DELETE", f"/api/documents/{doc_id}", None),
            ("POST",   f"/api/documents/{doc_id}/restore", None),
            ("GET",    f"/api/documents/{doc_id}/activity", None),
            ("GET",    f"/api/documents/{doc_id}/grants", None),
            ("POST",   f"/api/documents/{doc_id}/grants", {"user_id": "X", "permission": "edit"}),
            ("PATCH",  f"/api/documents/{doc_id}/grants/{grant_id}", {"permission": "edit"}),
            ("DELETE", f"/api/documents/{doc_id}/grants/{grant_id}", None),
            ("POST",   f"/api/documents/{doc_id}/suggestions", None),
        ]

    def call(self, person, method, path, body):
        if body == "FILE":
            return person.post(path, data={"file": (io.BytesIO(pdf_bytes("x")), "x.pdf")})
        if isinstance(body, dict) and body.get("user_id") == "X":
            body = {**body, "user_id": person.id}  # try to grant themselves
        return {"GET": lambda: person.get(path), "POST": lambda: person.post(path, json=body),
                "PATCH": lambda: person.patch(path, json=body), "DELETE": lambda: person.delete(path)}[method]()

    def test_strangers_get_404_on_every_route_and_nothing_changes(self):
        doc = self.alice.upload("Salary letter", "salary.pdf", pdf_bytes("SECRET-SALARY"))
        grant = self.alice.grant(doc, self.vera)
        for stranger in (self.mallory, self.bob, self.admin):
            for method, path, body in self.routes(doc, grant):
                with self.subTest(who=stranger.email, route=f"{method} {path}"):
                    r = self.call(stranger, method, path, body)
                    self.assertRefused(r, (404,))
                    self.assertNotIn(b"SECRET-SALARY", r.data)
                    self.assertNotIn(b"Salary letter", r.data)  # not even the title

        # Nothing was changed by any of that.
        r = self.alice.get(f"/api/documents/{doc}")
        self.assertEqual(r.get_json()["document"]["title"], "Salary letter")
        self.assertEqual(r.get_json()["document"]["current_version"], 1)
        grants = self.alice.get(f"/api/documents/{doc}/grants").get_json()["grants"]
        self.assertEqual([g["user"]["id"] for g in grants], [self.vera.id])
        self.assertEqual(grants[0]["permission"], "read")

    def test_unknown_and_forbidden_documents_look_identical(self):
        """AC-1: the response must not reveal whether an id exists."""
        doc = self.alice.upload()
        real = self.mallory.get(f"/api/documents/{doc}")
        fake = self.mallory.get(f"/api/documents/{'0' * 32}")
        self.assertEqual(real.status_code, fake.status_code)
        self.assertEqual(real.get_json(), fake.get_json())

    def test_refused_attempts_are_recorded(self):
        """AU-3: denied attempts are evidence too."""
        doc = self.alice.upload()
        self.mallory.get(f"/api/documents/{doc}/download")
        rows = self.audit_rows(actor_id=self.mallory.id, outcome="denied")
        self.assertTrue(any(r["action"] == "document.download" and r["document_id"] == doc for r in rows))


class GrantLevelsAreEnforced(TrustVaultTestCase):
    """AC-2: having some access does not give more access."""

    def setUp(self):
        super().setUp()
        self.doc = self.alice.upload("Contract", "c.pdf", pdf_bytes("CONTRACT"))

    def test_reader_can_read_and_download(self):
        self.alice.grant(self.doc, self.vera, "read")
        self.assertEqual(self.vera.get(f"/api/documents/{self.doc}").status_code, 200)
        r = self.vera.get(f"/api/documents/{self.doc}/download")
        self.assertEqual(r.status_code, 200)
        self.assertIn(b"CONTRACT", r.data)

    def test_reader_cannot_edit_upload_delete_share_or_see_activity(self):
        self.alice.grant(self.doc, self.vera, "read")
        self.assertRefused(self.vera.patch(f"/api/documents/{self.doc}", {"title": "x"}), (403,))
        self.assertRefused(self.vera.post(f"/api/documents/{self.doc}/versions",
                                          data={"file": (io.BytesIO(pdf_bytes()), "v.pdf")}), (403,))
        self.assertRefused(self.vera.delete(f"/api/documents/{self.doc}"), (403,))
        self.assertRefused(self.vera.get(f"/api/documents/{self.doc}/grants"), (403,))
        self.assertRefused(self.vera.post(f"/api/documents/{self.doc}/grants",
                                          {"user_id": self.mallory.id, "permission": "read"}), (403,))
        self.assertRefused(self.vera.get(f"/api/documents/{self.doc}/activity"), (403,))
        self.assertEqual(self.alice.get(f"/api/documents/{self.doc}").get_json()["document"]["title"], "Contract")

    def test_editor_can_edit_but_cannot_reshare_delete_or_upgrade_self(self):
        gid = self.alice.grant(self.doc, self.vera, "edit")
        self.assertEqual(self.vera.patch(f"/api/documents/{self.doc}", {"title": "Contract v2"}).status_code, 200)
        r = self.vera.post(f"/api/documents/{self.doc}/versions", data={"file": (io.BytesIO(pdf_bytes("V2")), "v2.pdf")})
        self.assertEqual(r.status_code, 201)
        # cannot pass access on
        self.assertRefused(self.vera.post(f"/api/documents/{self.doc}/grants",
                                          {"user_id": self.mallory.id, "permission": "read"}), (403,))
        # cannot touch their own grant
        self.assertRefused(self.vera.delete(f"/api/documents/{self.doc}/grants/{gid}"), (403,))
        # cannot delete
        self.assertRefused(self.vera.delete(f"/api/documents/{self.doc}"), (403,))
        self.assertEqual(self.mallory.get(f"/api/documents/{self.doc}").status_code, 404)

    def test_cannot_change_owner_through_metadata_update(self):
        """AC-7: mass assignment."""
        self.alice.grant(self.doc, self.vera, "edit")
        r = self.vera.patch(f"/api/documents/{self.doc}", {"title": "x", "owner_id": self.vera.id})
        self.assertEqual(r.status_code, 400)
        r = self.vera.patch(f"/api/documents/{self.doc}", {"deleted_at": None})
        self.assertEqual(r.status_code, 400)
        self.assertEqual(self.alice.get(f"/api/documents/{self.doc}").get_json()["document"]["owner"]["id"], self.alice.id)

    def test_viewer_role_cannot_create_documents(self):
        r = self.vera.post("/api/documents", data={"title": "x", "category": "HR",
                                                   "file": (io.BytesIO(pdf_bytes()), "x.pdf")})
        self.assertEqual(r.status_code, 403)

    def test_cannot_grant_to_self_or_owner(self):
        r = self.alice.post(f"/api/documents/{self.doc}/grants", {"user_id": self.alice.id, "permission": "read"})
        self.assertEqual(r.status_code, 400)


class AdminHasNoBackdoor(TrustVaultTestCase):
    """AC-3: the administrator role grants no access to document content."""

    def test_admin_cannot_read_or_download(self):
        doc = self.alice.upload("HR file", "hr.pdf", pdf_bytes("HR-SECRET"))
        self.assertEqual(self.admin.get(f"/api/documents/{doc}").status_code, 404)
        r = self.admin.get(f"/api/documents/{doc}/download")
        self.assertEqual(r.status_code, 404)
        self.assertNotIn(b"HR-SECRET", r.data)
        listing = self.admin.get("/api/documents").get_json()
        self.assertEqual(listing["total"], 0)

    def test_admin_metadata_view_has_no_content(self):
        doc = self.alice.upload("HR file", "hr.pdf", pdf_bytes("HR-SECRET"))
        r = self.admin.get("/api/admin/documents")
        self.assertEqual(r.status_code, 200)
        self.assertNotIn(b"HR-SECRET", r.data)
        self.assertIn(doc, r.get_data(as_text=True))

    def test_admin_cannot_transfer_document_to_self(self):
        doc = self.alice.upload()
        r = self.admin.post(f"/api/admin/documents/{doc}/transfer", {"new_owner_id": self.admin.id})
        self.assertEqual(r.status_code, 403)
        self.assertEqual(self.admin.get(f"/api/documents/{doc}/download").status_code, 404)

    def test_transfer_moves_access_and_is_audited(self):
        doc = self.alice.upload()
        r = self.admin.post(f"/api/admin/documents/{doc}/transfer", {"new_owner_id": self.bob.id})
        self.assertEqual(r.status_code, 200)
        self.assertEqual(self.bob.get(f"/api/documents/{doc}/download").status_code, 200)
        self.assertEqual(self.alice.get(f"/api/documents/{doc}/download").status_code, 404)
        self.assertTrue(self.audit_rows(action="admin.ownership_transfer", document_id=doc, outcome="success"))

    def test_non_admins_cannot_use_admin_routes(self):
        for p in (self.alice, self.vera, self.mallory):
            for path in ("/api/admin/users", "/api/admin/audit", "/api/admin/alerts",
                         "/api/admin/documents", "/api/admin/audit/verify", "/api/admin/audit/export"):
                with self.subTest(who=p.email, path=path):
                    self.assertEqual(p.get(path).status_code, 403)
            r = p.patch(f"/api/admin/users/{p.id}", {"role": "admin"})
            self.assertEqual(r.status_code, 403)
        db = self.db()
        self.assertEqual(db.execute("SELECT role FROM users WHERE id = ?", (self.vera.id,)).fetchone()[0], "viewer")
        db.close()


class IdConfusion(TrustVaultTestCase):
    """AC-4: ids that belong to a different document."""

    def test_cannot_revoke_or_change_a_grant_on_someone_elses_document_via_own_document(self):
        alice_doc = self.alice.upload("Alice's")
        bob_doc = self.bob.upload("Bob's")
        bob_grant = self.bob.grant(bob_doc, self.vera, "read")
        # Alice uses her own document id with Bob's grant id.
        self.assertEqual(self.alice.delete(f"/api/documents/{alice_doc}/grants/{bob_grant}").status_code, 404)
        self.assertEqual(self.alice.patch(f"/api/documents/{alice_doc}/grants/{bob_grant}",
                                          {"permission": "edit"}).status_code, 404)
        self.assertEqual(self.vera.get(f"/api/documents/{bob_doc}/download").status_code, 200)
        g = self.bob.get(f"/api/documents/{bob_doc}/grants").get_json()["grants"][0]
        self.assertEqual(g["permission"], "read")

    def test_version_numbers_are_scoped_to_the_document(self):
        doc = self.alice.upload("Mine", "m.pdf", pdf_bytes("MINE"))
        self.alice.grant(doc, self.vera)
        for v in ("0", "2", "-1", "1;", "abc", "99999999999999999999"):
            with self.subTest(version=v):
                self.assertEqual(self.vera.get(f"/api/documents/{doc}/download?version={v}").status_code, 404)

    def test_malformed_ids_are_rejected_cleanly(self):
        for bad in ("../../etc/passwd", "%27%20OR%201=1--", "a" * 500, "' OR '1'='1"):
            with self.subTest(bad=bad):
                r = self.mallory.get(f"/api/documents/{bad}/download")
                self.assertIn(r.status_code, (404,))


class DeletedDocuments(TrustVaultTestCase):
    """AC-5: a trashed document is unreachable, even by people who were granted it."""

    def test_trash_blocks_everyone_until_restored(self):
        doc = self.alice.upload("Old", "o.pdf", pdf_bytes("OLD"))
        self.alice.grant(doc, self.vera)
        self.assertEqual(self.alice.delete(f"/api/documents/{doc}").status_code, 200)
        self.assertEqual(self.vera.get(f"/api/documents/{doc}/download").status_code, 404)
        self.assertEqual(self.alice.get(f"/api/documents/{doc}/download").status_code, 404)
        self.assertEqual(self.vera.get("/api/documents").get_json()["total"], 0)
        # only the owner can restore
        self.assertRefused(self.vera.post(f"/api/documents/{doc}/restore"))
        self.assertEqual(self.mallory.post(f"/api/documents/{doc}/restore").status_code, 404)
        self.assertEqual(self.alice.post(f"/api/documents/{doc}/restore").status_code, 200)
        self.assertEqual(self.vera.get(f"/api/documents/{doc}/download").status_code, 200)

    def test_purged_documents_are_gone(self):
        from app.retention import purge_expired
        doc = self.alice.upload("Old", "o.pdf", pdf_bytes("OLD"))
        self.alice.delete(f"/api/documents/{doc}")
        with self.app.app_context():
            from app.db import get_db
            purged = purge_expired(get_db(), retention_days=-1)
        self.assertEqual(purged, [doc])
        self.assertEqual(self.alice.post(f"/api/documents/{doc}/restore").status_code, 404)
        db = self.db()
        self.assertEqual(db.execute("SELECT COUNT(*) FROM blobs").fetchone()[0], 0)
        db.close()


class Unauthenticated(TrustVaultTestCase):
    """AC-6: no session, no access."""

    def test_every_document_route_needs_a_session(self):
        doc = self.alice.upload()
        anon = self.app.test_client()
        for method, path in (("GET", "/api/documents"), ("GET", f"/api/documents/{doc}"),
                             ("GET", f"/api/documents/{doc}/download"), ("GET", "/api/users/directory"),
                             ("GET", "/api/admin/audit"), ("DELETE", f"/api/documents/{doc}")):
            with self.subTest(route=f"{method} {path}"):
                r = anon.open(path, method=method)
                self.assertEqual(r.status_code, 401)

    def test_forged_cookie_is_ignored(self):
        doc = self.alice.upload()
        anon = self.app.test_client()
        anon.set_cookie("tv_session", "A" * 43)
        self.assertEqual(anon.get(f"/api/documents/{doc}").status_code, 401)


if __name__ == "__main__":
    unittest.main()
