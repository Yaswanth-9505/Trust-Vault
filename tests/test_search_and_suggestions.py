"""Search never leaks, and suggestions never widen access.

THREATS.md: SR-1 (search leakage), SR-2 (wildcard injection), SR-3 (SQL injection),
AI-1 (automatic widening), AI-2 (suggestion id confusion).
"""
import json
import unittest

from tests.base import TrustVaultTestCase


class Search(TrustVaultTestCase):
    def setUp(self):
        super().setUp()
        self.secret = self.alice.upload("Merger plan Zeta", "m.pdf", category="Legal")
        self.shared = self.alice.upload("Holiday rota", "h.pdf", category="HR")
        self.alice.grant(self.shared, self.vera)

    def titles(self, person, query=""):
        return [d["title"] for d in person.get("/api/documents?" + query).get_json()["documents"]]

    def test_search_only_returns_accessible_documents(self):
        self.assertEqual(self.titles(self.vera), ["Holiday rota"])
        self.assertEqual(self.titles(self.vera, "q=Merger"), [])
        self.assertEqual(self.titles(self.mallory, "q=Merger"), [])
        self.assertEqual(self.mallory.get("/api/documents?q=Merger").get_json()["total"], 0)

    def test_filters_by_owner_category_and_date(self):
        self.assertEqual(self.titles(self.vera, "owner=" + self.alice.email), ["Holiday rota"])
        self.assertEqual(self.titles(self.alice, "category=Legal"), ["Merger plan Zeta"])
        self.assertEqual(self.titles(self.alice, "from=2000-01-01&to=2000-01-02"), [])
        self.assertEqual(len(self.titles(self.alice, "from=2000-01-01")), 2)

    def test_owner_filter_cannot_be_used_to_count_hidden_documents(self):
        r = self.mallory.get("/api/documents?owner=" + self.alice.email).get_json()
        self.assertEqual(r["total"], 0)

    def test_wildcards_are_literal(self):
        self.assertEqual(self.titles(self.mallory, "q=%25"), [])
        self.assertEqual(self.titles(self.mallory, "q=_"), [])
        self.assertEqual(self.titles(self.alice, "q=%25"), [])  # nothing actually contains '%'

    def test_sql_injection_attempts_are_plain_text(self):
        for q in ("' OR 1=1--", "\") OR 1=1--", "x' UNION SELECT * FROM blobs--"):
            with self.subTest(q=q):
                r = self.mallory.get("/api/documents", query_string={"q": q, "owner": q})
                self.assertEqual(r.status_code, 200)
                self.assertEqual(r.get_json()["total"], 0)

    def test_bad_filter_values_are_rejected(self):
        self.assertEqual(self.vera.get("/api/documents?category=Secret").status_code, 400)
        self.assertEqual(self.vera.get("/api/documents?from=yesterday").status_code, 400)
        self.assertEqual(self.vera.get("/api/documents?sort=1;DROP").status_code, 400)


class Suggestions(TrustVaultTestCase):
    def setUp(self):
        super().setUp()
        self.old = self.alice.upload("Payroll March", category="Finance")
        self.alice.grant(self.old, self.vera)
        self.new = self.alice.upload("Payroll April", category="Finance")

    def test_suggestion_does_not_grant_anything(self):
        r = self.alice.post(f"/api/documents/{self.new}/suggestions")
        sugg = r.get_json()["suggestions"]
        self.assertEqual([s["user"]["id"] for s in sugg], [self.vera.id])
        # Nothing changed: Vera still cannot open the new document.
        self.assertEqual(self.vera.get(f"/api/documents/{self.new}").status_code, 404)
        self.assertEqual(self.alice.get(f"/api/documents/{self.new}/grants").get_json()["grants"], [])
        shown = self.audit_rows(action="suggestion.shown", document_id=self.new)
        self.assertEqual(json.loads(shown[0]["details"])["suggested"], [self.vera.email])

    def test_accepting_records_both_suggestion_and_decision(self):
        sid = self.alice.post(f"/api/documents/{self.new}/suggestions").get_json()["suggestions"][0]["id"]
        r = self.alice.post(f"/api/documents/{self.new}/suggestions/{sid}/accept", {"permission": "read"})
        self.assertEqual(r.status_code, 201)
        self.assertEqual(r.get_json()["grant"]["source"], "suggestion")
        self.assertEqual(self.vera.get(f"/api/documents/{self.new}").status_code, 200)
        grant_row = self.audit_rows(action="permission.grant", document_id=self.new)[0]
        self.assertEqual(grant_row["actor_id"], self.alice.id)  # a person decided
        self.assertEqual(json.loads(grant_row["details"])["suggestion_id"], sid)
        self.assertTrue(self.audit_rows(action="suggestion.accepted", document_id=self.new))

    def test_only_the_owner_can_see_or_accept_suggestions(self):
        sid = self.alice.post(f"/api/documents/{self.new}/suggestions").get_json()["suggestions"][0]["id"]
        self.assertEqual(self.vera.post(f"/api/documents/{self.new}/suggestions/{sid}/accept",
                                        {"permission": "edit"}).status_code, 404)
        self.assertEqual(self.vera.get(f"/api/documents/{self.new}").status_code, 404)

    def test_suggestion_id_from_another_document_is_refused(self):
        sid = self.alice.post(f"/api/documents/{self.new}/suggestions").get_json()["suggestions"][0]["id"]
        other = self.alice.upload("Unrelated", category="HR")
        r = self.alice.post(f"/api/documents/{other}/suggestions/{sid}/accept", {"permission": "read"})
        self.assertEqual(r.status_code, 404)
        self.assertEqual(self.vera.get(f"/api/documents/{other}").status_code, 404)

    def test_dismissed_suggestion_cannot_be_accepted(self):
        sid = self.alice.post(f"/api/documents/{self.new}/suggestions").get_json()["suggestions"][0]["id"]
        self.alice.post(f"/api/documents/{self.new}/suggestions/{sid}/dismiss")
        r = self.alice.post(f"/api/documents/{self.new}/suggestions/{sid}/accept", {"permission": "read"})
        self.assertEqual(r.status_code, 404)


if __name__ == "__main__":
    unittest.main()
