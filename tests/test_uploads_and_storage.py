"""Upload validation and how files are stored and served.

THREATS.md: UP-1 (active content), UP-2 (type spoofing), UP-3 (path traversal),
UP-4 (size / resource), ST-1 (files at rest), ST-2 (direct file URLs), ST-3 (download rendering).
"""
import io
import unittest

from tests.base import TrustVaultTestCase, docx_bytes, pdf_bytes


class UploadValidation(TrustVaultTestCase):
    def up(self, filename, content, title="t"):
        return self.alice.post("/api/documents", data={"title": title, "category": "HR",
                                                         "file": (io.BytesIO(content), filename)})

    def test_accepts_allowed_types(self):
        for name, content in (("a.pdf", pdf_bytes()), ("a.txt", b"hi\n"), ("a.csv", b"a,b\n1,2\n"),
                              ("a.png", b"\x89PNG\r\n\x1a\n" + b"0" * 20), ("a.jpg", b"\xff\xd8\xff\xe0" + b"0" * 20),
                              ("a.docx", docx_bytes())):
            with self.subTest(name=name):
                self.assertEqual(self.up(name, content).status_code, 201)

    def test_rejects_active_content_types(self):
        for name, content in (("x.html", b"<script>alert(1)</script>"), ("x.svg", b"<svg onload=alert(1)>"),
                              ("x.exe", b"MZ\x90\x00"), ("x.js", b"alert(1)"), ("x.pdf.html", b"<html>"),
                              ("noextension", b"data")):
            with self.subTest(name=name):
                self.assertIn(self.up(name, content).status_code, (400, 415))

    def test_rejects_content_that_does_not_match_extension(self):
        for name, content in (("evil.pdf", b"MZ\x90\x00 windows exe"), ("evil.png", b"<html>"),
                              ("evil.docx", pdf_bytes()), ("evil.txt", b"\x00\x01binary")):
            with self.subTest(name=name):
                self.assertEqual(self.up(name, content).status_code, 415)

    def test_rejects_pdf_with_javascript_and_office_with_macros(self):
        self.assertEqual(self.up("js.pdf", b"%PDF-1.4\n<< /OpenAction << /S /JavaScript /JS (app.alert(1)) >> >>").status_code, 415)
        import zipfile
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            z.writestr("[Content_Types].xml", "<Types/>")
            z.writestr("word/document.xml", "<d/>")
            z.writestr("word/vbaProject.bin", b"macro")
        self.assertEqual(self.up("macro.docx", buf.getvalue()).status_code, 415)

    def test_empty_and_oversized_files(self):
        self.assertEqual(self.up("e.txt", b"").status_code, 400)
        big = b"%PDF-1.4\n" + b"0" * (self.cfg.MAX_UPLOAD_BYTES + 10)
        self.assertEqual(self.up("big.pdf", big).status_code, 413)

    def test_path_traversal_in_filename_is_neutralised(self):
        r = self.up("../../../../etc/passwd.txt", b"root:x:0:0\n")
        self.assertEqual(r.status_code, 201)
        self.assertEqual(r.get_json()["document"]["filename"], "passwd.txt")
        r = self.up("..\\..\\windows\\evil.txt", b"x")
        self.assertEqual(r.get_json()["document"]["filename"], "evil.txt")

    def test_bidi_override_in_filename_is_removed(self):
        r = self.up("invoice‮gpj.txt", b"x")
        self.assertEqual(r.status_code, 201)
        self.assertNotIn("‮", r.get_json()["document"]["filename"])

    def test_title_is_stored_as_text_not_markup(self):
        r = self.up("a.txt", b"x", title="<img src=x onerror=alert(1)>")
        self.assertEqual(r.status_code, 201)
        # The API returns JSON; the UI only uses textContent. The CSP forbids inline script regardless.
        self.assertEqual(r.content_type, "application/json")


class Storage(TrustVaultTestCase):
    def test_file_content_is_encrypted_at_rest(self):
        self.alice.upload("Secret", "s.txt", b"THE-PLAINTEXT-SECRET")
        import os
        raw = b""
        for path in (self.cfg.DATABASE_PATH, self.cfg.DATABASE_PATH + "-wal"):
            if os.path.exists(path):
                with open(path, "rb") as f:
                    raw += f.read()
        self.assertNotIn(b"THE-PLAINTEXT-SECRET", raw)

    def test_no_static_route_serves_stored_files(self):
        doc = self.alice.upload("Secret", "s.txt", b"SECRET")
        anon = self.app.test_client()
        for path in (f"/static/{doc}", "/static/../instance/trustvault.db", "/instance/trustvault.db",
                     "/static/..%2f..%2fapp%2fschema.sql", "/uploads/s.txt"):
            with self.subTest(path=path):
                r = anon.get(path)
                self.assertIn(r.status_code, (400, 404))
                self.assertNotIn(b"SECRET", r.data)

    def test_downloads_are_never_rendered_by_the_browser(self):
        doc = self.alice.upload("Page", "p.txt", b"<html><script>alert(1)</script></html>")
        r = self.alice.get(f"/api/documents/{doc}/download")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.mimetype, "application/octet-stream")
        self.assertTrue(r.headers["Content-Disposition"].startswith("attachment;"))
        self.assertIn("sandbox", r.headers["Content-Security-Policy"])
        self.assertEqual(r.headers["X-Content-Type-Options"], "nosniff")
        self.assertIn("no-store", r.headers["Cache-Control"])

    def test_header_injection_through_filename_is_impossible(self):
        """Even if a hostile filename reached the database, the download header
        must stay a single, well-formed header."""
        doc = self.alice.upload("H", "h.txt", b"x")
        db = self.db()
        db.execute("UPDATE document_versions SET filename = ? WHERE document_id = ?",
                   ('a"\r\nSet-Cookie: x=1;\u00e9.txt', doc))
        db.close()
        r = self.alice.get(f"/api/documents/{doc}/download")
        self.assertEqual(r.status_code, 200)
        self.assertNotIn("x=1", r.headers.get("Set-Cookie", ""))
        self.assertNotIn("\n", r.headers["Content-Disposition"])

    def test_versions_keep_old_content(self):
        doc = self.alice.upload("V", "v.txt", b"FIRST")
        self.alice.post(f"/api/documents/{doc}/versions", data={"file": (io.BytesIO(b"SECOND"), "v.txt")})
        self.assertEqual(self.alice.get(f"/api/documents/{doc}/download").data, b"SECOND")
        self.assertEqual(self.alice.get(f"/api/documents/{doc}/download?version=1").data, b"FIRST")


if __name__ == "__main__":
    unittest.main()
