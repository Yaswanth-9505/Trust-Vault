"""Smoke-check a deployed TrustVault with the seeded demo accounts.

    python -m scripts.check_live https://YOURNAME.pythonanywhere.com

Signs in as Olivia (owner) and Victor (viewer), then confirms on the LIVE site
that Victor is refused Olivia's documents he was not granted, and that the
admin cannot download anything. Uses only the standard library.
"""
import http.cookiejar
import json
import sys
import urllib.error
import urllib.request


class Session:
    def __init__(self, base):
        self.base = base.rstrip("/")
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))

    def call(self, method, path, body=None):
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(self.base + path, data=data, method=method,
                                     headers={"Content-Type": "application/json"} if data else {})
        try:
            with self.opener.open(req, timeout=20) as r:
                return r.status, r.read()
        except urllib.error.HTTPError as e:
            return e.code, e.read()

    def login(self, email, password):
        status, body = self.call("POST", "/api/auth/login", {"email": email, "password": password})
        if status != 200:
            sys.exit(f"Could not sign in as {email} ({status}): {body[:200]!r}. Did you run the seed script?")


def main():
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    base = sys.argv[1]
    ok = True

    def check(label, passed):
        nonlocal ok
        ok &= passed
        print(("PASS  " if passed else "FAIL  ") + label)

    status, _ = Session(base).call("GET", "/healthz")
    check(f"site is up ({status})", status == 200)

    olivia, victor, admin = Session(base), Session(base), Session(base)
    olivia.login("olivia@trustvault.test", "Olivia-Demo-2026!")
    victor.login("victor@trustvault.test", "Victor-Demo-2026!")
    admin.login("admin@trustvault.test", "Admin-Demo-2026!")

    _, body = olivia.call("GET", "/api/documents?scope=mine")
    docs = {d["title"]: d["id"] for d in json.loads(body)["documents"]}
    target = docs.get("Salary letter - Vera")
    check("Olivia sees her own documents", target is not None)
    if target:
        s, b = olivia.call("GET", f"/api/documents/{target}/download")
        check("Olivia can download her document", s == 200)
        s, b = victor.call("GET", f"/api/documents/{target}/download")
        check(f"Victor is refused Vera's salary letter ({s})", s == 404 and b"%PDF" not in b)
        s, b = victor.call("GET", f"/api/documents/{target}")
        check(f"Victor cannot see its details ({s})", s == 404)
        s, b = admin.call("GET", f"/api/documents/{target}/download")
        check(f"Admin cannot download it ({s})", s == 404 and b"%PDF" not in b)
    s, b = victor.call("GET", "/api/documents?q=Salary")
    titles = [d["title"] for d in json.loads(b)["documents"]]
    check(f"Victor's search shows only his own letter: {titles}", titles == ["Salary letter - Victor"])
    s, _ = victor.call("GET", "/api/admin/audit")
    check(f"Victor cannot open the audit trail ({s})", s == 403)
    s, b = admin.call("GET", "/api/admin/audit/verify")
    check("Audit chain is intact", s == 200 and json.loads(b).get("valid") is True)

    print("\nAll checks passed." if ok else "\nSOMETHING IS WRONG - fix before submitting.")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
