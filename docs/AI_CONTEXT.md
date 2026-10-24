# Context for AI tools working on TrustVault

Paste this at the start of any AI session about this repository.

You are working on TrustVault, a document-sharing system whose whole point is that the wrong person can never read a document, and that every access is provably recorded. Treat every change as a security change.

## Rules

1. **One decision point.** Any route that receives a document id calls `authorize(document_id, action)` from `app/authz.py` *before* reading or writing anything about that document. Use the row it returns. Never look up a document, version, grant, suggestion or blob by a client-supplied id alone. Always include the authorised document's id in the `WHERE`.
2. **Role never grants document access.** `authorize()` does not read `g.user["role"]`. Do not add an admin bypass.
3. **Writes and downloads** call `authorize()` inside `with transaction(db):`, so the check and the action happen under the same lock.
4. **Audit.** Every state change calls `audit.append(...)` inside the same transaction. Every refusal is recorded. Never `UPDATE` or `DELETE` `audit_log`.
5. **Input.** JSON bodies go through `json_body(allowed, required)`, which rejects unknown fields. All SQL is parameterised. LIKE input goes through `like_escape`.
6. **Output.** The UI uses `textContent` only, never `innerHTML` with data. Downloads stay `application/octet-stream` with `attachment`.
7. **Nothing that confers access goes to the client.** No signed URLs, no permission-bearing tokens.
8. **Tests.** For every new check, write a test that fails when the check is removed, and add that removal as a mutant in `scripts/mutation_check.py`. Run `python -m scripts.mutation_check <name>`.
9. **Don't trust yourself.** If you are confident a security property holds, write the test that would fail if you are wrong, and run it before saying so.

## Commands

- Run the tests: `python -m unittest discover -s tests -t .`
- Run the mutation check: `python -m scripts.mutation_check`
