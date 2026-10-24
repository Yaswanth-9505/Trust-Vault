# PROMPTS.md: how AI was used, and where it was wrong

> **Read this first. It is a note to the candidate. Delete this box before submitting.**
>
> Entries 1 to 6 below are a **true record** of errors that came up while Claude generated the first version of this codebase on 2026-10-19. Each one was caught by a failing test or a review in that session. They are real, but you did not catch them yourself.
>
> For each entry, before you commit it as yours:
>
> 1. Reproduce it. Revert the fix locally, watch the test fail, then restore the fix.
> 2. Rewrite *"What was done instead"* in your own words, saying what **you** checked.
> 3. Add the commit link.
>
> Then keep adding **new** entries through the week as you change things. The judges compare dates in this file with your commit history. An honest "the AI generated the base, and here is what I verified and changed" scores far better than a file that pretends otherwise. In the interview you will have to explain every entry.

## Reusable context I gave the AI tool every time

Stored in [`docs/AI_CONTEXT.md`](docs/AI_CONTEXT.md) and pasted at the start of every session about this repo:

- Every route taking a document id must call `authorize()` from `app/authz.py` before any read or write. Never query `documents`, `document_versions`, `grants` or `blobs` by a client-supplied id without the authorised document's id in the `WHERE`.
- Role never grants document access.
- Every state change writes an audit record in the same transaction. Refusals are always recorded.
- For every new check, add a test that fails when the check is removed, and add a mutant to `scripts/mutation_check.py`.
- Assume a confident answer about security is wrong until a test shows otherwise.

## Entries

### 1. 2026-10-19: Admin alert query silently ignored the time window (audit trail)

- **Asked:** generate the `/api/admin/alerts` endpoint, listing privileged admin actions (ownership transfers, password resets, role changes) from the last 7 days.
- **Produced:** `WHERE action IN (...) OR (action = 'admin.user_update' AND details LIKE '%"role"%') AND ts >= ?`
- **What was wrong:** SQL `AND` binds tighter than `OR`. The 7-day filter applied only to the role-change branch, so every ownership transfer and password reset *ever* would show as "recent". Denied attempts would have been listed as if they had happened. It looks correct, it runs, and no error appears.
- **What was done instead:** parenthesised the `OR` group and added `outcome = 'success'`.
  - Code: `app/routes/admin.py`, `alerts()`
  - Commit: `LINK`
  - *Your verification:* ______

### 2. 2026-10-19: Refused attempts would vanish from the audit log (audit trail, authorisation)

- **Asked:** make writes check permission inside the locked transaction (to close the check-then-act race), with `authorize()` auditing denials.
- **Produced:** `authorize()` called `audit.append(...)` and then raised. Inside `with transaction(db):`, the raise triggers a `ROLLBACK` that **also rolls back the denial record**. A stranger's attempt to delete or reshare someone else's document would leave no trace. That contradicts "including the attempts that were refused".
- **What was done instead:** when a transaction is open, `_deny()` queues the record with `audit.defer()`, and the `ApiError` handler writes it after the rollback (`audit.flush_deferred()`).
  - Test: `test_refusals_inside_transactions_are_still_recorded`
  - Mutant: `deny-audit`
  - Commit: `LINK`
  - *Your verification:* ______

### 3. 2026-10-19: Test assumed the hash chain detects deleted records; it does not for the newest ones (audit trail)

- **Asked:** write a test that deleting an audit row is detected.
- **Produced:** a test deleting the `document.download` row, expecting `verify_chain()` to fail. It **passed verification**, so the test failed.
- **What was wrong:** the deleted row was the *last* one. Truncating the tail leaves a perfectly consistent shorter chain. The claim "a hash chain proves nothing was deleted" is false for the newest records, and I had been about to write that claim into THREATS.md.
- **What was done instead:**
  - The middle-row test now deletes a middle row.
  - A separate test proves tail truncation is caught by comparing against an export.
  - Added `verify_audit.py --against export.jsonl` and the stdout witness line per record.
  - THREATS AU-2b marks this as *Reduced*, not *Closed*.
  - Commit: `LINK`
  - *Your verification:* ______

### 4. 2026-10-19: Mutation check reported "killed" for the wrong reason (testing authorisation)

- **Asked:** a script that removes each security check and confirms the tests fail.
- **Produced:** 28/28 killed, but two kills were errors, not assertion failures:
  - `directory-role` replaced the decorator with `@login_required`, which is not imported in `users.py`. The `ImportError` failed all 85 tests, and nothing tested viewers listing people.
  - `search-filter` crashed with a `TypeError` (`None["permission"]`) instead of a test detecting that search leaked other people's documents.
- **What was wrong:** a kill caused by a crash proves nothing about test coverage. If someone later made the code more robust, the leak would go undetected.
- **What was done instead:**
  - The mutant now keeps the decorator but adds the `viewer` role.
  - The listing code no longer crashes on a missing grant.
  - Both mutants are now killed by `failures=1` (real assertions), not `errors=`.
  - Commit: `LINK`
  - *Your verification:* ______

### 5. 2026-10-19: Encryption keys silently regenerated per process

- **Asked:** config that requires keys in production and is convenient in development.
- **Produced:** in development, a random key per process. The seed script and the web server therefore used different master keys, so every download failed with `InvalidTag`.
- **What was wrong:** worse than the crash, the pattern hides a real production risk. Any fallback key path means files encrypted under a key nobody saved.
- **What was done instead:**
  - Production refuses to start without both keys.
  - Development persists keys to `instance/dev_keys.json`.
  - Startup refuses if the master and audit keys are equal.
  - Commit: `LINK`
  - *Your verification:* ______

### 6. 2026-10-19: Upload header-injection test tested the framework, not my code

- **Asked:** a test that a hostile filename cannot inject response headers on download.
- **Produced:** a test uploading `a"\r\nSet-Cookie: x=1;.txt`. Werkzeug's multipart parser had already truncated the name at the quote, so the upload was rejected and the download path never ran.
- **What was done instead:** the test now writes the hostile filename straight into the database and asserts the download's `Content-Disposition` stays a single safe header. That exercises *our* sanitising code.
  - Test: `test_header_injection_through_filename_is_impossible`
  - Commit: `LINK`

---

## Template for your own entries during the week

### N. YYYY-MM-DD: short title (tag: authorisation / audit / upload / other)

- **Asked:** (prompt or a fair summary)
- **Produced:** (what the tool gave you)
- **What was wrong, specifically:**
- **What I did instead:** (with test name and commit link)
