# TrustVault threat model

How I believe this system could be broken, what I did about each one, and what I knowingly left open.

**Status key.** *Closed*: a control exists and a named test proves it. *Reduced*: the risk is smaller but not gone. *Accepted*: I know it is open and say why.

**How to check my claims.** Every *Closed* entry names the test that proves it. `python -m scripts.mutation_check` removes 28 individual checks one at a time and confirms the suite fails each time; the mutant name is given where one exists.

## The attacker I designed against

1. **A signed-in user reaching for documents they were not given.** This is the judge's position: a colleague, an ex-employee, an external partner.
2. **Someone with no account**, on the public internet.
3. **A malicious or careless administrator.**
4. **Someone who gets a copy of the database file**, through a backup, a misconfigured host or a stolen laptop.
5. **Someone who controls the server and its environment.** I cannot defend against this one, and I say so in OP-6.

## Where the authorisation decision is made

Every route that takes a document id calls `authorize(document_id, action)` in `app/authz.py` before it reads or changes anything. That function:

- reads the document;
- refuses trashed or purged documents;
- computes the caller's level from the database at that moment (`owner`, or a grant that is unrevoked and unexpired);
- checks that level against `ACTION_LEVELS`.

Role is never consulted, so an admin has no route to content.

Writes, and the download itself, call `authorize()` inside a `BEGIN IMMEDIATE` transaction. That holds SQLite's write lock from the check until the audit record commits, so a revoke cannot land between "allowed" and "sent". If you delete the `authorize` line in `download()`, 16 tests fail (mutant `download-authorize`).

---

## AC: Access control

| ID | Threat | What I did | Status | Proof |
|---|---|---|---|---|
| AC-1 | **IDOR**: change the document id in any URL (metadata, download, versions, grants, activity, suggestions, restore, delete). | One `authorize()` on every route. A walker test hits **all 13 document routes** as three different strangers (a viewer, another owner, the admin) and checks that each gets 404, sees no title or content, and changes nothing. | Closed | `test_access_control.EveryRouteRefusesStrangers`; mutants `owner`, `grant-user`, `no-level` |
| AC-1b | **Enumeration**: telling "exists but not yours" apart from "doesn't exist". | Both return the same 404 body. Ids are 128-bit random, not sequential. | Closed | `test_unknown_and_forbidden_documents_look_identical` |
| AC-2 | **Escalation within a document**: a reader edits, an editor deletes or reshares, or a grantee alters their own grant. | `ACTION_LEVELS`: read < edit < owner. Only the owner can delete, restore, share or see activity. An editor cannot pass access on. | Closed | `GrantLevelsAreEnforced`; mutants `action-level`, `edit-authorize`, `delete-authorize`, `share-authorize` |
| AC-3 | **Admin backdoor**: the admin role reads everything. | `authorize()` ignores role, and no admin route returns content. Admin sees metadata only (title, owner, grant count). Admin cannot transfer a document to themselves. | Closed (see AC-3b) | `AdminHasNoBackdoor`; mutant `transfer-self` |
| AC-3b | **Admin works around AC-3** by resetting a user's password and signing in as them, or by creating a puppet owner and transferring documents to it. | Cannot be prevented without removing account administration. Every step is audited (`admin.password_reset`, `admin.user_create`, `admin.ownership_transfer`) and shown in Alerts as a privileged action. The real victim learns on their next sign-in that their password changed. | **Accepted**, detectable | `test_transfer_moves_access_and_is_audited` |
| AC-4 | **Id confusion**: using my document's URL with *your* grant id, suggestion id or version number. | Every child lookup is keyed by `(child_id, document_id)` from the authorised document, never by child id alone. Version numbers are integers checked against the document. | Closed | `IdConfusion`, `test_suggestion_id_from_another_document_is_refused`; mutant `grant-doc` |
| AC-5 | **Trashed or purged documents** stay reachable by grantees, or by "restore" from a non-owner. | Trashed means unreachable for every action except owner restore. Purged means the encrypted content is deleted and nothing is reachable. | Closed | `DeletedDocuments`; mutants `deleted`, `purged` |
| AC-6 | **No session at all**, or a forged cookie. | Every API route needs a session found in the database by token hash. | Closed | `Unauthenticated` |
| AC-7 | **Mass assignment**: sending `owner_id`, `role` or `deleted_at` in a JSON body. | `json_body()` rejects any field not on the allow-list for that route, rather than ignoring it. | Closed | `test_cannot_change_owner_through_metadata_update`; mutant `mass-assignment` |
| AC-8 | **Folder or group inheritance leaks**: given a folder to see one file, you see forty. | Designed out. There are no folders, groups or inheritance. Every grant names one person and one document. Categories are labels, not containers. | Closed by design | See WRITEUP.md |
| AC-9 | **Role-gated routes**: a viewer uploads, or a non-admin calls admin routes. | `roles_required()` decorator, with the refusal audited. | Closed | `test_non_admins_cannot_use_admin_routes`, `test_viewer_role_cannot_create_documents`; mutant `role` |
| AC-10 | **Grant to self, to the owner, or to a deactivated user.** | Rejected in `_grantee()`. | Closed | `test_cannot_grant_to_self_or_owner` |
| AC-11 | **Race between check and use**: a revoke lands between the access check and the file being sent. | Download and every write call `authorize()` inside `BEGIN IMMEDIATE`. A revoke needs the same lock, so it lands strictly before (refused) or after (download already recorded). | Closed | Code: `documents.download()`. Not unit-tested, because SQLite locking would need concurrent processes. **Reduced** for honesty. |

## RV: Taking access away

My definition of "immediately": the next HTTP request made after the revoke commits is refused, on every route, including requests on a session and URL issued before the revoke. This works because **nothing that confers access is ever handed to the client.** There are no signed URLs, no JWTs carrying permissions, and no cached permission decisions. The only thing a client holds is an opaque session id, and every request re-reads `sessions`, `users` and `grants`.

**The cost:** one indexed SQLite lookup per request and per document. I cannot scale out to a CDN or put files behind pre-signed object-storage URLs without changing this definition. I chose that trade on purpose.

| ID | Threat | What I did | Status | Proof |
|---|---|---|---|---|
| RV-1 | Revoked grantee keeps using an open page, a download link or a search result. | Grants are re-read on each request; the revoked row is excluded. | Closed | `test_revocation_stops_the_very_next_request_on_the_same_session`; mutant `revoked` |
| RV-2 | Time-limited grant keeps working after it expires. | Expiry is compared in the same query as the access check, and in search. | Closed | `ExpiredGrant`; mutant `expiry` |
| RV-3 | Leaver: deactivated user's existing session keeps working. | Deactivation deletes their sessions. Separately, the session lookup refuses inactive users, so either control alone is enough. | Closed | `test_deactivated_user_is_cut_off_mid_session`, `test_deactivation_is_enforced_even_if_session_rows_survived`; mutant `session-active` |
| RV-4 | Role change does not take effect until the next login. | Changing role ends all of that user's sessions. | Closed | `test_role_change_ends_sessions`; mutant `revoke-sessions-on-role` |
| RV-5 | Password reset or change leaves a stolen session alive. | Admin reset ends all sessions. Self-change ends all *other* sessions. | Closed | `test_admin_password_reset_ends_sessions`, `test_own_password_change_ends_other_sessions` |
| RV-6 | Copying the cookie and replaying it after logout. | Logout deletes the session row server-side. | Closed | `test_logout_kills_the_session_server_side` |
| RV-7 | Abandoned session on a shared computer. | 30-minute idle timeout and 8-hour absolute lifetime. | Closed | `test_idle_session_expires`, `test_absolute_session_lifetime`; mutant `session-idle` |
| RV-8 | **A file already downloaded before revocation.** | Nothing a server can do. The audit trail records exactly who downloaded which version (SHA-256) and when, which is the evidence the brief asks for. | **Accepted** | `test_download_record_names_the_exact_file` |
| RV-9 | **Large download in progress** at the moment of revocation. | Files are at most 10 MB and are sent from memory once authorised. A response already authorised finishes. | **Accepted** | (by design) |
| RV-10 | Ownership transfer leaves the old owner with access. | The old owner gets no grant. The new owner's previous grant is closed. | Closed | `test_transfer_moves_access_and_is_audited` |

## AU: The audit trail is evidence

| ID | Threat | What I did | Status | Proof |
|---|---|---|---|---|
| AU-1 | **Edit a record** to change who downloaded something. | Layer 1: SQLite triggers abort any `UPDATE` or `DELETE` on `audit_log`. Layer 2: each row stores `HMAC-SHA256(audit_key, prev_hash ‖ row)`, so any edit breaks verification from that row onward. The key lives in the environment, not the database, so someone holding only the DB file cannot recompute the chain. Admin Alerts re-verify the whole chain on every view. | Closed | `test_database_refuses_update_and_delete`, `test_edited_row_is_detected_even_if_triggers_are_dropped` |
| AU-2 | **Delete a record** from the middle. | Breaks the chain (sequence gap and prev_hash mismatch). | Closed | `test_deleted_row_is_detected` |
| AU-2b | **Truncate the tail**: delete the most recent records. A hash chain cannot detect this on its own, because the remaining chain is still consistent. I found this when my first test wrongly assumed it would. | Two outside witnesses: (a) every record's seq and hash is written to stdout, and the hosting platform keeps those logs separately; (b) admin export (JSONL with hashes) plus `scripts/verify_audit.py --against export.jsonl` proves a later database is missing records. | **Reduced**: detection depends on someone keeping exports or logs | `test_deleting_the_tail_is_detected_by_comparing_with_an_export` |
| AU-3 | **Refused attempts not recorded.** In particular, a denial raised inside a write transaction would be rolled back along with the transaction. | Denials inside a transaction are queued and written by the error handler after the rollback. Recorded denials include document reads and downloads, every refused action, failed logins (with reason), lockouts, role failures, CSRF and bad-origin refusals. | Closed | `test_refused_attempts_are_recorded`, `test_refusals_inside_transactions_are_still_recorded`; mutant `deny-audit` |
| AU-4 | **Insert a forged record.** | Cannot produce a valid HMAC without the key. | Closed | `test_forged_row_without_key_is_detected` |
| AU-5 | **An action happens without a record**, for example the disk is full. | The audit row is written in the same transaction as the action. A download's record commits before any byte is sent; if the write fails, the download fails (fail closed). | Closed | `test_audit_failure_blocks_the_download`, `test_every_required_event_is_recorded_with_actor` |
| AU-6 | **Spoofed IP** in the record via `X-Forwarded-For`. | `ProxyFix` trusts exactly `TV_TRUSTED_PROXIES` hops (1 on the host). Locally it trusts none. | Closed (config) | `app/__init__.py` |
| AU-7 | **Someone holding both the DB and the audit key** rewrites the whole chain consistently. | Out of reach of the chain itself. Only the outside witnesses (AU-2b) catch it. | **Accepted** | See OP-6 |
| AU-8 | **Audit table filling the disk** through deliberate floods of denied requests. | Login is rate-limited per IP. Other denials need a valid session. No retention on audit by design (it is evidence). | **Accepted** at this scale | |

## AN: Authentication

| ID | Threat | What I did | Status | Proof |
|---|---|---|---|---|
| AN-1 | **Password guessing.** | Per-account lockout after 5 failures for 15 minutes (DB-backed, holds across workers). Per-IP limit of 20 attempts per 5 minutes (in memory, per worker). scrypt hashing. Minimum 12 characters. | Closed | `test_lockout_after_repeated_failures`, `test_ip_rate_limit`; mutant `lockout` |
| AN-1b | **Lockout as denial of service**: lock someone out by failing on purpose. | Inherent to lockout. Admin can unlock. Alerts show repeated failures per account and per IP. | **Accepted** | |
| AN-2 | **User enumeration** through login messages or timing. | Identical message and status for unknown email, wrong password, locked and deactivated. A dummy scrypt verify runs for unknown emails. | Closed | `test_unknown_email_and_wrong_password_look_the_same` |
| AN-3 | **Session theft from a DB copy.** | Only SHA-256 of the token is stored. | Closed | `test_database_holds_only_token_hashes` |
| AN-4 | **Session fixation.** | Login always mints a new token. | Closed | `test_login_issues_a_fresh_token` |
| AN-5 | **Cookie theft** via JavaScript or HTTP. | `HttpOnly`, `Secure`, `SameSite=Strict`, and the `__Host-` prefix in production. HSTS. | Closed | `test_cookie_flags` |
| AN-6 | **Shared demo accounts**: one judge changes a password and locks the others out. | `TV_DEMO_MODE=1` blocks self-service password change for seeded accounts. | Closed (demo only) | `auth_routes.change_password` |
| AN-7 | **No MFA.** | Not built in seven days. | **Accepted**; first thing I would add | |

## RQ: Forged requests and the browser

| ID | Threat | What I did | Status | Proof |
|---|---|---|---|---|
| RQ-1 | **CSRF**: another site makes the victim's browser grant access or delete. | Per-session CSRF token required in a header on every state change, compared in constant time. The cookie is `SameSite=Strict`. Login must be JSON. | Closed | `ForgedRequests`; mutant `csrf` |
| RQ-2 | **Cross-origin requests.** | Any state-changing request with a foreign `Origin` is refused and audited. No CORS headers are ever sent. | Closed | `test_cross_origin_request_is_refused_even_with_token`; mutant `origin` |
| RQ-3 | **Stored XSS** through a document title, description, filename or user name. | The UI only ever uses `textContent`; there is no `innerHTML` in `app.js`. CSP `script-src 'self'` with no inline script, so injected markup could not run even if inserted. | Closed | `test_title_is_stored_as_text_not_markup`, `test_security_headers` |
| RQ-4 | **Clickjacking** the share button. | `frame-ancestors 'none'` and `X-Frame-Options: DENY`. | Closed | `test_security_headers` |
| RQ-5 | **Sensitive responses cached** by a proxy or shared computer. | `Cache-Control: no-store` on every API response and download. | Closed | `test_api_responses_are_not_cached` |

## UP / ST: Uploads and storage

| ID | Threat | What I did | Status | Proof |
|---|---|---|---|---|
| UP-1 | **Active content uploaded**: HTML, SVG, JS, executables. | Extension allow-list only (pdf, png, jpg, txt, csv, md, docx, xlsx, pptx). | Closed | `test_rejects_active_content_types`; mutant `upload-allowlist` |
| UP-2 | **Type spoofing**: an exe renamed `.pdf`. | Magic bytes are checked per type. Office files must be a valid ZIP with the right parts. Text must be UTF-8 with no NUL. The browser's Content-Type is ignored. | Closed | `test_rejects_content_that_does_not_match_extension`; mutant `upload-magic` |
| UP-3 | **Dangerous documents**: PDF JavaScript or launch actions, Office macros. | PDFs containing `/JavaScript /JS /Launch /EmbeddedFile /RichMedia /XFA` are refused. Office files containing `vbaProject.bin` are refused. | Reduced: pattern-based, an obfuscated PDF can evade it | `test_rejects_pdf_with_javascript_and_office_with_macros` |
| UP-4 | **Path traversal** through the filename. | The filename is display-only. Storage is keyed by random id in the DB; there is no filesystem path. The name is still reduced to a basename and stripped of control and bidi characters. | Closed | `test_path_traversal_in_filename_is_neutralised`, `test_bidi_override_in_filename_is_removed` |
| UP-5 | **Huge uploads, zip bombs, form floods.** | 10 MB limit at the WSGI layer and again in code. ZIPs are inspected via the central directory only and never decompressed. Form parts limited. | Closed | `test_empty_and_oversized_files` |
| UP-6 | **Malware inside an allowed type**, for example an exploit PDF. | No antivirus scanning. Files are only ever delivered as downloads, never rendered on our origin. | **Accepted**: would add ClamAV in production | |
| ST-1 | **Stolen DB file or backup** reveals file contents. | AES-256-GCM per file with a random data key, wrapped by a master key held in the environment. The blob id is bound as associated data, so ciphertext moved between rows will not decrypt. | Closed | `test_file_content_is_encrypted_at_rest` |
| ST-2 | **Guessable or public file URLs**, as with an S3 bucket or static folder. | Files are not on the filesystem or any public URL; they are rows in the DB. The only route to bytes is `download()`. | Closed | `test_no_static_route_serves_stored_files` |
| ST-3 | **Download rendered in the browser** (HTML or SVG polyglot executes on our origin). | Always `application/octet-stream`, `Content-Disposition: attachment`, `nosniff`, and `CSP: sandbox` on the response. | Closed | `test_downloads_are_never_rendered_by_the_browser`; mutant `download-octet` |
| ST-4 | **Header injection** through the filename in `Content-Disposition`. | ASCII fallback with quotes, semicolons and control characters replaced, plus RFC 5987 encoding. | Closed | `test_header_injection_through_filename_is_impossible` |
| ST-5 | **Deleted content lingers** in free pages after purge. | `PRAGMA secure_delete=ON`. Content is encrypted anyway. | Reduced: backups taken earlier still contain it | |

## SR: Search and listings

| ID | Threat | What I did | Status | Proof |
|---|---|---|---|---|
| SR-1 | **Search leaks titles or counts** of documents you cannot open. | The access rule is in the SQL `WHERE` (`VISIBLE_DOCUMENTS_SQL`, the same rule as `access_level()`), so totals and pages only count visible documents. | Closed | `test_search_only_returns_accessible_documents`, `test_owner_filter_cannot_be_used_to_count_hidden_documents`; mutant `search-filter` |
| SR-2 | **Wildcard injection**: `%` or `_` matching everything. | LIKE input is escaped. | Closed | `test_wildcards_are_literal` |
| SR-3 | **SQL injection** in any filter or sort. | Parameterised queries everywhere. Sort is chosen from a fixed map. Category comes from a fixed list. | Closed | `test_sql_injection_attempts_are_plain_text`, `test_bad_filter_values_are_rejected` |
| SR-4 | **User directory used for enumeration.** | Viewers cannot list people. Owners see name and email of active users only, with no roles. | Reduced: an internal directory is a feature | `Directory` tests; mutant `directory-role` |
| SR-5 | **Admin sees document titles** of everything. | A choice, not a leak. Oversight of sharing is impossible without it. Titles also appear in audit. Content is never available to admin. | **Accepted** | |

## AI: Access suggestions

| ID | Threat | What I did | Status | Proof |
|---|---|---|---|---|
| AI-1 | **The machine widens access on its own.** | Suggestions write to `access_suggestions` and the audit log only; nothing in that code path touches `grants`. A grant needs a POST from the owner. The grant's audit record carries `source: suggestion`, the suggestion id and the human actor. | Closed | `test_suggestion_does_not_grant_anything`, `test_accepting_records_both_suggestion_and_decision` |
| AI-2 | **Accept another document's suggestion**, or a dismissed one. | Lookups by `(suggestion_id, document_id, status='pending')`. | Closed | `test_suggestion_id_from_another_document_is_refused`, `test_dismissed_suggestion_cannot_be_accepted` |
| AI-3 | **Suggestions leak who has access to other documents.** | Only the owner sees suggestions, and they are computed only from that same owner's own documents. Nothing is revealed that the owner could not already see. | Closed | `test_only_the_owner_can_see_or_accept_suggestions` |
| AI-4 | **Document data sent to a third-party AI service.** | I deliberately used a rule, not an external LLM, so no confidential data leaves the system. | Closed by design | |

## OP: Operations and things outside the code

| ID | Threat | What I did | Status |
|---|---|---|---|
| OP-1 | **Default or missing keys** in production. | In production the app refuses to start without both keys, and refuses if they are equal. Dev keys exist only outside production. | Closed |
| OP-2 | **Losing the master key** means losing every file. | Documented in README: keep it in a password manager. | Accepted (operational) |
| OP-3 | **Verbose errors** leak internals. | Generic 500 body; the stack trace goes only to the server log. | Closed |
| OP-4 | **Demo credentials are public.** | They are seed accounts on demo data only. `TV_DEMO_MODE` protects them. `python -m scripts.seed --reset` restores the demo. | Accepted |
| OP-5 | **Single SQLite file** is a single point of failure. | WAL mode, and an online backup via `sqlite3 .backup` is documented. Fine at this scale; Postgres is the next step. | Accepted |
| OP-6 | **Server or host compromise**: an attacker with the process environment has both keys and the DB. | Out of scope for application code. Mitigations would be a KMS or HSM for keys, and audit shipping to append-only external storage (WORM). | Accepted |
| OP-7 | **Dependency vulnerabilities.** | Three direct dependencies, version ranges pinned. Should run `pip-audit` in CI. | Reduced |
| OP-8 | **Denial of service**: slow uploads, many requests. | Size limits only. No general rate limiting beyond login. | Accepted |
| OP-9 | **No external sharing links.** External people get a normal viewer account (see `ext@partner.test`). | Public links are the most common source of "the link still works after they left". Not building them is the control. | Closed by omission |

## What I would do next, in order

1. MFA for owners and admins.
2. Ship audit records to append-only external storage, which closes AU-2b and AU-7.
3. A step-up confirmation (re-enter password) before granting access to HR-category documents.
4. Antivirus scanning on upload.
5. A periodic access-review email to owners listing who can see each document.
