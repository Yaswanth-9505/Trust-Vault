# TrustVault API

All endpoints are under `/api`, take and return JSON unless noted, and send `Cache-Control: no-store`.

**Authentication.** Sign in with `POST /api/auth/login`. This sets an HttpOnly session cookie and returns a `csrfToken`.

**State changes.** Every request that changes state (POST, PATCH, DELETE), except login, must send that token as `X-CSRF-Token`. Any request with a foreign `Origin` header is refused.

**Errors** have the shape `{"error": "<code>", "message": "<human text>"}`.

| Status | Meaning |
|---|---|
| 401 | Not signed in, or the session has ended. |
| 403 | Your role or access level does not allow this. |
| 404 | No such document, *or* you have no access to it. These two are deliberately indistinguishable. |
| 400 / 409 / 413 / 415 / 429 | Bad input / conflict / file too large / file type refused / too many attempts. |

**Document levels** are computed per request in `app/authz.py`:

- **owner**: `documents.owner_id` is you;
- **edit** or **read**: you hold a grant that is not revoked and not expired.

Role never grants document access.

## Auth

| Method & path | Who may call | Notes |
|---|---|---|
| `POST /auth/login` `{email, password}` | Anyone | Same 401 for unknown, wrong, locked or deactivated. 5 failures lock the account for 15 min; 20 tries per IP per 5 min. |
| `POST /auth/logout` | Signed in | Deletes the session server-side. |
| `GET /auth/me` | Signed in | Current user and CSRF token. |
| `POST /auth/password` `{current_password, new_password}` | Signed in (not demo accounts in demo mode) | Ends your other sessions. |

## Documents

| Method & path | Who may call | Notes |
|---|---|---|
| `POST /documents` (multipart: `title`, `category`, `description`, `file`) | Role **owner** | Creates a private document; you are its owner. File validated (see THREATS UP-*). |
| `GET /documents?q=&owner=&category=&from=&to=&scope=all\|mine\|shared&sort=newest\|oldest\|title\|updated&page=&page_size=` | Signed in | Only documents you can open, enforced in the query. `from`/`to` are `YYYY-MM-DD` on created date. |
| `GET /documents/trash` | Signed in | Your own trashed documents. |
| `GET /documents/{id}` | Level read, edit or owner | Metadata, versions, `my_access`. |
| `GET /documents/{id}/download[?version=n]` | Level read, edit or owner | Always `application/octet-stream` as an attachment. The download is audited before any byte is sent. |
| `PATCH /documents/{id}` `{title?, description?, category?}` | Level edit or owner | Unknown fields are refused. |
| `POST /documents/{id}/versions` (multipart: `file`) | Level edit or owner | Adds version n+1; old versions are kept. |
| `DELETE /documents/{id}` | Owner | Soft delete: nobody can open it until restored. Purged after 30 days. |
| `POST /documents/{id}/restore` | Owner | Trashed, unpurged documents only. |
| `GET /documents/{id}/activity` | Owner | This document's audit records, including refusals. |

## Sharing

| Method & path | Who may call | Notes |
|---|---|---|
| `GET /documents/{id}/grants` | Owner | Live grants and the last 20 revoked. |
| `POST /documents/{id}/grants` `{user_id, permission: read\|edit, expires_at?}` | Owner | The target must be active, not the owner, and not already granted (409). Expiry must be in the future and at most 366 days away. |
| `PATCH /documents/{id}/grants/{grant_id}` `{permission?, expires_at?}` | Owner | The grant must belong to this document. |
| `DELETE /documents/{id}/grants/{grant_id}` | Owner | Revokes. Takes effect on the grantee's next request. |
| `POST /documents/{id}/suggestions` | Owner | Returns suggested people and reasons. **Changes no access.** Audited as `suggestion.shown`. |
| `POST /documents/{id}/suggestions/{sid}/accept` `{permission, expires_at?}` | Owner | Creates the grant (`source: suggestion`) and audits both the grant and the decision. |
| `POST /documents/{id}/suggestions/{sid}/dismiss` | Owner | Audited. |
| `GET /users/directory?q=` | Role owner or admin | Active users' id, name and email (at most 25). |

## Administration (role admin only)

| Method & path | Notes |
|---|---|
| `GET /admin/users` | All accounts with status and lock state. |
| `POST /admin/users` `{email, name, role, password}` | Creates an account. |
| `PATCH /admin/users/{id}` `{role?, active?, name?}` | Cannot change your own role or status. Role or status change ends that user's sessions. |
| `POST /admin/users/{id}/reset-password` `{new_password}` | Ends their sessions and unlocks the account. |
| `POST /admin/users/{id}/unlock` | Clears the lockout. |
| `GET /admin/documents` | **Metadata only** (title, owner, grant count, state). No content route exists for admins. |
| `POST /admin/documents/{id}/transfer` `{new_owner_id}` | The new owner must be an active owner-role user and **not the calling admin**. Flagged in alerts. |
| `POST /admin/purge-expired` | Destroys the content of documents trashed longer than the retention period. |
| `GET /admin/audit?actor=&action=&outcome=&document_id=&actor_id=&target_user_id=&from=&to=&page=&page_size=` | `action` accepts a prefix such as `document.*`. |
| `GET /admin/audit/verify` | Recomputes the HMAC chain and reports where it first breaks, if anywhere. |
| `GET /admin/audit/export` | Full log as JSON lines including hashes. The export itself is audited. |
| `GET /admin/alerts` | Chain integrity, probing, failed sign-ins, download spikes, sharing bursts, privileged admin actions, forged requests, documents without an active owner. |

## Other

| Method & path | Who | Notes |
|---|---|---|
| `GET /` | Anyone | The single-page UI. |
| `GET /healthz` | Anyone | `{"status":"ok"}`. |
