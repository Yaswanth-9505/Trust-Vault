-- TrustVault database schema (SQLite 3.35+)
-- Applied by `python -m scripts.init_db`. Safe to run on an empty database only.

PRAGMA foreign_keys = ON;

-- ---------------------------------------------------------------------------
-- Users and sessions
-- ---------------------------------------------------------------------------
CREATE TABLE users (
    id              TEXT PRIMARY KEY,                      -- uuid4 hex
    email           TEXT NOT NULL UNIQUE COLLATE NOCASE,
    name            TEXT NOT NULL,
    role            TEXT NOT NULL CHECK (role IN ('admin', 'owner', 'viewer')),
    password_hash   TEXT NOT NULL,
    is_active       INTEGER NOT NULL DEFAULT 1 CHECK (is_active IN (0, 1)),
    is_demo         INTEGER NOT NULL DEFAULT 0 CHECK (is_demo IN (0, 1)),
    failed_logins   INTEGER NOT NULL DEFAULT 0,
    locked_until    TEXT,
    created_at      TEXT NOT NULL,
    updated_at      TEXT NOT NULL
);

-- Server-side sessions. Only the SHA-256 of the token is stored, so a copy of
-- the database does not give anyone a working session cookie.
CREATE TABLE sessions (
    token_hash      TEXT PRIMARY KEY,
    user_id         TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    csrf_token      TEXT NOT NULL,
    created_at      TEXT NOT NULL,
    last_seen_at    TEXT NOT NULL,
    expires_at      TEXT NOT NULL,                         -- absolute expiry
    ip              TEXT,
    user_agent      TEXT
);
CREATE INDEX idx_sessions_user ON sessions(user_id);

-- ---------------------------------------------------------------------------
-- Documents, versions and encrypted file content
-- ---------------------------------------------------------------------------
CREATE TABLE documents (
    id              TEXT PRIMARY KEY,
    title           TEXT NOT NULL,
    description     TEXT NOT NULL DEFAULT '',
    category        TEXT NOT NULL CHECK (category IN
                        ('HR', 'Legal', 'Finance', 'Engineering', 'Audit', 'General')),
    owner_id        TEXT NOT NULL REFERENCES users(id),
    current_version INTEGER NOT NULL DEFAULT 1,
    created_at      TEXT NOT NULL,
    updated_at      TEXT NOT NULL,
    deleted_at      TEXT,                                  -- soft delete (trash)
    deleted_by      TEXT REFERENCES users(id),
    purged_at       TEXT                                   -- content destroyed
);
CREATE INDEX idx_documents_owner ON documents(owner_id);
CREATE INDEX idx_documents_created ON documents(created_at);

-- File content, encrypted with AES-256-GCM. Each blob has its own random data
-- key, which is itself encrypted ("wrapped") with the master key from the
-- environment. The master key never touches the database.
CREATE TABLE blobs (
    id              TEXT PRIMARY KEY,
    nonce           BLOB NOT NULL,
    ciphertext      BLOB NOT NULL,
    key_nonce       BLOB NOT NULL,
    wrapped_key     BLOB NOT NULL
);

CREATE TABLE document_versions (
    id              TEXT PRIMARY KEY,
    document_id     TEXT NOT NULL REFERENCES documents(id),
    version_no      INTEGER NOT NULL,
    blob_id         TEXT REFERENCES blobs(id) ON DELETE SET NULL,
    filename        TEXT NOT NULL,
    mime            TEXT NOT NULL,
    size_bytes      INTEGER NOT NULL,
    sha256          TEXT NOT NULL,
    uploaded_by     TEXT NOT NULL REFERENCES users(id),
    created_at      TEXT NOT NULL,
    UNIQUE (document_id, version_no)
);

-- ---------------------------------------------------------------------------
-- Permissions: explicit, per-document grants to named users. No folders, no
-- inheritance, no groups - see WRITEUP.md for why.
-- ---------------------------------------------------------------------------
CREATE TABLE grants (
    id              TEXT PRIMARY KEY,
    document_id     TEXT NOT NULL REFERENCES documents(id),
    user_id         TEXT NOT NULL REFERENCES users(id),
    permission      TEXT NOT NULL CHECK (permission IN ('read', 'edit')),
    granted_by      TEXT NOT NULL REFERENCES users(id),
    source          TEXT NOT NULL DEFAULT 'manual' CHECK (source IN ('manual', 'suggestion')),
    created_at      TEXT NOT NULL,
    expires_at      TEXT,
    revoked_at      TEXT,
    revoked_by      TEXT REFERENCES users(id)
);
-- At most one live grant per (document, user).
CREATE UNIQUE INDEX uq_grants_live ON grants(document_id, user_id) WHERE revoked_at IS NULL;
CREATE INDEX idx_grants_user ON grants(user_id);

-- Access suggestions. A suggestion is only a record that something was
-- proposed; nothing here is ever read by the authorisation check.
CREATE TABLE access_suggestions (
    id                  TEXT PRIMARY KEY,
    document_id         TEXT NOT NULL REFERENCES documents(id),
    suggested_user_id   TEXT NOT NULL REFERENCES users(id),
    reason              TEXT NOT NULL,
    status              TEXT NOT NULL DEFAULT 'pending'
                            CHECK (status IN ('pending', 'accepted', 'dismissed')),
    created_at          TEXT NOT NULL,
    decided_at          TEXT,
    decided_by          TEXT REFERENCES users(id)
);

-- ---------------------------------------------------------------------------
-- Audit log: append-only, HMAC hash-chained.
-- ---------------------------------------------------------------------------
CREATE TABLE audit_log (
    seq             INTEGER PRIMARY KEY,                   -- assigned by the app, gapless
    ts              TEXT NOT NULL,
    actor_id        TEXT,
    actor_email     TEXT,
    action          TEXT NOT NULL,
    outcome         TEXT NOT NULL CHECK (outcome IN ('success', 'denied', 'error')),
    document_id     TEXT,
    target_user_id  TEXT,
    ip              TEXT,
    user_agent      TEXT,
    details         TEXT NOT NULL DEFAULT '{}',            -- JSON
    prev_hash       TEXT NOT NULL,
    hash            TEXT NOT NULL
);
CREATE INDEX idx_audit_ts ON audit_log(ts);
CREATE INDEX idx_audit_actor ON audit_log(actor_id);
CREATE INDEX idx_audit_document ON audit_log(document_id);
CREATE INDEX idx_audit_action ON audit_log(action);

-- First line of defence: the database refuses to change or remove audit rows.
-- (Someone with direct database access can drop these triggers; the HMAC chain
-- is what makes that detectable. See THREATS.md, A-1 to A-4.)
CREATE TRIGGER audit_log_no_update BEFORE UPDATE ON audit_log
BEGIN
    SELECT RAISE(ABORT, 'audit_log is append-only');
END;

CREATE TRIGGER audit_log_no_delete BEFORE DELETE ON audit_log
BEGIN
    SELECT RAISE(ABORT, 'audit_log is append-only');
END;
