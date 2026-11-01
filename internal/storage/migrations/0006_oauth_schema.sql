CREATE TABLE oauth2as_grants (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    client_id TEXT NOT NULL,
    granted_scopes JSON NOT NULL,
    redirect_uri TEXT NOT NULL,
    code_challenge TEXT NOT NULL,
    nonce TEXT NOT NULL,
    max_age INTEGER,
    granted_at INTEGER NOT NULL,
    authenticated_at INTEGER,
    expires_at INTEGER NOT NULL,
    dpop_thumbprint TEXT NOT NULL,
    acr TEXT NOT NULL,
    amr JSON NOT NULL,
    -- Advanced by every token exchange; guards the whole grant against races.
    version INTEGER NOT NULL CHECK (version > 0)
);

CREATE TABLE oauth2as_authorization_codes (
    id TEXT PRIMARY KEY,
    grant_id TEXT NOT NULL REFERENCES oauth2as_grants(id) ON DELETE CASCADE,
    valid_until INTEGER NOT NULL,
    delete_after INTEGER NOT NULL
);

CREATE TABLE oauth2as_refresh_tokens (
    id TEXT PRIMARY KEY,
    grant_id TEXT NOT NULL REFERENCES oauth2as_grants(id) ON DELETE CASCADE,
    valid_until INTEGER NOT NULL,
    delete_after INTEGER NOT NULL,
    replaced_by_id TEXT NOT NULL
);

CREATE TABLE oauth2as_refresh_sessions (
    grant_id TEXT PRIMARY KEY REFERENCES oauth2as_grants(id) ON DELETE CASCADE,
    expires_at INTEGER NOT NULL,
    last_used_at INTEGER NOT NULL
);

CREATE INDEX oauth2as_grant_owner_idx ON oauth2as_grants (user_id, client_id, id);
CREATE INDEX oauth2as_grant_expiry_idx ON oauth2as_grants (expires_at);
CREATE INDEX oauth2as_code_expiry_idx ON oauth2as_authorization_codes (delete_after);
CREATE INDEX oauth2as_code_grant_idx ON oauth2as_authorization_codes (grant_id);
CREATE INDEX oauth2as_token_expiry_idx ON oauth2as_refresh_tokens (delete_after);
CREATE INDEX oauth2as_token_grant_idx ON oauth2as_refresh_tokens (grant_id);
CREATE INDEX oauth2as_session_active_idx ON oauth2as_refresh_sessions (expires_at, last_used_at, grant_id);
