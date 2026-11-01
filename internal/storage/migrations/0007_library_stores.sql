-- Schemas used by the session and keyset library adapters.
CREATE TABLE IF NOT EXISTS sessions (
    id TEXT PRIMARY KEY,
    data BLOB NOT NULL,
    expires_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS sessions_expires_at_idx ON sessions (expires_at);

CREATE TABLE IF NOT EXISTS keysets (
    name VARCHAR(255) PRIMARY KEY,
    keyset_data BLOB NOT NULL,
    revision BIGINT NOT NULL
);
