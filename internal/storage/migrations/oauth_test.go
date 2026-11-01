package migrations

import (
	"crypto/rand"
	"database/sql"
	"strings"
	"testing"

	_ "modernc.org/sqlite"
)

// oauthUpgradeDB reconstructs a database from main before OAuth migrations
// were consolidated: application migrations through 0004 plus the OAuth schema
// created by oauth2ext's standalone runner, which only had migration 1. The
// legacy schema is a frozen snapshot and must not be derived from current files.
func oauthUpgradeDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+rand.Text()+"?mode=memory&cache=shared&_pragma=foreign_keys(ON)&_pragma=busy_timeout(5000)")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	exec := func(statement string) {
		t.Helper()
		if _, err := db.ExecContext(t.Context(), statement); err != nil {
			t.Fatal(err)
		}
	}
	exec(`CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY, name TEXT NOT NULL, applied_at TEXT NOT NULL)`)
	migrations, err := loadMigrations(migrationFS)
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range migrations {
		if m.version > 4 {
			break
		}
		for _, statement := range m.stmts {
			exec(statement)
		}
		if _, err := db.ExecContext(t.Context(), `INSERT INTO schema_migrations VALUES (?, ?, 'before')`, m.version, m.name); err != nil {
			t.Fatal(err)
		}
	}
	legacy := []string{
		`CREATE TABLE oauth2as_schema_migrations (version BIGINT PRIMARY KEY, name TEXT NOT NULL, applied_at TEXT NOT NULL)`,
		`INSERT INTO oauth2as_schema_migrations VALUES (1, 'initial_schema', '2026-01-01T00:00:00Z')`,
		`CREATE TABLE oauth2as_grants (
			id TEXT PRIMARY KEY, user_id TEXT NOT NULL, client_id TEXT NOT NULL,
			granted_scopes JSON NOT NULL, request JSON, granted_at TEXT NOT NULL,
			authenticated_at TEXT, expires_at TEXT NOT NULL, additional_state JSON,
			metadata BLOB, encrypted_metadata BLOB, acr TEXT, amr JSON,
			version BIGINT NOT NULL CHECK (version > 0))`,
		`CREATE TABLE oauth2as_authorization_codes (
			id TEXT PRIMARY KEY, grant_id TEXT NOT NULL REFERENCES oauth2as_grants(id) ON DELETE CASCADE,
			code BLOB NOT NULL, valid_until TEXT NOT NULL, delete_after TEXT NOT NULL,
			encrypted_grant_key BLOB, version BIGINT NOT NULL CHECK (version > 0))`,
		`CREATE TABLE oauth2as_refresh_tokens (
			id TEXT PRIMARY KEY, grant_id TEXT NOT NULL REFERENCES oauth2as_grants(id) ON DELETE CASCADE,
			token BLOB NOT NULL, valid_until TEXT NOT NULL, delete_after TEXT NOT NULL,
			replaced_by_id TEXT, encrypted_grant_key BLOB,
			version BIGINT NOT NULL CHECK (version > 0))`,
		`CREATE TABLE oauth2as_refresh_sessions (
			grant_id TEXT PRIMARY KEY REFERENCES oauth2as_grants(id) ON DELETE CASCADE,
			expires_at TEXT NOT NULL, last_used_at TEXT NOT NULL,
			version BIGINT NOT NULL CHECK (version > 0))`,
		`CREATE TABLE unrelated_state (id TEXT PRIMARY KEY, value TEXT NOT NULL)`,
		`INSERT INTO unrelated_state VALUES ('keep', 'retained')`,
		`INSERT INTO oauth2as_grants VALUES ('legacy-grant', 'legacy-user', 'legacy-client', '[]', '{}', '2026-01-01T00:00:00Z', NULL, '2026-01-02T00:00:00Z', '{}', X'01', X'02', '', '[]', 1)`,
		`INSERT INTO oauth2as_authorization_codes VALUES ('legacy-code', 'legacy-grant', X'01', '2026-01-01T00:01:00Z', '2026-01-01T00:02:00Z', NULL, 1)`,
		`INSERT INTO oauth2as_refresh_tokens VALUES ('legacy-token', 'legacy-grant', X'02', '2026-01-01T00:01:00Z', '2026-01-02T00:00:00Z', NULL, NULL, 1)`,
		`INSERT INTO oauth2as_refresh_sessions VALUES ('legacy-grant', '2026-01-02T00:00:00Z', '2026-01-01T00:00:00Z', 1)`,
	}
	for _, statement := range legacy {
		if _, err := db.ExecContext(t.Context(), statement); err != nil {
			t.Fatalf("create legacy schema: %v\n%s", err, statement)
		}
	}
	return db
}

func TestMigrateOAuthReset(t *testing.T) {
	db := oauthUpgradeDB(t)
	if err := Apply(t.Context(), db); err != nil {
		t.Fatal(err)
	}
	for _, table := range []string{"oauth2as_grants", "oauth2as_authorization_codes", "oauth2as_refresh_tokens", "oauth2as_refresh_sessions"} {
		var count int
		if err := db.QueryRowContext(t.Context(), "SELECT count(*) FROM "+table).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count != 0 {
			t.Errorf("%s retained %d old rows", table, count)
		}
	}
	var count int
	if err := db.QueryRowContext(t.Context(), `SELECT count(*) FROM sqlite_master WHERE name = 'oauth2as_schema_migrations'`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatal("standalone migration tracking table remains")
	}
	if err := db.QueryRowContext(t.Context(), `SELECT count(*) FROM schema_migrations WHERE version IN (5, 6)`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 2 {
		t.Fatal("OAuth migrations were not recorded")
	}
	var value string
	if err := db.QueryRowContext(t.Context(), `SELECT value FROM unrelated_state WHERE id = 'keep'`).Scan(&value); err != nil {
		t.Fatal(err)
	}
	if value != "retained" {
		t.Fatal("unrelated state changed")
	}
	// A subsequent startup must retain newly issued OAuth state.
	if _, err := db.ExecContext(t.Context(), `INSERT INTO oauth2as_grants VALUES ('new-grant', 'user', 'client', '[]', '', '', '', NULL, 0, NULL, 1, '', '', '[]', 1)`); err != nil {
		t.Fatal(err)
	}
	if err := Apply(t.Context(), db); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRowContext(t.Context(), `SELECT count(*) FROM oauth2as_grants WHERE id = 'new-grant'`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatal("repeated migration discarded new OAuth state")
	}
}

func TestMigrateOAuthResetRollsBack(t *testing.T) {
	db := oauthUpgradeDB(t)
	// This unrelated index collides with schema creation after the reset.
	if _, err := db.ExecContext(t.Context(), `CREATE INDEX oauth2as_grant_owner_idx ON unrelated_state (value)`); err != nil {
		t.Fatal(err)
	}
	if err := Apply(t.Context(), db); err == nil || !strings.Contains(err.Error(), "apply migration 6") {
		t.Fatalf("migration error = %v, want schema creation failure", err)
	}
	for _, table := range []string{"oauth2as_grants", "oauth2as_authorization_codes", "oauth2as_refresh_tokens", "oauth2as_refresh_sessions", "oauth2as_schema_migrations"} {
		var count int
		if err := db.QueryRowContext(t.Context(), "SELECT count(*) FROM "+table).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count != 1 {
			t.Errorf("%s rows after rollback = %d, want 1", table, count)
		}
	}
	var count int
	if err := db.QueryRowContext(t.Context(), `SELECT count(*) FROM schema_migrations WHERE version IN (5, 6)`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatal("failed migrations were recorded")
	}
	if _, err := db.ExecContext(t.Context(), `DROP INDEX oauth2as_grant_owner_idx`); err != nil {
		t.Fatal(err)
	}
	if err := Apply(t.Context(), db); err != nil {
		t.Fatalf("retry after rollback: %v", err)
	}
}
