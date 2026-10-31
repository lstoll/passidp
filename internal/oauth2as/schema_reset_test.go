package oauth2as

import (
	"database/sql"
	"slices"
	"testing"
	"time"
)

func legacySQLStorage(t *testing.T) (*sql.DB, *Storage) {
	t.Helper()
	db := newSQLiteDB(t)
	store, err := NewSQLStorage(db)
	if err != nil {
		t.Fatal(err)
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
			t.Fatalf("create v1 schema: %v\n%s", err, statement)
		}
	}
	return db, store
}

func TestSQLiteMigrateResetsLegacySchemaAndRoundTripsTypedGrant(t *testing.T) {
	db, store := legacySQLStorage(t)
	if err := store.Migrate(t.Context()); err != nil {
		t.Fatalf("Migrate legacy schema: %v", err)
	}
	assertLegacyRowsGone(t, db)
	assertUnrelatedRow(t, db)
	assertMigrationVersions(t, db, 1, 3)
	assertNoLegacyGrantColumns(t, db)

	base := time.Date(2026, time.October, 31, 12, 30, 45, 987654321, time.UTC)
	maxAgeZero := 0
	grant := storedGrant{
		ID:              "new-grant",
		UserID:          "user",
		ClientID:        "client",
		GrantedScopes:   []string{"openid", "profile"},
		RedirectURI:     "https://client.example/callback",
		CodeChallenge:   "challenge",
		Nonce:           "nonce",
		MaxAge:          &maxAgeZero,
		DPoPThumbprint:  "thumbprint",
		GrantedAt:       base,
		AuthenticatedAt: base.Add(time.Second),
		ExpiresAt:       base.Add(time.Hour),
		ACR:             "urn:example:mfa",
		AMR:             []string{"pwd", "otp"},
	}
	emptyOptional := storedGrant{
		ID:        "empty-grant",
		UserID:    "user",
		ClientID:  "client",
		GrantedAt: base,
		ExpiresAt: base.Add(time.Hour),
	}
	session := storedRefreshSession{
		GrantID:    grant.ID,
		UserID:     grant.UserID,
		ClientID:   grant.ClientID,
		CreatedAt:  grant.GrantedAt,
		ExpiresAt:  grant.ExpiresAt,
		LastUsedAt: base.Add(2 * time.Second),
	}
	if err := store.commit(t.Context(), storageCommit{
		Checks: []storageCheck{
			{Kind: storageKindGrant, ID: grant.ID},
			{Kind: storageKindGrant, ID: emptyOptional.ID},
			{Kind: storageKindSession, ID: grant.ID},
		},
		Grants:   []storedGrant{grant, emptyOptional},
		Sessions: []storedRefreshSession{session},
	}); err != nil {
		t.Fatalf("store typed records: %v", err)
	}

	got, err := store.getGrant(t.Context(), grant.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.RedirectURI != grant.RedirectURI || got.CodeChallenge != grant.CodeChallenge || got.Nonce != grant.Nonce || got.DPoPThumbprint != grant.DPoPThumbprint || got.MaxAge == nil || *got.MaxAge != 0 {
		t.Fatalf("typed grant fields did not round trip: %+v", got)
	}
	if !got.GrantedAt.Equal(base.UTC().Truncate(time.Microsecond)) || !got.AuthenticatedAt.Equal(base.Add(time.Second).UTC().Truncate(time.Microsecond)) || !got.ExpiresAt.Equal(base.Add(time.Hour).UTC().Truncate(time.Microsecond)) {
		t.Fatalf("grant timestamps did not round trip at microsecond precision: %+v", got)
	}
	var timestampType string
	var grantedAt int64
	if err := db.QueryRowContext(t.Context(), `SELECT typeof(granted_at), granted_at FROM oauth2as_grants WHERE id = ?`, grant.ID).Scan(&timestampType, &grantedAt); err != nil {
		t.Fatal(err)
	}
	if timestampType != "integer" || grantedAt != base.UnixMicro() {
		t.Fatalf("granted_at storage = (%s, %d), want (integer, %d)", timestampType, grantedAt, base.UnixMicro())
	}
	emptyGot, err := store.getGrant(t.Context(), emptyOptional.ID)
	if err != nil {
		t.Fatal(err)
	}
	if emptyGot.MaxAge != nil || emptyGot.Nonce != "" || emptyGot.CodeChallenge != "" || emptyGot.RedirectURI != "" || emptyGot.DPoPThumbprint != "" {
		t.Fatalf("empty optional fields did not round trip: %+v", emptyGot)
	}

	sessions, err := store.listRefreshSessions(t.Context(), storageRefreshSessionQuery{UserID: grant.UserID, ActiveAt: base, Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(sessions) != 1 || sessions[0].GrantID != grant.ID || !sessions[0].DPoPBound || !sessions[0].LastUsedAt.Equal(session.LastUsedAt.UTC().Truncate(time.Microsecond)) {
		t.Fatalf("typed session did not round trip: %+v", sessions)
	}

	if err := store.Migrate(t.Context()); err != nil {
		t.Fatalf("second Migrate: %v", err)
	}
	gotAgain, err := store.getGrant(t.Context(), grant.ID)
	if err != nil || gotAgain.Nonce != grant.Nonce || gotAgain.DPoPThumbprint != grant.DPoPThumbprint || gotAgain.MaxAge == nil || *gotAgain.MaxAge != 0 {
		t.Fatalf("second Migrate changed grant: %+v, %v", gotAgain, err)
	}
	sessions, err = store.listRefreshSessions(t.Context(), storageRefreshSessionQuery{UserID: grant.UserID, ActiveAt: base, Limit: 10})
	if err != nil || len(sessions) != 1 || sessions[0].GrantID != grant.ID {
		t.Fatalf("second Migrate changed sessions: %+v, %v", sessions, err)
	}
	assertMigrationVersions(t, db, 1, 3)
}

func TestSQLiteMigrateResetFailureRollsBack(t *testing.T) {
	db, store := legacySQLStorage(t)
	store.migrations[0].up = append(store.migrations[0].up, "CREATE TABLE broken (")
	if err := store.Migrate(t.Context()); err == nil {
		t.Fatal("Migrate succeeded with invalid SQL")
	}
	assertLegacyRowsPresent(t, db)
	assertUnrelatedRow(t, db)
	assertMigrationVersions(t, db, 1)
	assertLegacyGrantColumnPresent(t, db)

	store.migrations = sqlMigrations()
	if err := store.Migrate(t.Context()); err != nil {
		t.Fatalf("Migrate after rollback: %v", err)
	}
	assertLegacyRowsGone(t, db)
	assertUnrelatedRow(t, db)
	assertMigrationVersions(t, db, 1, 3)
	assertNoLegacyGrantColumns(t, db)
}

func assertLegacyRowsGone(t *testing.T, db *sql.DB) {
	t.Helper()
	for _, table := range []string{tblGrants, tblAuthCodes, tblRefreshTokens, tblRefreshSessions} {
		var count int
		if err := db.QueryRowContext(t.Context(), "SELECT count(*) FROM "+table).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count != 0 {
			t.Errorf("%s rows = %d, want 0", table, count)
		}
	}
}

func assertLegacyRowsPresent(t *testing.T, db *sql.DB) {
	t.Helper()
	for _, table := range []string{tblGrants, tblAuthCodes, tblRefreshTokens, tblRefreshSessions} {
		var count int
		if err := db.QueryRowContext(t.Context(), "SELECT count(*) FROM "+table).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count != 1 {
			t.Errorf("%s rows = %d, want 1 after rollback", table, count)
		}
	}
}

func assertUnrelatedRow(t *testing.T, db *sql.DB) {
	t.Helper()
	var value string
	if err := db.QueryRowContext(t.Context(), `SELECT value FROM unrelated_state WHERE id = 'keep'`).Scan(&value); err != nil {
		t.Fatal(err)
	}
	if value != "retained" {
		t.Fatalf("unrelated row value = %q", value)
	}
}

func assertMigrationVersions(t *testing.T, db *sql.DB, want ...int) {
	t.Helper()
	rows, err := db.QueryContext(t.Context(), `SELECT version FROM oauth2as_schema_migrations ORDER BY version`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var got []int
	for rows.Next() {
		var version int
		if err := rows.Scan(&version); err != nil {
			t.Fatal(err)
		}
		got = append(got, version)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(got, want) {
		t.Fatalf("migration versions = %v, want %v", got, want)
	}
}

func assertNoLegacyGrantColumns(t *testing.T, db *sql.DB) {
	t.Helper()
	columns := grantColumns(t, db)
	if columns["metadata"] || columns["encrypted_metadata"] || columns["additional_state"] || columns["request"] {
		t.Fatalf("legacy grant columns remain: %v", columns)
	}
}

func assertLegacyGrantColumnPresent(t *testing.T, db *sql.DB) {
	t.Helper()
	if !grantColumns(t, db)["metadata"] {
		t.Fatal("metadata column missing after failed migration rollback")
	}
}

func grantColumns(t *testing.T, db *sql.DB) map[string]bool {
	t.Helper()
	rows, err := db.QueryContext(t.Context(), "PRAGMA table_info("+tblGrants+")")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	columns := make(map[string]bool)
	for rows.Next() {
		var cid, notNull, primaryKey int
		var name, columnType string
		var defaultValue any
		if err := rows.Scan(&cid, &name, &columnType, &notNull, &defaultValue, &primaryKey); err != nil {
			t.Fatal(err)
		}
		columns[name] = true
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return columns
}

func TestSQLiteMigrateResetsIntermediateSchema(t *testing.T) {
	db, store := newMigratedSQLStorage(t)
	// Reconstruct the intermediate typed schema, which still stored verifiers.
	for _, statement := range []string{
		`ALTER TABLE oauth2as_authorization_codes ADD COLUMN code BLOB`,
		`ALTER TABLE oauth2as_refresh_tokens ADD COLUMN token BLOB`,
		`DELETE FROM oauth2as_schema_migrations`,
		`INSERT INTO oauth2as_schema_migrations VALUES (2, 'passidp_schema', 0)`,
		`CREATE TABLE unrelated_state (id TEXT PRIMARY KEY, value TEXT NOT NULL)`,
		`INSERT INTO unrelated_state VALUES ('keep', 'retained')`,
	} {
		if _, err := db.ExecContext(t.Context(), statement); err != nil {
			t.Fatal(err)
		}
	}
	grantID, err := store.createGrant(t.Context(), &storedGrant{UserID: "user", ClientID: "client", ExpiresAt: time.Now().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(t.Context(), `INSERT INTO oauth2as_authorization_codes VALUES ('old-code', ?, 0, 0, 1, X'01')`, grantID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(t.Context(), `INSERT INTO oauth2as_refresh_tokens VALUES ('old-token', ?, 0, 0, '', 1, X'02')`, grantID); err != nil {
		t.Fatal(err)
	}
	if err := store.Migrate(t.Context()); err != nil {
		t.Fatal(err)
	}
	assertLegacyRowsGone(t, db)
	assertUnrelatedRow(t, db)
	assertMigrationVersions(t, db, 2, 3)
	for _, table := range []string{tblAuthCodes, tblRefreshTokens} {
		var count int
		if err := db.QueryRowContext(t.Context(), `SELECT count(*) FROM pragma_table_info(?) WHERE name IN ('code', 'token')`, table).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count != 0 {
			t.Fatalf("%s retains a verifier column", table)
		}
	}
}
