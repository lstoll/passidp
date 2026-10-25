package oauth2as

import "testing"

// newTestStorage returns migrated SQLite storage backed by a database file in
// a per-test temp directory.
func newTestStorage(t *testing.T) *Storage {
	t.Helper()
	_, store := newMigratedSQLStorage(t)
	return store
}

// refreshTokenCount returns the number of stored refresh token records.
func refreshTokenCount(t *testing.T, store *Storage) int {
	t.Helper()
	var n int
	if err := store.backend.db.QueryRowContext(t.Context(), "SELECT COUNT(*) FROM oauth2as_refresh_tokens").Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}
