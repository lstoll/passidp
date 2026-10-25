package oauth2as_test

import (
	"database/sql"
	"path/filepath"
	"testing"

	"lds.li/passidp/internal/oauth2as"
	_ "modernc.org/sqlite"
)

// newTestStorage returns migrated SQLite storage backed by a database file in
// a per-test temp directory.
func newTestStorage(t *testing.T) *oauth2as.Storage {
	t.Helper()
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	store, err := oauth2as.NewSQLStorage(db)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Migrate(t.Context()); err != nil {
		t.Fatal(err)
	}
	return store
}
