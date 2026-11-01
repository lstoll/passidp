package oauth2as_test

import (
	"crypto/rand"
	"database/sql"
	"testing"

	"lds.li/passidp/internal/oauth2as"
	"lds.li/passidp/internal/storage/migrations"
	_ "modernc.org/sqlite"
)

// newTestStorage uses the application's migrated, shared in-memory SQLite database.
func newTestStorage(t *testing.T) *oauth2as.Storage {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+rand.Text()+"?mode=memory&cache=shared&_pragma=foreign_keys(ON)&_pragma=busy_timeout(5000)")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if err := migrations.Apply(t.Context(), db); err != nil {
		t.Fatal(err)
	}
	db.SetMaxIdleConns(1)
	db.SetMaxOpenConns(4)
	store, err := oauth2as.NewSQLStorage(db)
	if err != nil {
		t.Fatal(err)
	}
	return store
}
