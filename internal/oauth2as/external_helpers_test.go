package oauth2as_test

import (
	"database/sql"
	"testing"

	"lds.li/passidp/internal/oauth2as"
	_ "modernc.org/sqlite"
	"uuid"
)

// newTestStorage returns migrated SQLite storage backed by an isolated,
// shared in-memory database. Pragmas apply to every pooled connection.
func newTestStorage(t *testing.T) *oauth2as.Storage {
	t.Helper()
	dsn := "file:" + uuid.NewV4().String() + "?mode=memory&cache=shared&_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxIdleConns(1)
	db.SetMaxOpenConns(4)
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
