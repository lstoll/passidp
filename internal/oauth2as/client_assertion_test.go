package oauth2as

import (
	"errors"
	"testing"
	"time"
)

func TestClientAssertionReplayScopesByClient(t *testing.T) {
	store := newTestStorage(t)
	until := time.Now().Add(time.Minute)
	if err := store.useClientAssertion(t.Context(), "client-a", "same-jti", until); err != nil {
		t.Fatal(err)
	}
	if err := store.useClientAssertion(t.Context(), "client-b", "same-jti", until); err != nil {
		t.Fatalf("different client was treated as a replay: %v", err)
	}
	if err := store.useClientAssertion(t.Context(), "client-a", "same-jti", until); !errors.Is(err, ErrClientAssertionReplay) {
		t.Fatalf("same client replay error = %v", err)
	}
}

func TestClientAssertionReplaySurvivesNewStorageHandle(t *testing.T) {
	store := newTestStorage(t)
	until := time.Now().Add(time.Minute)
	if err := store.useClientAssertion(t.Context(), "client", "jti", until); err != nil {
		t.Fatal(err)
	}
	// A fresh handle on the same database models a restart or second replica.
	reopened, err := NewSQLStorage(store.db)
	if err != nil {
		t.Fatal(err)
	}
	if err := reopened.useClientAssertion(t.Context(), "client", "jti", until); !errors.Is(err, ErrClientAssertionReplay) {
		t.Fatalf("replay after reopen error = %v, want ErrClientAssertionReplay", err)
	}
}

func TestClientAssertionReplayExpiryAndCleanup(t *testing.T) {
	store := newTestStorage(t)
	if _, err := store.db.ExecContext(t.Context(), `INSERT INTO oauth2as_client_assertions (assertion_key, expires_at) VALUES (?, ?)`,
		keyBytes("client", "stale"), time.Now().Add(-time.Second).UnixMicro()); err != nil {
		t.Fatal(err)
	}
	// An expired record that was not cleaned up yet does not block a new use.
	if err := store.useClientAssertion(t.Context(), "client", "stale", time.Now().Add(time.Minute)); err != nil {
		t.Fatalf("reuse of expired record: %v", err)
	}
	if err := store.useClientAssertion(t.Context(), "client", "old", time.Now().Add(time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	result, err := store.Cleanup(t.Context(), CleanupOptions{Before: time.Now().Add(time.Second)})
	if err != nil {
		t.Fatal(err)
	}
	if result.Deleted != 1 {
		t.Fatalf("cleanup deleted %d records, want 1", result.Deleted)
	}
	var remaining int
	if err := store.db.QueryRowContext(t.Context(), `SELECT count(*) FROM oauth2as_client_assertions`).Scan(&remaining); err != nil {
		t.Fatal(err)
	}
	if remaining != 1 {
		t.Fatalf("remaining assertion records = %d, want 1", remaining)
	}
}

func keyBytes(clientID, jti string) []byte {
	key := clientAssertionKey(clientID, jti)
	return key[:]
}
