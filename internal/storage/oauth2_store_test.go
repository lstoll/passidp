package storage_test

import (
	"context"
	"testing"
	"time"

	"lds.li/passidp/internal/oauth2as"
	"lds.li/passidp/internal/storage"
)

func TestNewOAuth2Storage(t *testing.T) {
	ctx := context.Background()
	store, err := storage.NewOAuth2Storage(ctx, storage.OpenTest(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Cleanup(ctx, oauth2as.CleanupOptions{}); err != nil {
		t.Fatal(err)
	}
}

func TestOAuth2GrantsDPoPBound(t *testing.T) {
	ctx := context.Background()
	sqlDB := storage.OpenTest(t)
	if _, err := storage.NewOAuth2Storage(ctx, sqlDB); err != nil {
		t.Fatal(err)
	}

	now := time.Now().UTC().Format("2006-01-02T15:04:05.000000Z")
	insertGrant := func(id, additionalState string) {
		t.Helper()
		_, err := sqlDB.Exec(`
			INSERT INTO oauth2as_grants (id, user_id, client_id, granted_scopes, granted_at, expires_at, additional_state, version)
			VALUES (?, 'user', 'client', '[]', ?, ?, ?, 1)`,
			id, now, now, additionalState)
		if err != nil {
			t.Fatal(err)
		}
	}
	insertGrant("bound", `{"dpopThumbprint":"abc"}`)
	insertGrant("unbound", `{}`)
	insertGrant("empty", `{"dpopThumbprint":""}`)

	bound, err := storage.NewOAuth2Grants(sqlDB).DPoPBound(ctx, []string{"bound", "unbound", "empty", "missing"})
	if err != nil {
		t.Fatal(err)
	}
	if !bound["bound"] {
		t.Fatal("expected bound grant to be DPoP constrained")
	}
	if bound["unbound"] || bound["empty"] || bound["missing"] {
		t.Fatalf("unexpected DPoP bindings: %#v", bound)
	}

	empty, err := storage.NewOAuth2Grants(sqlDB).DPoPBound(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(empty) != 0 {
		t.Fatalf("empty lookup = %#v, want empty map", empty)
	}
}
