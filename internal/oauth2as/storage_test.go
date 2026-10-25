package oauth2as

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestSQLStorageTablePrefix(t *testing.T) {
	for _, prefix := range []string{"UPPER", "has-hyphen", strings.Repeat("a", 64)} {
		if _, err := NewSQLStorage(new(sql.DB), SQLStorageOptions{
			Dialect:     SQLDialectPostgreSQL,
			TablePrefix: prefix,
		}); err == nil {
			t.Errorf("invalid table prefix %q accepted", prefix)
		}
	}
}

func TestMemoryStorageCleanup(t *testing.T) {
	store := NewMemoryStorage()
	now := time.Now().Round(0)
	for _, item := range []struct {
		id      string
		expires time.Time
	}{
		{"expired-1", now.Add(-time.Minute)},
		{"expired-2", now},
		{"active", now.Add(time.Minute)},
		{"retained", time.Time{}},
	} {
		if err := store.commit(context.Background(), storageCommit{
			Checks: []storageCheck{{Kind: storageKindGrant, ID: item.id}},
			Grants: []storedGrant{{ID: item.id, UserID: "user", ClientID: "client", ExpiresAt: item.expires}},
		}); err != nil {
			t.Fatal(err)
		}
	}

	result, err := store.Cleanup(context.Background(), CleanupOptions{Before: now, Limit: 1})
	if err != nil {
		t.Fatal(err)
	}
	if result.Deleted != 1 || !result.More {
		t.Fatalf("first cleanup = %#v, want one deletion with more work", result)
	}
	result, err = store.Cleanup(context.Background(), CleanupOptions{Before: now, Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if result.Deleted != 1 || result.More {
		t.Fatalf("second cleanup = %#v, want one deletion and no more work", result)
	}
	for _, id := range []string{"active", "retained"} {
		if _, err := store.getGrant(context.Background(), id); err != nil {
			t.Fatalf("retained grant %q: %v", id, err)
		}
	}
}

func TestMemoryStorageCleanupCascadesGrantChildren(t *testing.T) {
	store := NewMemoryStorage()
	now := time.Now().Round(0)
	grantID := "grant-1"
	if err := store.commit(context.Background(), storageCommit{
		Checks: []storageCheck{
			{Kind: storageKindGrant, ID: grantID},
			{Kind: storageKindAuthCode, ID: "code-1"},
			{Kind: storageKindRefreshToken, ID: "token-1"},
			{Kind: storageKindSession, ID: grantID},
		},
		Grants:        []storedGrant{{ID: grantID, UserID: "user", ClientID: "client", ExpiresAt: now}},
		AuthCodes:     []storedAuthCode{{ID: "code-1", GrantID: grantID, StorageExpiresAt: now.Add(time.Hour)}},
		RefreshTokens: []storedRefreshToken{{ID: "token-1", GrantID: grantID, StorageExpiresAt: now.Add(time.Hour)}},
		Sessions:      []storedRefreshSession{{GrantID: grantID, UserID: "user", ClientID: "client", ExpiresAt: now}},
	}); err != nil {
		t.Fatal(err)
	}

	result, err := store.Cleanup(context.Background(), CleanupOptions{Before: now, Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if result.More {
		t.Fatalf("cleanup = %#v, want no remaining work", result)
	}
	if _, err := store.getGrant(context.Background(), grantID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("grant survived cleanup: %v", err)
	}
	if _, err := store.getAuthCode(context.Background(), "code-1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("auth code survived grant cleanup: %v", err)
	}
	if _, err := store.getRefreshToken(context.Background(), "token-1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("refresh token survived grant cleanup: %v", err)
	}
	page, err := store.listRefreshSessions(context.Background(), storageRefreshSessionQuery{UserID: "user", ActiveAt: now.Add(-time.Second), Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(page) != 0 {
		t.Fatalf("listed %d sessions after grant cleanup, want 0", len(page))
	}
}

func TestStorageCleanupValidation(t *testing.T) {
	if _, err := (*Storage)(nil).Cleanup(context.Background(), CleanupOptions{}); err == nil {
		t.Fatal("nil storage accepted")
	}
	if _, err := new(Storage).Cleanup(context.Background(), CleanupOptions{}); err == nil {
		t.Fatal("zero storage accepted")
	}
	if _, err := NewMemoryStorage().Cleanup(context.Background(), CleanupOptions{Limit: maxCleanupLimit + 1}); err == nil {
		t.Fatal("oversized cleanup limit accepted")
	}
}

func TestStorageMigrateValidation(t *testing.T) {
	if err := (*Storage)(nil).Migrate(context.Background()); err == nil {
		t.Fatal("nil storage accepted")
	}
	if err := new(Storage).Migrate(context.Background()); err == nil {
		t.Fatal("zero storage accepted")
	}
	if err := NewMemoryStorage().Migrate(context.Background()); err != nil {
		t.Fatalf("memory migrate: %v", err)
	}
}
