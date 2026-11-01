package oauth2as

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestStorageCleanup(t *testing.T) {
	store := newTestStorage(t)
	now := time.Now().Round(0)
	for _, item := range []struct {
		id      string
		expires time.Time
	}{
		{"expired-1", now.Add(-time.Minute)},
		{"expired-2", now},
		{"active", now.Add(time.Minute)},
	} {
		if err := store.seed(context.Background(), storageFixtures{
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
	for _, id := range []string{"active"} {
		if _, err := store.getGrant(context.Background(), id); err != nil {
			t.Fatalf("unexpired grant %q: %v", id, err)
		}
	}
}

func TestStorageCleanupCascadesGrantChildren(t *testing.T) {
	store := newTestStorage(t)
	now := time.Now().Round(0)
	grantID := "grant-1"
	if err := store.seed(context.Background(), storageFixtures{
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
	if _, err := newTestStorage(t).Cleanup(context.Background(), CleanupOptions{Limit: maxCleanupLimit + 1}); err == nil {
		t.Fatal("oversized cleanup limit accepted")
	}
}
