package storage_test

import (
	"context"
	"testing"

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
