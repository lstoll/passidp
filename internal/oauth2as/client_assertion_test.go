package oauth2as

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestClientAssertionReplayStoreScopesByClient(t *testing.T) {
	store := newMemoryClientAssertionReplayStore()
	until := time.Now().Add(time.Minute)
	if err := store.Use(context.Background(), "client-a", "same-jti", until); err != nil {
		t.Fatal(err)
	}
	if err := store.Use(context.Background(), "client-b", "same-jti", until); err != nil {
		t.Fatalf("different client was treated as a replay: %v", err)
	}
	if err := store.Use(context.Background(), "client-a", "same-jti", until); !errors.Is(err, ErrClientAssertionReplay) {
		t.Fatalf("same client replay error = %v", err)
	}
}
