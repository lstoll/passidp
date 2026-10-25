package oauth2as

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

func testStorage(t *testing.T, factory func(t *testing.T) *Storage) {
	t.Helper()
	ctx := context.Background()

	t.Run("Get_notFound", func(t *testing.T) {
		_, err := factory(t).getGrant(ctx, "missing")
		if !errors.Is(err, ErrNotFound) {
			t.Fatalf("getGrant() error = %v, want ErrNotFound", err)
		}
	})

	t.Run("CreateAndGet", func(t *testing.T) {
		store := factory(t)
		expires := time.Now().Add(time.Hour).Round(0)
		if err := store.commit(ctx, storageCommit{
			Checks: []storageCheck{{Kind: storageKindGrant, ID: "g1"}},
			Grants: []storedGrant{{ID: "g1", UserID: "user", ClientID: "client", Metadata: []byte("opaque"), ExpiresAt: expires}},
		}); err != nil {
			t.Fatal(err)
		}
		got, err := store.getGrant(ctx, "g1")
		if err != nil {
			t.Fatal(err)
		}
		if got.storageVersion != 1 || got.UserID != "user" || string(got.Metadata) != "opaque" || !got.ExpiresAt.Equal(expires) {
			t.Fatalf("unexpected grant: %#v", got)
		}
		got.Metadata[0] = 'X'
		again, err := store.getGrant(ctx, "g1")
		if err != nil {
			t.Fatal(err)
		}
		if string(again.Metadata) != "opaque" {
			t.Fatal("Get returned storage-owned memory")
		}
	})

	t.Run("ConditionalUpdate", func(t *testing.T) {
		store := factory(t)
		if err := store.commit(ctx, storageCommit{
			Checks: []storageCheck{{Kind: storageKindGrant, ID: "g1"}},
			Grants: []storedGrant{{ID: "g1", UserID: "one"}},
		}); err != nil {
			t.Fatal(err)
		}
		if err := store.commit(ctx, storageCommit{
			Checks: []storageCheck{{Kind: storageKindGrant, ID: "g1", Version: 1}},
			Grants: []storedGrant{{ID: "g1", UserID: "two"}},
		}); err != nil {
			t.Fatal(err)
		}
		got, err := store.getGrant(ctx, "g1")
		if err != nil {
			t.Fatal(err)
		}
		if got.storageVersion != 2 || got.UserID != "two" {
			t.Fatalf("unexpected updated grant: %#v", got)
		}
		if err := store.commit(ctx, storageCommit{
			Checks:  []storageCheck{{Kind: storageKindGrant, ID: "g1", Version: 1}},
			Deletes: []storageRef{{Kind: storageKindGrant, ID: "g1"}},
		}); !errors.Is(err, errStorageConflict) {
			t.Fatalf("stale commit error = %v, want storage conflict", err)
		}
	})

	t.Run("AtomicFailure", func(t *testing.T) {
		store := factory(t)
		if err := store.commit(ctx, storageCommit{
			Checks: []storageCheck{{Kind: storageKindGrant, ID: "g1"}},
			Grants: []storedGrant{{ID: "g1", UserID: "original"}},
		}); err != nil {
			t.Fatal(err)
		}
		err := store.commit(ctx, storageCommit{
			Checks: []storageCheck{
				{Kind: storageKindGrant, ID: "g1"},
				{Kind: storageKindAuthCode, ID: "c1"},
			},
			Grants:    []storedGrant{{ID: "g1", UserID: "changed"}},
			AuthCodes: []storedAuthCode{{ID: "c1", GrantID: "g1"}},
		})
		if !errors.Is(err, errStorageConflict) {
			t.Fatalf("Commit() error = %v, want storage conflict", err)
		}
		got, err := store.getGrant(ctx, "g1")
		if err != nil || got.UserID != "original" {
			t.Fatalf("grant changed after failed commit: %#v, %v", got, err)
		}
		if _, err := store.getAuthCode(ctx, "c1"); !errors.Is(err, ErrNotFound) {
			t.Fatalf("auth code created after failed commit: %v", err)
		}
	})

	t.Run("DuplicateMutationRejected", func(t *testing.T) {
		store := factory(t)
		err := store.commit(ctx, storageCommit{
			Grants:  []storedGrant{{ID: "g1", UserID: "user"}},
			Deletes: []storageRef{{Kind: storageKindGrant, ID: "g1"}},
		})
		if err == nil {
			t.Fatal("Commit() accepted duplicate mutation")
		}
		if _, err := store.getGrant(ctx, "g1"); !errors.Is(err, ErrNotFound) {
			t.Fatalf("duplicate mutation partially applied: %v", err)
		}
	})

	t.Run("Delete", func(t *testing.T) {
		store := factory(t)
		if err := store.commit(ctx, storageCommit{
			Checks: []storageCheck{{Kind: storageKindGrant, ID: "g1"}},
			Grants: []storedGrant{{ID: "g1", UserID: "user"}},
		}); err != nil {
			t.Fatal(err)
		}
		if err := store.commit(ctx, storageCommit{
			Checks:  []storageCheck{{Kind: storageKindGrant, ID: "g1", Version: 1}},
			Deletes: []storageRef{{Kind: storageKindGrant, ID: "g1"}},
		}); err != nil {
			t.Fatal(err)
		}
		if _, err := store.getGrant(ctx, "g1"); !errors.Is(err, ErrNotFound) {
			t.Fatalf("getGrant() after delete error = %v, want ErrNotFound", err)
		}
	})

	t.Run("ConcurrentCAS", func(t *testing.T) {
		store := factory(t)
		if err := store.commit(ctx, storageCommit{
			Checks: []storageCheck{{Kind: storageKindGrant, ID: "g1"}},
			Grants: []storedGrant{{ID: "g1", UserID: "zero"}},
		}); err != nil {
			t.Fatal(err)
		}
		start := make(chan struct{})
		errs := make(chan error, 2)
		var wg sync.WaitGroup
		for _, userID := range []string{"one", "two"} {
			wg.Go(func() {
				<-start
				errs <- store.commit(ctx, storageCommit{
					Checks: []storageCheck{{Kind: storageKindGrant, ID: "g1", Version: 1}},
					Grants: []storedGrant{{ID: "g1", UserID: userID}},
				})
			})
		}
		close(start)
		wg.Wait()
		close(errs)
		var successes, conflicts int
		for err := range errs {
			switch {
			case err == nil:
				successes++
			case errors.Is(err, errStorageConflict):
				conflicts++
			default:
				t.Fatalf("unexpected commit error: %v", err)
			}
		}
		if successes != 1 || conflicts != 1 {
			t.Fatalf("successes=%d conflicts=%d, want 1 each", successes, conflicts)
		}
	})
}
