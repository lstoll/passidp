package storage

import (
	"context"
	"testing"

	"github.com/tink-crypto/tink-go/v2/jwt"
	"github.com/tink-crypto/tink-go/v2/keyset"
	"lds.li/tinkrotate"
	tinkrotatev1 "lds.li/tinkrotate/proto/tinkrotate/v1"
)

func TestKeysetStore(t *testing.T) {
	// Create a new State instance
	state, err := NewState(t.TempDir() + "/state.bolt")
	if err != nil {
		t.Fatalf("failed to create state: %v", err)
	}
	defer state.db.Close()

	// Create a KeysetStore
	store := NewKeysetStore(state)

	// Create a test keyset handle
	handle, err := keyset.NewHandle(jwt.RS256_2048_F4_Key_Template())
	if err != nil {
		t.Fatalf("failed to create keyset handle: %v", err)
	}

	keysetName := "test-keyset"
	metadata := &tinkrotatev1.KeyRotationMetadata{
		RotationPolicy: &tinkrotatev1.RotationPolicy{
			KeyTemplate: jwt.RS256_2048_F4_Key_Template(),
		},
	}

	// Test writing a new keyset (insert)
	err = store.WriteKeysetAndMetadata(context.Background(), keysetName, handle, metadata, nil)
	if err != nil {
		t.Fatalf("failed to write keyset: %v", err)
	}

	// Test reading the keyset
	result, err := store.ReadKeysetAndMetadata(context.Background(), keysetName)
	if err != nil {
		t.Fatalf("failed to read keyset: %v", err)
	}
	if result == nil {
		t.Fatal("expected result to be non-nil")
	}
	if result.Handle == nil {
		t.Fatal("expected handle to be non-nil")
	}
	if result.Metadata == nil {
		t.Fatal("expected metadata to be non-nil")
	}
	if result.Metadata.RotationPolicy == nil {
		t.Error("expected RotationPolicy to be non-nil")
	}
	if result.Context != int64(1) {
		t.Errorf("expected version 1, got %v", result.Context)
	}

	// Test GetHandle
	retrievedHandle, err := store.GetHandle(context.Background(), keysetName)
	if err != nil {
		t.Fatalf("failed to get handle: %v", err)
	}
	if retrievedHandle == nil {
		t.Fatal("expected handle to be non-nil")
	}

	// Test GetPublicHandle
	publicHandle, err := store.GetPublicHandle(context.Background(), keysetName)
	if err != nil {
		t.Fatalf("failed to get public handle: %v", err)
	}
	if publicHandle == nil {
		t.Fatal("expected public handle to be non-nil")
	}

	// Test updating the keyset with correct version (optimistic locking)
	updatedMetadata := &tinkrotatev1.KeyRotationMetadata{
		RotationPolicy: &tinkrotatev1.RotationPolicy{
			KeyTemplate: jwt.ES256Template(),
		},
	}
	err = store.WriteKeysetAndMetadata(context.Background(), keysetName, handle, updatedMetadata, int64(1))
	if err != nil {
		t.Fatalf("failed to update keyset: %v", err)
	}

	// Verify update
	updatedResult, err := store.ReadKeysetAndMetadata(context.Background(), keysetName)
	if err != nil {
		t.Fatalf("failed to read updated keyset: %v", err)
	}
	if updatedResult.Metadata.RotationPolicy == nil {
		t.Error("expected RotationPolicy to be non-nil")
	}
	if updatedResult.Context != int64(2) {
		t.Errorf("expected version 2, got %v", updatedResult.Context)
	}

	// Test optimistic lock failure (wrong version)
	err = store.WriteKeysetAndMetadata(context.Background(), keysetName, handle, updatedMetadata, int64(1))
	if err != tinkrotate.ErrOptimisticLockFailed {
		t.Errorf("expected ErrOptimisticLockFailed, got %v", err)
	}

	// Test reading non-existent keyset
	_, err = store.ReadKeysetAndMetadata(context.Background(), "non-existent")
	if err != tinkrotate.ErrKeysetNotFound {
		t.Errorf("expected ErrKeysetNotFound, got %v", err)
	}

	// Test ForEachKeyset
	keysetNames := make(map[string]bool)
	err = store.ForEachKeyset(context.Background(), func(name string) error {
		keysetNames[name] = true
		return nil
	})
	if err != nil {
		t.Fatalf("failed to iterate keysets: %v", err)
	}
	if !keysetNames[keysetName] {
		t.Errorf("expected to find keyset %s in iteration", keysetName)
	}

	// Test writing another keyset
	handle2, err := keyset.NewHandle(jwt.ES256Template())
	if err != nil {
		t.Fatalf("failed to create second keyset handle: %v", err)
	}
	keysetName2 := "test-keyset-2"
	metadata2 := &tinkrotatev1.KeyRotationMetadata{
		RotationPolicy: &tinkrotatev1.RotationPolicy{
			KeyTemplate: jwt.ES256Template(),
		},
	}
	err = store.WriteKeysetAndMetadata(context.Background(), keysetName2, handle2, metadata2, nil)
	if err != nil {
		t.Fatalf("failed to write second keyset: %v", err)
	}

	// Verify both keysets are found
	keysetNames = make(map[string]bool)
	err = store.ForEachKeyset(context.Background(), func(name string) error {
		keysetNames[name] = true
		return nil
	})
	if err != nil {
		t.Fatalf("failed to iterate keysets: %v", err)
	}
	if len(keysetNames) != 2 {
		t.Errorf("expected 2 keysets, got %d", len(keysetNames))
	}
	if !keysetNames[keysetName] {
		t.Errorf("expected to find keyset %s", keysetName)
	}
	if !keysetNames[keysetName2] {
		t.Errorf("expected to find keyset %s", keysetName2)
	}

	// Test that secrets are preserved (can sign with the handle)
	signer, err := jwt.NewSigner(retrievedHandle)
	if err != nil {
		t.Fatalf("failed to create signer: %v", err)
	}
	if signer == nil {
		t.Fatal("expected signer to be non-nil")
	}
}

func TestKeysetStoreOptimisticLocking(t *testing.T) {
	// Create a new State instance
	state, err := NewState(t.TempDir() + "/state.bolt")
	if err != nil {
		t.Fatalf("failed to create state: %v", err)
	}
	defer state.db.Close()

	// Create a KeysetStore
	store := NewKeysetStore(state)

	// Create a test keyset handle
	handle, err := keyset.NewHandle(jwt.RS256_2048_F4_Key_Template())
	if err != nil {
		t.Fatalf("failed to create keyset handle: %v", err)
	}

	keysetName := "test-lock"
	metadata := &tinkrotatev1.KeyRotationMetadata{
		RotationPolicy: &tinkrotatev1.RotationPolicy{
			KeyTemplate: jwt.RS256_2048_F4_Key_Template(),
		},
	}

	// Insert a keyset
	err = store.WriteKeysetAndMetadata(context.Background(), keysetName, handle, metadata, nil)
	if err != nil {
		t.Fatalf("failed to write keyset: %v", err)
	}

	// Try to insert again (should fail with optimistic lock error)
	err = store.WriteKeysetAndMetadata(context.Background(), keysetName, handle, metadata, nil)
	if err != tinkrotate.ErrOptimisticLockFailed {
		t.Errorf("expected ErrOptimisticLockFailed when inserting existing keyset, got %v", err)
	}

	// Try to update with version 0 (should fail)
	err = store.WriteKeysetAndMetadata(context.Background(), keysetName, handle, metadata, int64(0))
	if err != tinkrotate.ErrOptimisticLockFailed {
		t.Errorf("expected ErrOptimisticLockFailed when updating with version 0, got %v", err)
	}

	// Try to update non-existent keyset (should fail)
	err = store.WriteKeysetAndMetadata(context.Background(), "non-existent", handle, metadata, int64(1))
	if err != tinkrotate.ErrOptimisticLockFailed {
		t.Errorf("expected ErrOptimisticLockFailed when updating non-existent keyset, got %v", err)
	}
}
