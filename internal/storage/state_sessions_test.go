package storage

import (
	"context"
	"testing"
	"time"
)

func TestSessionKV(t *testing.T) {
	// Create a new State instance
	state, err := NewState(t.TempDir() + "/state.bolt")
	if err != nil {
		t.Fatalf("failed to create state: %v", err)
	}
	defer state.db.Close()

	// Create a SessionKV
	kv := NewSessionKV(state)

	key := "test-session-key"
	value := []byte("test-session-value")
	expiresAt := time.Now().Add(time.Hour)

	// Test Set
	err = kv.Set(context.Background(), key, expiresAt, value)
	if err != nil {
		t.Fatalf("failed to set session: %v", err)
	}

	// Test Get (should find it)
	retrievedValue, found, err := kv.Get(context.Background(), key)
	if err != nil {
		t.Fatalf("failed to get session: %v", err)
	}
	if !found {
		t.Fatal("expected session to be found")
	}
	if string(retrievedValue) != string(value) {
		t.Errorf("expected value %q, got %q", string(value), string(retrievedValue))
	}

	// Test updating the session
	newValue := []byte("updated-session-value")
	newExpiresAt := time.Now().Add(2 * time.Hour)
	err = kv.Set(context.Background(), key, newExpiresAt, newValue)
	if err != nil {
		t.Fatalf("failed to update session: %v", err)
	}

	// Verify update
	updatedValue, found, err := kv.Get(context.Background(), key)
	if err != nil {
		t.Fatalf("failed to get updated session: %v", err)
	}
	if !found {
		t.Fatal("expected updated session to be found")
	}
	if string(updatedValue) != string(newValue) {
		t.Errorf("expected updated value %q, got %q", string(newValue), string(updatedValue))
	}

	// Test Delete
	err = kv.Delete(context.Background(), key)
	if err != nil {
		t.Fatalf("failed to delete session: %v", err)
	}

	// Verify deletion
	deletedValue, found, err := kv.Get(context.Background(), key)
	if err != nil {
		t.Fatalf("failed to get deleted session: %v", err)
	}
	if found {
		t.Error("expected session to not be found after deletion")
	}
	if deletedValue != nil {
		t.Errorf("expected nil value, got %q", string(deletedValue))
	}

	// Test expiration
	expiredKey := "expired-session"
	expiredValue := []byte("expired-value")
	pastExpiresAt := time.Now().Add(-time.Hour) // Expired 1 hour ago

	err = kv.Set(context.Background(), expiredKey, pastExpiresAt, expiredValue)
	if err != nil {
		t.Fatalf("failed to set expired session: %v", err)
	}

	// Should not find expired session
	expiredRetrieved, found, err := kv.Get(context.Background(), expiredKey)
	if err != nil {
		t.Fatalf("failed to get expired session: %v", err)
	}
	if found {
		t.Error("expected expired session to not be found")
	}
	if expiredRetrieved != nil {
		t.Errorf("expected nil value for expired session, got %q", string(expiredRetrieved))
	}
}

func TestSessionKVGC(t *testing.T) {
	// Create a new State instance
	state, err := NewState(t.TempDir() + "/state.bolt")
	if err != nil {
		t.Fatalf("failed to create state: %v", err)
	}
	defer state.db.Close()

	// Create a SessionKV
	kv := NewSessionKV(state)

	// Create some expired sessions
	expiredKeys := []string{"expired1", "expired2", "expired3"}
	pastExpiresAt := time.Now().Add(-time.Hour)
	for _, key := range expiredKeys {
		err := kv.Set(context.Background(), key, pastExpiresAt, []byte("expired-value"))
		if err != nil {
			t.Fatalf("failed to set expired session %s: %v", key, err)
		}
	}

	// Create some valid sessions
	validKeys := []string{"valid1", "valid2"}
	futureExpiresAt := time.Now().Add(time.Hour)
	for _, key := range validKeys {
		err := kv.Set(context.Background(), key, futureExpiresAt, []byte("valid-value"))
		if err != nil {
			t.Fatalf("failed to set valid session %s: %v", key, err)
		}
	}

	// Run GC
	deleted, err := kv.GC(context.Background())
	if err != nil {
		t.Fatalf("failed to run GC: %v", err)
	}
	if deleted != len(expiredKeys) {
		t.Errorf("expected %d deleted sessions, got %d", len(expiredKeys), deleted)
	}

	// Verify expired sessions are gone
	for _, key := range expiredKeys {
		value, found, err := kv.Get(context.Background(), key)
		if err != nil {
			t.Fatalf("failed to get expired session %s: %v", key, err)
		}
		if found {
			t.Errorf("expected expired session %s to be deleted", key)
		}
		if value != nil {
			t.Errorf("expected nil value for expired session %s, got %q", key, string(value))
		}
	}

	// Verify valid sessions still exist
	for _, key := range validKeys {
		value, found, err := kv.Get(context.Background(), key)
		if err != nil {
			t.Fatalf("failed to get valid session %s: %v", key, err)
		}
		if !found {
			t.Errorf("expected valid session %s to still exist", key)
		}
		if string(value) != "valid-value" {
			t.Errorf("expected value 'valid-value' for session %s, got %q", key, string(value))
		}
	}
}

func TestSessionKVMultipleSessions(t *testing.T) {
	// Create a new State instance
	state, err := NewState(t.TempDir() + "/state.bolt")
	if err != nil {
		t.Fatalf("failed to create state: %v", err)
	}
	defer state.db.Close()

	// Create a SessionKV
	kv := NewSessionKV(state)

	// Create multiple sessions
	sessions := map[string][]byte{
		"session1": []byte("value1"),
		"session2": []byte("value2"),
		"session3": []byte("value3"),
	}
	expiresAt := time.Now().Add(time.Hour)

	for key, value := range sessions {
		err := kv.Set(context.Background(), key, expiresAt, value)
		if err != nil {
			t.Fatalf("failed to set session %s: %v", key, err)
		}
	}

	// Verify all sessions exist
	for key, expectedValue := range sessions {
		value, found, err := kv.Get(context.Background(), key)
		if err != nil {
			t.Fatalf("failed to get session %s: %v", key, err)
		}
		if !found {
			t.Errorf("expected session %s to be found", key)
		}
		if string(value) != string(expectedValue) {
			t.Errorf("expected value %q for session %s, got %q", string(expectedValue), key, string(value))
		}
	}
}
