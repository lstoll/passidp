package storage

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestRunCompactor(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "state.bolt")

	state, err := NewState(dbPath)
	if err != nil {
		t.Fatalf("failed to create state: %v", err)
	}
	defer state.Close()

	kv := state.SessionKV()
	expiresAt := time.Now().Add(time.Hour)
	if err := kv.Set(context.Background(), "smoke-test-key", expiresAt, []byte("smoke-test-value")); err != nil {
		t.Fatalf("failed to set session data: %v", err)
	}

	_, found, err := kv.Get(context.Background(), "smoke-test-key")
	if err != nil {
		t.Fatalf("failed to get session before compaction: %v", err)
	}
	if !found {
		t.Fatal("expected session to exist before compaction")
	}

	log := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	log = log.With("component", "compactor_test")

	if err := state.runCompactor(log); err != nil {
		t.Fatalf("runCompactor failed: %v", err)
	}

	value, found, err := kv.Get(context.Background(), "smoke-test-key")
	if err != nil {
		t.Fatalf("failed to get session after compaction: %v", err)
	}
	if !found {
		t.Fatal("expected session to exist after compaction")
	}
	if string(value) != "smoke-test-value" {
		t.Errorf("expected value %q after compaction, got %q", "smoke-test-value", string(value))
	}
}
