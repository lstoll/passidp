package storage

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	bolt "go.etcd.io/bbolt"
	"lds.li/web/session"
)

var _ session.KV = (*SessionKV)(nil)

const (
	// Bucket name for session storage
	bucketSessions = "sessions"
)

// SessionKV implements session.KV using BoltDB
type SessionKV struct {
	db *bolt.DB
}

// NewSessionKV creates a new SessionKV from a State instance
func NewSessionKV(state *State) *SessionKV {
	return &SessionKV{db: state.db}
}

// storedSession represents a session stored in BoltDB
type storedSession struct {
	Data      []byte    `json:"data"`
	ExpiresAt time.Time `json:"expires_at"`
}

// Get retrieves a value by key, checking expiration
func (s *SessionKV) Get(ctx context.Context, key string) (_ []byte, found bool, _ error) {
	var data []byte
	err := s.db.View(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte(bucketSessions))
		if bucket == nil {
			return nil // No bucket means no session
		}

		sessionData := bucket.Get([]byte(key))
		if sessionData == nil {
			return nil // Session not found
		}

		var stored storedSession
		if err := json.Unmarshal(sessionData, &stored); err != nil {
			return fmt.Errorf("unmarshal session: %w", err)
		}

		// Check expiration
		if time.Now().After(stored.ExpiresAt) {
			return nil // Session expired
		}

		data = stored.Data
		return nil
	})

	if err != nil {
		return nil, false, fmt.Errorf("getting %s: %w", key, err)
	}

	if data == nil {
		return nil, false, nil
	}

	return data, true, nil
}

// Set stores a key with a given value and expiration time, creating or updating as needed
func (s *SessionKV) Set(ctx context.Context, key string, expiresAt time.Time, value []byte) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte(bucketSessions))
		if bucket == nil {
			return fmt.Errorf("sessions bucket does not exist")
		}

		stored := storedSession{
			Data:      value,
			ExpiresAt: expiresAt,
		}

		data, err := json.Marshal(stored)
		if err != nil {
			return fmt.Errorf("marshal session: %w", err)
		}

		if err := bucket.Put([]byte(key), data); err != nil {
			return fmt.Errorf("storing session: %w", err)
		}

		return nil
	})
}

// Delete removes a key from the store
func (s *SessionKV) Delete(ctx context.Context, key string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte(bucketSessions))
		if bucket == nil {
			return nil // No bucket means nothing to delete
		}

		if err := bucket.Delete([]byte(key)); err != nil {
			return fmt.Errorf("deleting %s: %w", key, err)
		}

		return nil
	})
}

// GC performs garbage collection, removing expired sessions
func (s *SessionKV) GC(ctx context.Context) (deleted int, _ error) {
	var count int
	err := s.db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte(bucketSessions))
		if bucket == nil {
			return nil // No bucket means nothing to clean
		}

		now := time.Now()
		toDelete := make([][]byte, 0)

		// First pass: collect expired keys
		err := bucket.ForEach(func(k, v []byte) error {
			var stored storedSession
			if err := json.Unmarshal(v, &stored); err != nil {
				// If we can't unmarshal, consider it corrupted and delete it
				toDelete = append(toDelete, k)
				return nil
			}

			if now.After(stored.ExpiresAt) {
				toDelete = append(toDelete, k)
			}

			return nil
		})

		if err != nil {
			return fmt.Errorf("iterating sessions: %w", err)
		}

		// Second pass: delete expired keys
		for _, key := range toDelete {
			if err := bucket.Delete(key); err != nil {
				return fmt.Errorf("deleting expired session: %w", err)
			}
			count++
		}

		return nil
	})

	if err != nil {
		return 0, fmt.Errorf("gc: %w", err)
	}

	return count, nil
}

// RunGC starts a background goroutine that performs garbage collection at regular intervals
func (s *SessionKV) RunGC(ctx context.Context, interval time.Duration, logger *slog.Logger) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				if logger != nil {
					logger.InfoContext(ctx, "Garbage collection stopped", "reason", ctx.Err())
				}
				return
			case <-ticker.C:
				deleted, err := s.GC(ctx)
				if err != nil {
					if logger != nil {
						logger.ErrorContext(ctx, "Garbage collection failed", "error", err)
					}
				} else if logger != nil {
					logger.InfoContext(ctx, "Garbage collection successful", "deleted_sessions", deleted)
				}
			}
		}
	}()
}
