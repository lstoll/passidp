package storage

import (
	"fmt"

	bolt "go.etcd.io/bbolt"
)

// State represents the on-disk runtime state for the IDP.
type State struct {
	db *bolt.DB
}

// Close closes the BoltDB database
func (s *State) Close() error {
	return s.db.Close()
}

func NewState(path string) (*State, error) {
	db, err := bolt.Open(path, 0o600, nil)
	if err != nil {
		return nil, fmt.Errorf("open bolt db: %w", err)
	}

	// Initialize buckets
	if err := db.Update(func(tx *bolt.Tx) error {
		if _, err := tx.CreateBucketIfNotExists([]byte(bucketGrants)); err != nil {
			return fmt.Errorf("create grants bucket: %w", err)
		}
		if _, err := tx.CreateBucketIfNotExists([]byte(bucketAuthCodes)); err != nil {
			return fmt.Errorf("create auth codes bucket: %w", err)
		}
		if _, err := tx.CreateBucketIfNotExists([]byte(bucketRefreshTokens)); err != nil {
			return fmt.Errorf("create refresh tokens bucket: %w", err)
		}
		if _, err := tx.CreateBucketIfNotExists([]byte(bucketKeysets)); err != nil {
			return fmt.Errorf("create keysets bucket: %w", err)
		}
		if _, err := tx.CreateBucketIfNotExists([]byte(bucketSessions)); err != nil {
			return fmt.Errorf("create sessions bucket: %w", err)
		}
		if _, err := tx.CreateBucketIfNotExists([]byte(bucketDynamicClients)); err != nil {
			return fmt.Errorf("create dynamic_clients bucket: %w", err)
		}
		if _, err := tx.CreateBucketIfNotExists([]byte(bucketDynamicClientsBySecret)); err != nil {
			return fmt.Errorf("create dynamic_clients_by_secret bucket: %w", err)
		}
		return nil
	}); err != nil {
		db.Close()
		return nil, fmt.Errorf("initialize buckets: %w", err)
	}

	return &State{db: db}, nil
}
