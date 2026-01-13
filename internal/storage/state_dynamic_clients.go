package storage

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"

	bolt "go.etcd.io/bbolt"
)

const (
	// Bucket names for dynamic client storage
	bucketDynamicClients = "dynamic_clients"
)

var (
	// ErrDynamicClientNotFound is returned when a dynamic client is not found
	ErrDynamicClientNotFound = errors.New("dynamic client not found")
)

// DynamicClient represents a dynamic OIDC client
type DynamicClient struct {
	ID               string    `json:"id"`
	ClientSecret     string    `json:"client_secret"`
	RegistrationBlob string    `json:"registration_blob"`
	CreatedAt        time.Time `json:"created_at"`
	ExpiresAt        time.Time `json:"expires_at"`
	Active           bool      `json:"active"`
}

// DynamicClientStore implements dynamic client storage using BoltDB
type DynamicClientStore struct {
	dbAccessor *dbAccessor
}

// GetDynamicClient retrieves an active, non-expired dynamic client by ID
func (s *DynamicClientStore) GetDynamicClient(ctx context.Context, id string) (*DynamicClient, error) {
	db, release := s.dbAccessor.db()
	defer release()

	var client *DynamicClient

	err := db.View(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte(bucketDynamicClients))
		if bucket == nil {
			return ErrDynamicClientNotFound
		}

		data := bucket.Get([]byte(id))
		if data == nil {
			return ErrDynamicClientNotFound
		}

		var stored DynamicClient
		if err := json.Unmarshal(data, &stored); err != nil {
			return fmt.Errorf("unmarshal dynamic client: %w", err)
		}

		// Check if client is active and not expired
		if !stored.Active || time.Now().After(stored.ExpiresAt) {
			return ErrDynamicClientNotFound
		}

		client = &stored
		return nil
	})

	if err != nil {
		return nil, err
	}

	return client, nil
}

// CreateDynamicClient creates a new dynamic client
func (s *DynamicClientStore) CreateDynamicClient(ctx context.Context, id, clientSecret, registrationBlob string, expiresAt time.Time) error {
	db, release := s.dbAccessor.db()
	defer release()

	return db.Update(func(tx *bolt.Tx) error {
		clientsBucket := tx.Bucket([]byte(bucketDynamicClients))
		if clientsBucket == nil {
			return fmt.Errorf("dynamic_clients bucket does not exist")
		}

		// Check if client already exists
		if clientsBucket.Get([]byte(id)) != nil {
			return fmt.Errorf("client %s already exists", id)
		}

		client := DynamicClient{
			ID:               id,
			ClientSecret:     clientSecret,
			RegistrationBlob: registrationBlob,
			CreatedAt:        time.Now(),
			ExpiresAt:        expiresAt,
			Active:           true,
		}

		data, err := json.Marshal(client)
		if err != nil {
			return fmt.Errorf("marshal dynamic client: %w", err)
		}

		// Store client by ID
		if err := clientsBucket.Put([]byte(id), data); err != nil {
			return fmt.Errorf("store dynamic client: %w", err)
		}

		return nil
	})
}

// DeactivateDynamicClient deactivates a dynamic client
func (s *DynamicClientStore) DeactivateDynamicClient(ctx context.Context, id string) error {
	db, release := s.dbAccessor.db()
	defer release()

	return db.Update(func(tx *bolt.Tx) error {
		clientsBucket := tx.Bucket([]byte(bucketDynamicClients))
		if clientsBucket == nil {
			return ErrDynamicClientNotFound
		}

		data := clientsBucket.Get([]byte(id))
		if data == nil {
			return ErrDynamicClientNotFound
		}

		var client DynamicClient
		if err := json.Unmarshal(data, &client); err != nil {
			return fmt.Errorf("unmarshal dynamic client: %w", err)
		}

		client.Active = false

		updatedData, err := json.Marshal(client)
		if err != nil {
			return fmt.Errorf("marshal dynamic client: %w", err)
		}

		if err := clientsBucket.Put([]byte(id), updatedData); err != nil {
			return fmt.Errorf("update dynamic client: %w", err)
		}

		return nil
	})
}

// ListActiveDynamicClients returns all active, non-expired dynamic clients
// sorted by creation date (most recent first)
func (s *DynamicClientStore) ListActiveDynamicClients(ctx context.Context) ([]*DynamicClient, error) {
	db, release := s.dbAccessor.db()
	defer release()

	var clients []*DynamicClient

	err := db.View(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte(bucketDynamicClients))
		if bucket == nil {
			return nil // No bucket means no clients
		}

		now := time.Now()

		err := bucket.ForEach(func(k, v []byte) error {
			var client DynamicClient
			if err := json.Unmarshal(v, &client); err != nil {
				return nil // Skip corrupted entries
			}

			// Only include active, non-expired clients
			if client.Active && now.Before(client.ExpiresAt) {
				clients = append(clients, &client)
			}

			return nil
		})

		if err != nil {
			return fmt.Errorf("iterating dynamic clients: %w", err)
		}

		// Sort by CreatedAt DESC (most recent first)
		sort.Slice(clients, func(i, j int) bool {
			return clients[i].CreatedAt.After(clients[j].CreatedAt)
		})

		return nil
	})

	if err != nil {
		return nil, err
	}

	return clients, nil
}

// CleanupExpiredDynamicClients removes expired or inactive dynamic clients.
// Returns the number of clients deleted.
func (s *DynamicClientStore) CleanupExpiredDynamicClients() (int, error) {
	db, release := s.dbAccessor.db()
	defer release()

	var deletedCount int

	err := db.Update(func(tx *bolt.Tx) error {
		clientsBucket := tx.Bucket([]byte(bucketDynamicClients))
		if clientsBucket == nil {
			return nil // No bucket means nothing to clean
		}

		now := time.Now()
		var toDelete [][]byte

		// Collect expired or inactive clients
		err := clientsBucket.ForEach(func(k, v []byte) error {
			var client DynamicClient
			if err := json.Unmarshal(v, &client); err != nil {
				// If we can't unmarshal, consider it corrupted and delete it
				toDelete = append(toDelete, k)
				return nil
			}

			if !client.Active || now.After(client.ExpiresAt) {
				toDelete = append(toDelete, k)
			}

			return nil
		})

		if err != nil {
			return fmt.Errorf("iterating dynamic clients: %w", err)
		}

		// Delete expired/inactive clients
		for _, key := range toDelete {
			if err := clientsBucket.Delete(key); err != nil {
				return fmt.Errorf("deleting expired/inactive client: %w", err)
			}
			deletedCount++
		}

		return nil
	})

	if err != nil {
		return 0, err
	}

	return deletedCount, nil
}
