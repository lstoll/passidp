package storage

import (
	"fmt"
	"log/slog"
	"time"

	bolt "go.etcd.io/bbolt"
)

// expectedBuckets is the set of bucket names that should exist in the database
var expectedBuckets = map[string]bool{
	bucketGrants:                 true,
	bucketAuthCodes:              true,
	bucketRefreshTokens:          true,
	bucketKeysets:                true,
	bucketSessions:               true,
	bucketDynamicClients:         true,
	bucketDynamicClientsBySecret: true,
	bucketPendingEnrollments:     true,
}

// State represents the on-disk runtime state for the IDP.
type State struct {
	db *bolt.DB

	pendingEnrollments *PendingEnrollments
	sessionKV          *SessionKV
	oauth2State        *OAuth2State
}

func NewState(path string) (*State, error) {
	db, err := bolt.Open(path, 0o600, nil)
	if err != nil {
		return nil, fmt.Errorf("open bolt db: %w", err)
	}

	// Initialize buckets and clean up unexpected ones
	var deletedBuckets []string
	if err := db.Update(func(tx *bolt.Tx) error {
		for bucketName := range expectedBuckets {
			if _, err := tx.CreateBucketIfNotExists([]byte(bucketName)); err != nil {
				return fmt.Errorf("create bucket %s: %w", bucketName, err)
			}
		}

		var bucketsToDelete [][]byte
		if err := tx.ForEach(func(name []byte, b *bolt.Bucket) error {
			if !expectedBuckets[string(name)] {
				bucketsToDelete = append(bucketsToDelete, name)
			}
			return nil
		}); err != nil {
			return fmt.Errorf("iterate buckets: %w", err)
		}

		for _, name := range bucketsToDelete {
			bucketName := string(name)
			if err := tx.DeleteBucket(name); err != nil {
				return fmt.Errorf("delete unexpected bucket %s: %w", bucketName, err)
			}
			deletedBuckets = append(deletedBuckets, bucketName)
		}

		return nil
	}); err != nil {
		db.Close()
		return nil, fmt.Errorf("initialize buckets: %w", err)
	}

	if len(deletedBuckets) > 0 {
		log := slog.With("component", "storage")
		log.Info("deleted unexpected buckets", slog.Any("buckets", deletedBuckets))
	}

	s := &State{
		db:                 db,
		pendingEnrollments: &PendingEnrollments{db: db},
		sessionKV:          &SessionKV{db: db},
		oauth2State:        &OAuth2State{db: db},
	}

	return s, nil
}

// Close closes the BoltDB database
func (s *State) Close() error {
	return s.db.Close()
}

// PendingEnrollments returns a PendingEnrollments instance for managing pending enrollments
func (s *State) PendingEnrollments() *PendingEnrollments {
	return s.pendingEnrollments
}

func (s *State) SessionKV() *SessionKV {
	return s.sessionKV
}

// OAuth2State returns an OAuth2State instance for managing OAuth2 grants
func (s *State) OAuth2State() *OAuth2State {
	return s.oauth2State
}

func (s *State) GarbageCollector(interval time.Duration) (execute func() error, interrupt func(error)) {
	stopCh := make(chan struct{})

	return func() error {
			ticker := time.NewTicker(interval)
			defer ticker.Stop()

			// do an initial run.
			s.runGC()

			for {
				select {
				case <-ticker.C:
					s.runGC()
				case <-stopCh:
					return nil
				}
			}
		},
		func(error) {
			close(stopCh)
		}
}

func (s *State) runGC() {
	log := slog.With("component", "garbage_collector")

	log.Info("starting")

	if deleted, err := s.pendingEnrollments.GarbageCollectPendingEnrollments(); err != nil {
		log.Error("garbage collect pending enrollments", slog.String("error", err.Error()))
	} else if deleted > 0 {
		log.Info("garbage collected pending enrollments", slog.Int("deleted", deleted))
	}

	authCodesDeleted, refreshTokensDeleted, grantsDeleted, err := s.oauth2State.GarbageCollect()
	if err != nil {
		log.Error("garbage collect oauth2 state", slog.String("error", err.Error()))
	} else if authCodesDeleted > 0 || refreshTokensDeleted > 0 || grantsDeleted > 0 {
		log.Info("garbage collected oauth2 state",
			slog.Int("auth_codes_deleted", authCodesDeleted),
			slog.Int("refresh_tokens_deleted", refreshTokensDeleted),
			slog.Int("grants_deleted", grantsDeleted))
	}

	if deleted, err := s.sessionKV.GC(); err != nil {
		log.Error("garbage collect sessions", slog.String("error", err.Error()))
	} else if deleted > 0 {
		log.Info("garbage collected sessions", slog.Int("deleted", deleted))
	}

	log.Info("finished garbage collection")
}
