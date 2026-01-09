package storage

import (
	"fmt"
	"log/slog"
	"os"
	"sync"
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

const dbMode = 0o600

// dbAccessor wraps the state and is what we pass to the sub-stores, to ensure
// that locking is handled correctly.
type dbAccessor struct {
	st *State
}

func (d *dbAccessor) db() (_ *bolt.DB, release func()) {
	d.st.dbMu.RLock()
	return d.st.db, func() {
		d.st.dbMu.RUnlock()
	}
}

// State represents the on-disk runtime state for the IDP.
type State struct {
	db   *bolt.DB
	dbMu sync.RWMutex

	pendingEnrollments *PendingEnrollments
	sessionKV          *SessionKV
	oauth2State        *OAuth2State
	dynamicClientStore *DynamicClientStore
	keysetStore        *KeysetStore
}

func NewState(path string) (*State, error) {
	db, err := bolt.Open(path, dbMode, nil)
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
		db: db,
	}

	s.pendingEnrollments = &PendingEnrollments{dbAccessor: &dbAccessor{st: s}}
	s.sessionKV = &SessionKV{dbAccessor: &dbAccessor{st: s}}
	s.oauth2State = &OAuth2State{dbAccessor: &dbAccessor{st: s}}
	s.dynamicClientStore = &DynamicClientStore{dbAccessor: &dbAccessor{st: s}}
	s.keysetStore = &KeysetStore{dbAccessor: &dbAccessor{st: s}}

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

// DynamicClientStore returns a DynamicClientStore instance for managing dynamic clients
func (s *State) DynamicClientStore() *DynamicClientStore {
	return s.dynamicClientStore
}

// KeysetStore returns a KeysetStore instance for managing keysets
func (s *State) KeysetStore() *KeysetStore {
	return s.keysetStore
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

	if deleted, err := s.dynamicClientStore.CleanupExpiredDynamicClients(); err != nil {
		log.Error("garbage collect dynamic clients", slog.String("error", err.Error()))
	} else if deleted > 0 {
		log.Info("garbage collected dynamic clients", slog.Int("deleted", deleted))
	}

	log.Info("finished garbage collection")
}

func (s *State) Compactor(interval time.Duration) (execute func() error, interrupt func(error)) {
	log := slog.With("component", "compactor")

	stopCh := make(chan struct{})

	return func() error {
			ticker := time.NewTicker(interval)
			defer ticker.Stop()

			for {
				select {
				case <-ticker.C:
					log.Info("starting compaction run")
					if err := s.runCompactor(log); err != nil {
						log.Error("compaction failed", slog.String("error", err.Error()))
					}
				case <-stopCh:
					return nil
				}
			}

		}, func(error) {
			close(stopCh)
		}
}

func (s *State) runCompactor(log *slog.Logger) error {
	start := time.Now()
	s.dbMu.Lock()
	defer s.dbMu.Unlock()
	log.Info("lock acquired, compacting", "lock_acquisition_time", time.Since(start))

	path := s.db.Path()
	compactPath := path + ".compact"

	// Get original file size before compaction.
	sizeBefore, err := getFileSize(path)
	if err != nil {
		return fmt.Errorf("failed to get DB file size: %w", err)
	}

	log.Info("compacting BoltDB", "input", path, "output", compactPath)

	newDB, err := bolt.Open(compactPath, dbMode, nil)
	if err != nil {
		return fmt.Errorf("failed to open new DB at %s: %w", compactPath, err)
	}

	if err := bolt.Compact(newDB, s.db, 10000); err != nil {
		newDB.Close()
		os.Remove(compactPath)
		return fmt.Errorf("failed to compact DB: %w", err)
	}

	if err := newDB.Close(); err != nil {
		os.Remove(compactPath)
		return fmt.Errorf("failed to close new DB: %w", err)
	}

	sizeAfter, err := getFileSize(compactPath)
	if err != nil {
		os.Remove(compactPath)
		return fmt.Errorf("failed to get compacted DB file size: %w", err)
	}

	if err := s.db.Close(); err != nil {
		os.Remove(compactPath)
		return fmt.Errorf("failed to close existing DB: %w", err)
	}

	if err := os.Rename(compactPath, path); err != nil {
		return fmt.Errorf("failed to replace DB with compacted version: %w", err)
	}

	db, err := bolt.Open(path, dbMode, nil)
	if err != nil {
		return fmt.Errorf("failed to open compacted DB: %w", err)
	}

	s.db = db
	log.Info("compaction complete", "path", path, "size_before", formatBytes(sizeBefore), "size_after", formatBytes(sizeAfter))
	return nil
}

// getFileSize returns the size in bytes of the file at the given path.
func getFileSize(path string) (int64, error) {
	info, err := os.Stat(path)
	if err != nil {
		return 0, err
	}
	return info.Size(), nil
}

// formatBytes formats a byte count into a human-readable string using binary
// units (KiB, MiB, GiB, etc.).
func formatBytes(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	units := []string{"KiB", "MiB", "GiB", "TiB", "PiB", "EiB"}
	if exp >= len(units) {
		return fmt.Sprintf("%d B", bytes)
	}
	return fmt.Sprintf("%.2f %s", float64(bytes)/float64(div), units[exp])
}
