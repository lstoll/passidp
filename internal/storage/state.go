package storage

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	bolt "go.etcd.io/bbolt"
)

// expectedBuckets is the set of bucket names that should exist in the database
var expectedBuckets = map[string]bool{
	bucketGrants:             true,
	bucketAuthCodes:          true,
	bucketRefreshTokens:      true,
	bucketKeysets:            true,
	bucketSessions:           true,
	bucketDynamicClients:     true,
	bucketPendingEnrollments: true,
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

	// Report initial file size metric
	reportStateFileSize(path)

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

// ListBuckets returns a list of all bucket names in the database.
func (s *State) ListBuckets() ([]string, error) {
	s.dbMu.RLock()
	defer s.dbMu.RUnlock()

	var buckets []string
	err := s.db.View(func(tx *bolt.Tx) error {
		return tx.ForEach(func(name []byte, b *bolt.Bucket) error {
			buckets = append(buckets, string(name))
			return nil
		})
	})
	return buckets, err
}

// DeleteBucketContents deletes all contents from a bucket.
func (s *State) DeleteBucketContents(bucketName string) error {
	s.dbMu.Lock()
	defer s.dbMu.Unlock()

	return s.db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte(bucketName))
		if bucket == nil {
			return fmt.Errorf("bucket %s does not exist", bucketName)
		}

		// Delete all keys in the bucket
		return bucket.ForEach(func(k, v []byte) error {
			// Skip sub-buckets (they have nil values)
			if v == nil {
				return nil
			}
			return bucket.Delete(k)
		})
	})
}

// BucketEntry represents a single key-value pair in a bucket.
type BucketEntry struct {
	Key      string          `json:"key"`
	KeyParts []string        `json:"key_parts,omitempty"` // Decoded parts if key is composite
	Value    json.RawMessage `json:"value"`
	Format   string          `json:"format"` // "json" or "raw"
}

// ListBucketContents lists all entries in a bucket, streaming them via the provided callback.
// The callback is called for each entry. If it returns an error, iteration stops.
func (s *State) ListBucketContents(bucketName string, fn func(BucketEntry) error) error {
	s.dbMu.RLock()
	defer s.dbMu.RUnlock()

	return s.db.View(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte(bucketName))
		if bucket == nil {
			return fmt.Errorf("bucket %s does not exist", bucketName)
		}

		return bucket.ForEach(func(k, v []byte) error {
			// Skip sub-buckets (they have nil values)
			if v == nil {
				return nil
			}

			entry := BucketEntry{}

			// Detect if key is composite (contains null bytes)
			if parts := decodeCompositeKey(k); len(parts) > 1 {
				// Composite key - use decoded parts
				entry.KeyParts = parts
				// Create a readable representation
				entry.Key = formatCompositeKey(parts)
			} else {
				// Single-part key - detect if it's a UUID
				uuidStr := detectUUID(k)
				if uuidStr != "" {
					// If it's a UUID, use the UUID string as the key
					entry.Key = uuidStr
				} else {
					// Not a UUID, use the raw key
					entry.Key = string(k)
				}
			}

			// Try to detect format and decode appropriately
			if isJSON(v) {
				entry.Format = "json"
				// Pretty-print JSON
				var jsonValue interface{}
				if err := json.Unmarshal(v, &jsonValue); err == nil {
					prettyJSON, err := json.MarshalIndent(jsonValue, "", "  ")
					if err == nil {
						entry.Value = prettyJSON
					} else {
						entry.Value = v
					}
				} else {
					entry.Value = v
				}
			} else {
				entry.Format = "raw"
				// For raw data, output as hex
				entry.Value = []byte(fmt.Sprintf(`{"format":"raw","hex":"%x","size":%d}`, v, len(v)))
			}

			return fn(entry)
		})
	})
}

// isJSON checks if data appears to be valid JSON.
func isJSON(data []byte) bool {
	var v interface{}
	return json.Unmarshal(data, &v) == nil
}


// detectUUID checks if the key is a UUID in either string or binary format.
// Returns the UUID string representation if detected, empty string otherwise.
func detectUUID(key []byte) string {
	// Check if it's a UUID in binary format (16 bytes)
	if len(key) == 16 {
		// Try to parse as UUID bytes
		if uuidVal, err := uuid.FromBytes(key); err == nil {
			return uuidVal.String()
		}
	}

	// Check if it's a UUID string
	keyStr := string(key)
	if err := uuid.Validate(keyStr); err == nil {
		// Validate succeeded, parse to normalize format
		if uuidVal, err := uuid.Parse(keyStr); err == nil {
			return uuidVal.String()
		}
	}

	return ""
}

// decodeCompositeKey detects and decodes composite keys that use null bytes (0x00) as separators.
// Returns a slice of decoded parts, or a single-element slice if not composite.
func decodeCompositeKey(key []byte) []string {
	// Check if key contains null bytes
	hasNull := false
	for _, b := range key {
		if b == 0 {
			hasNull = true
			break
		}
	}

	if !hasNull {
		// Not composite, return as single part
		uuidStr := detectUUID(key)
		if uuidStr != "" {
			return []string{uuidStr}
		}
		return []string{string(key)}
	}

	// Split on null bytes
	var parts []string
	currentPart := []byte{}

	for _, b := range key {
		if b == 0 {
			// End of current part
			if len(currentPart) > 0 {
				decoded := decodeKeyPart(currentPart)
				parts = append(parts, decoded)
				currentPart = []byte{}
			}
		} else {
			currentPart = append(currentPart, b)
		}
	}

	// Add final part if any
	if len(currentPart) > 0 {
		decoded := decodeKeyPart(currentPart)
		parts = append(parts, decoded)
	}

	return parts
}

// decodeKeyPart attempts to decode a single key part, trying UUID first, then string.
func decodeKeyPart(part []byte) string {
	// Try UUID detection first
	if uuidStr := detectUUID(part); uuidStr != "" {
		return uuidStr
	}
	// Fall back to string representation
	return string(part)
}

// formatCompositeKey formats composite key parts into a readable string.
func formatCompositeKey(parts []string) string {
	// Join parts with " / " separator for readability
	return fmt.Sprintf("%s", strings.Join(parts, " / "))
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

	// Update file size metric after compaction
	reportStateFileSize(path)

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
