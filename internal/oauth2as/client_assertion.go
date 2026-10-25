package oauth2as

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
	"time"
)

const (
	clientAssertionMaxLifetime = 5 * time.Minute
	clientAssertionReplayLimit = 10000
	clientAssertionMaxJTI      = 256
)

var (
	// ErrClientAssertionReplay indicates that an assertion jti was already used.
	ErrClientAssertionReplay = errors.New("oauth2as: client assertion replay")
	// ErrClientAssertionReplayStore indicates that replay protection could not
	// safely record a new assertion.
	ErrClientAssertionReplayStore = errors.New("oauth2as: client assertion replay store unavailable")
)

// ClientAssertionReplayStore atomically records a client assertion ID in a
// client-specific namespace until its expiration. Implementations must reject
// a previously recorded clientID/jti pair.
// Configure a shared implementation when a server is deployed on multiple
// replicas.
type ClientAssertionReplayStore interface {
	Use(ctx context.Context, clientID, jti string, expiresAt time.Time) error
}

type memoryClientAssertionReplayStore struct {
	mu   sync.Mutex
	seen map[[sha256.Size]byte]time.Time
}

func newMemoryClientAssertionReplayStore() *memoryClientAssertionReplayStore {
	return &memoryClientAssertionReplayStore{seen: make(map[[sha256.Size]byte]time.Time)}
}

func (s *memoryClientAssertionReplayStore) Use(ctx context.Context, clientID, jti string, expiresAt time.Time) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("%w: %v", ErrClientAssertionReplayStore, err)
	}
	if len(clientID) == 0 || len(jti) == 0 || len(jti) > clientAssertionMaxJTI || !expiresAt.After(time.Now()) {
		return fmt.Errorf("%w: invalid assertion", ErrClientAssertionReplayStore)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	for id, until := range s.seen {
		if now.After(until) {
			delete(s.seen, id)
		}
	}
	framed := make([]byte, 8+len(clientID)+len(jti))
	binary.BigEndian.PutUint64(framed, uint64(len(clientID)))
	copy(framed[8:], clientID)
	copy(framed[8+len(clientID):], jti)
	key := sha256.Sum256(framed)
	if _, ok := s.seen[key]; ok {
		return ErrClientAssertionReplay
	}
	if len(s.seen) >= clientAssertionReplayLimit {
		return ErrClientAssertionReplayStore
	}
	s.seen[key] = expiresAt
	return nil
}
