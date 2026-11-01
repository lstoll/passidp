package oauth2as

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	"lds.li/passidp/internal/storage/dbsql"
)

const (
	clientAssertionMaxLifetime = 5 * time.Minute
	clientAssertionMaxJTI      = 256
)

// ErrClientAssertionReplay indicates that an assertion jti was already used.
var ErrClientAssertionReplay = errors.New("oauth2as: client assertion replay")

// useClientAssertion atomically records a private_key_jwt assertion ID for a
// client until expiresAt. It returns [ErrClientAssertionReplay] if the same
// client already used the jti and that record has not expired. Records are kept
// in SQLite so replay protection survives restarts and is shared by replicas.
func (s *Storage) useClientAssertion(ctx context.Context, clientID, jti string, expiresAt time.Time) error {
	if len(clientID) == 0 || len(jti) == 0 || len(jti) > clientAssertionMaxJTI {
		return fmt.Errorf("oauth2as: invalid client assertion identifier")
	}
	now := time.Now()
	if !expiresAt.After(now) {
		return fmt.Errorf("oauth2as: client assertion already expired")
	}
	key := clientAssertionKey(clientID, jti)
	return s.transact(ctx, func(q *dbsql.Queries) error {
		rows, err := q.InsertOAuthClientAssertion(ctx, dbsql.InsertOAuthClientAssertionParams{
			AssertionKey: key[:], ExpiresAt: expiresAt.UnixMicro(),
		})
		if err != nil {
			return err
		}
		if rows == 1 {
			return nil
		}
		// A record whose expiry passed but was not cleaned up yet is reusable.
		rows, err = q.ReuseExpiredOAuthClientAssertion(ctx, dbsql.ReuseExpiredOAuthClientAssertionParams{
			AssertionKey: key[:], ExpiresAt: expiresAt.UnixMicro(), Cutoff: now.UnixMicro(),
		})
		if err != nil {
			return err
		}
		if rows == 0 {
			return ErrClientAssertionReplay
		}
		return nil
	})
}

// clientAssertionKey namespaces the attacker-controlled jti by client and
// stores only a fixed-size digest. The length prefix keeps framing unambiguous.
func clientAssertionKey(clientID, jti string) [sha256.Size]byte {
	framed := make([]byte, 8+len(clientID)+len(jti))
	binary.BigEndian.PutUint64(framed, uint64(len(clientID)))
	copy(framed[8:], clientID)
	copy(framed[8+len(clientID):], jti)
	return sha256.Sum256(framed)
}
