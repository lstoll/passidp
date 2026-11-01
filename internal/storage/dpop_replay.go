package storage

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"fmt"
	"time"

	"lds.li/oauth2ext/dpop"
	"lds.li/passidp/internal/storage/dbsql"
)

// DPoPReplayStore records accepted DPoP proofs in SQLite so replay checks
// survive process restarts and work across replicas sharing the database.
type DPoPReplayStore struct {
	queries *dbsql.Queries
}

var _ dpop.ReplayStore = (*DPoPReplayStore)(nil)

// NewDPoPReplayStore returns a SQL-backed DPoP replay store.
func NewDPoPReplayStore(sqlDB *sql.DB) *DPoPReplayStore {
	return &DPoPReplayStore{queries: dbsql.New(sqlDB)}
}

// CheckAndRecord atomically records a verified DPoP proof until its acceptance
// deadline. It returns [dpop.ErrProofReplay] when the same thumbprint and jti
// are still recorded.
func (s *DPoPReplayStore) CheckAndRecord(ctx context.Context, thumbprint, jti string, until time.Time) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	key := dpopReplayKey(thumbprint, jti)
	now := time.Now()
	rows, err := s.queries.InsertDPoPProof(ctx, dbsql.InsertDPoPProofParams{
		ProofKey: key[:], Until: until,
	})
	if err != nil {
		return fmt.Errorf("record dpop proof: %w", err)
	}
	if rows == 0 {
		rows, err = s.queries.RefreshExpiredDPoPProof(ctx, dbsql.RefreshExpiredDPoPProofParams{
			Until: until, ProofKey: key[:], Cutoff: now,
		})
		if err != nil {
			return fmt.Errorf("record dpop proof: %w", err)
		}
		if rows == 0 {
			return dpop.ErrProofReplay
		}
	}
	return nil
}

func (s *DPoPReplayStore) GarbageCollectExpiredProofs() (int, error) {
	deleted, err := s.queries.GarbageCollectDPoPProofs(context.Background(), time.Now())
	if err != nil {
		return 0, fmt.Errorf("delete expired dpop proofs: %w", err)
	}
	return int(deleted), nil
}

func dpopReplayKey(thumbprint, jti string) [sha256.Size]byte {
	// Match oauth2ext's in-memory store: jti is attacker controlled, so keep
	// only a fixed-size digest. A JWK thumbprint is base64url and cannot
	// contain NUL, so this framing is unambiguous.
	return sha256.Sum256([]byte(thumbprint + "\x00" + jti))
}
