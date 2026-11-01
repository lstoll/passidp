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
	db *sql.DB
}

var _ dpop.ReplayStore = (*DPoPReplayStore)(nil)

// NewDPoPReplayStore returns a SQL-backed DPoP replay store.
func NewDPoPReplayStore(sqlDB *sql.DB) *DPoPReplayStore {
	return &DPoPReplayStore{db: sqlDB}
}

// CheckAndRecord atomically records a verified DPoP proof until its acceptance
// deadline. It returns [dpop.ErrProofReplay] when the same thumbprint and jti
// are still recorded.
func (s *DPoPReplayStore) CheckAndRecord(ctx context.Context, thumbprint, jti string, until time.Time) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	// Keep the insert and expired-record replacement atomic with respect to GC.
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("record dpop proof: %w", err)
	}
	defer tx.Rollback()
	queries := dbsql.New(tx)
	key := dpopReplayKey(thumbprint, jti)
	now := time.Now()
	rows, err := queries.InsertDPoPProof(ctx, dbsql.InsertDPoPProofParams{
		ProofKey: key[:], Until: until,
	})
	if err != nil {
		return fmt.Errorf("record dpop proof: %w", err)
	}
	if rows == 0 {
		rows, err = queries.RefreshExpiredDPoPProof(ctx, dbsql.RefreshExpiredDPoPProofParams{
			Until: until, ProofKey: key[:], Cutoff: now,
		})
		if err != nil {
			return fmt.Errorf("record dpop proof: %w", err)
		}
		if rows == 0 {
			return dpop.ErrProofReplay
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("record dpop proof: %w", err)
	}
	return nil
}

func (s *DPoPReplayStore) GarbageCollectExpiredProofs() (int, error) {
	deleted, err := dbsql.New(s.db).GarbageCollectDPoPProofs(context.Background(), time.Now())
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
