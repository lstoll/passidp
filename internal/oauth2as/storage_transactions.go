package oauth2as

import (
	"context"
	"strings"
	"time"

	"lds.li/passidp/internal/storage/dbsql"
)

// transact retries SQLite contention without repeating policy callbacks or signing.
func (s *Storage) transact(ctx context.Context, fn func(*dbsql.Queries) error) error {
	var err error
	for attempt := range 4 {
		err = s.transactOnce(ctx, fn)
		if err == nil || !retryableSQLError(err) || attempt == 3 {
			return err
		}
		timer := time.NewTimer(time.Duration(1<<attempt) * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
	return err
}

func (s *Storage) transactOnce(ctx context.Context, fn func(*dbsql.Queries) error) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := fn(dbsql.New(tx)); err != nil {
		return err
	}
	if s.commitHook != nil {
		if err := s.commitHook(); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func retryableSQLError(err error) bool {
	message := strings.ToLower(err.Error())
	return strings.Contains(message, "database is locked") || strings.Contains(message, "database table is locked") || strings.Contains(message, "sqlite_busy")
}

func (s *Storage) createGrantWithAuthCode(ctx context.Context, grant *storedGrant, code *storedAuthCode) error {
	return s.transact(ctx, func(q *dbsql.Queries) error {
		if err := insertGrant(ctx, q, *grant); err != nil {
			return err
		}
		return insertAuthCode(ctx, q, *code)
	})
}

// exchangeCode validates the grant snapshot and consumes the code in one commit.
func (s *Storage) exchangeCode(ctx context.Context, loaded *loadedGrant, prepared *preparedTokenResponse) error {
	return s.transact(ctx, func(q *dbsql.Queries) error {
		if err := advanceGrantRevision(ctx, q, loaded.grant); err != nil {
			return err
		}
		rows, err := q.ConsumeOAuthAuthCode(ctx, dbsql.ConsumeOAuthAuthCodeParams{ID: loaded.authCode.ID, GrantID: loaded.grant.ID})
		if err != nil {
			return err
		}
		if rows != 1 {
			return errStorageConflict
		}
		return saveRefreshResponse(ctx, q, prepared)
	})
}

// rotateRefreshToken protects the whole token family with its grant revision.
// The token and grant must have been read together by getRefreshTokenAndGrant.
func (s *Storage) rotateRefreshToken(ctx context.Context, loaded *loadedGrant, prepared *preparedTokenResponse) error {
	return s.transact(ctx, func(q *dbsql.Queries) error {
		if err := advanceGrantRevision(ctx, q, loaded.grant); err != nil {
			return err
		}
		previous := loaded.refreshToken
		if previous.ReplacedByTokenID != "" {
			if err := q.DeleteOAuthRefreshToken(ctx, previous.ReplacedByTokenID); err != nil {
				return err
			}
		}
		if prepared.refreshToken == nil {
			if err := q.DeleteOAuthRefreshToken(ctx, previous.ID); err != nil {
				return err
			}
			return q.DeleteOAuthRefreshSession(ctx, loaded.grant.ID)
		}
		rotated := *previous
		rotated.ReplacedByTokenID = prepared.refreshToken.ID
		if err := updateRefreshToken(ctx, q, rotated); err != nil {
			return err
		}
		return saveRefreshResponse(ctx, q, prepared)
	})
}

func saveRefreshResponse(ctx context.Context, q *dbsql.Queries, prepared *preparedTokenResponse) error {
	if prepared.refreshToken == nil {
		return nil
	}
	if err := insertRefreshToken(ctx, q, *prepared.refreshToken); err != nil {
		return err
	}
	session := prepared.refreshSession
	return q.UpsertOAuthRefreshSession(ctx, dbsql.UpsertOAuthRefreshSessionParams{
		GrantID: session.GrantID, ExpiresAt: session.ExpiresAt.UnixMicro(), LastUsedAt: session.LastUsedAt.UnixMicro(),
	})
}

func (s *Storage) revokeGrant(ctx context.Context, userID, grantID string) (bool, error) {
	rows, err := dbsql.New(s.db).RevokeOAuthGrantForUser(ctx, dbsql.RevokeOAuthGrantForUserParams{ID: grantID, UserID: userID})
	return rows == 1, err
}

func advanceGrantRevision(ctx context.Context, q *dbsql.Queries, grant *storedGrant) error {
	rows, err := q.AdvanceOAuthGrantRevision(ctx, dbsql.AdvanceOAuthGrantRevisionParams{
		ID: grant.ID, Version: int64(grant.storageVersion), DpopThumbprint: grant.DPoPThumbprint,
	})
	if err != nil {
		return err
	}
	if rows != 1 {
		return errStorageConflict
	}
	return nil
}
