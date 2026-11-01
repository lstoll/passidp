package oauth2as

import (
	"context"
	"database/sql"
	jsonv2 "encoding/json/v2"
	"errors"
	"time"

	"lds.li/passidp/internal/storage/dbsql"
)

// Storage holds SQLite authorization-server state for one issuer.
// Construct it with [NewSQLStorage].
type Storage struct {
	db *sql.DB

	// commitHook is a test seam called after writes and before transaction commit.
	commitHook func() error
}

// NewSQLStorage returns SQLite-backed storage using db. It does not connect to
// the database or apply migrations. Use a database opened by storage.Open.
func NewSQLStorage(db *sql.DB) (*Storage, error) {
	if db == nil {
		return nil, errors.New("oauth2as: SQL database is required")
	}
	return &Storage{db: db}, nil
}

func timeFromMicros(value int64) time.Time { return time.UnixMicro(value).UTC() }

func (s *Storage) getGrant(ctx context.Context, id string) (*storedGrant, error) {
	row, err := dbsql.New(s.db).GetOAuthGrant(ctx, id)
	if err != nil {
		return nil, storageReadError(err)
	}
	return decodeGrant(row)
}

func decodeGrant(row dbsql.Oauth2asGrant) (*storedGrant, error) {
	grant := &storedGrant{
		ID: row.ID, UserID: row.UserID, ClientID: row.ClientID,
		RedirectURI: row.RedirectUri, CodeChallenge: row.CodeChallenge,
		Nonce: row.Nonce, DPoPThumbprint: row.DpopThumbprint,
		GrantedAt: timeFromMicros(row.GrantedAt), AuthenticatedAt: nullableTime(row.AuthenticatedAt),
		ExpiresAt: timeFromMicros(row.ExpiresAt), ACR: row.Acr, storageVersion: uint64(row.Version),
	}
	if row.MaxAge.Valid {
		age := int(row.MaxAge.Int64)
		grant.MaxAge = &age
	}
	if err := jsonv2.Unmarshal([]byte(row.GrantedScopes), &grant.GrantedScopes); err != nil {
		return nil, err
	}
	if err := jsonv2.Unmarshal([]byte(row.Amr), &grant.AMR); err != nil {
		return nil, err
	}
	return grant, nil
}

func storageReadError(err error) error {
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	return err
}

func nullableTime(value sql.NullInt64) time.Time {
	if !value.Valid {
		return time.Time{}
	}
	return timeFromMicros(value.Int64)
}

func nullTime(value time.Time) sql.NullInt64 {
	return sql.NullInt64{Int64: value.UnixMicro(), Valid: !value.IsZero()}
}

func jsonStrings(values []string) (string, error) {
	if values == nil {
		return "[]", nil
	}
	data, err := jsonv2.Marshal(values)
	return string(data), err
}

func insertGrant(ctx context.Context, q *dbsql.Queries, value storedGrant) error {
	scopes, err := jsonStrings(value.GrantedScopes)
	if err != nil {
		return err
	}
	amr, err := jsonStrings(value.AMR)
	if err != nil {
		return err
	}
	var age sql.NullInt64
	if value.MaxAge != nil {
		age = sql.NullInt64{Int64: int64(*value.MaxAge), Valid: true}
	}
	return q.InsertOAuthGrant(ctx, dbsql.InsertOAuthGrantParams{
		ID:              value.ID,
		UserID:          value.UserID,
		ClientID:        value.ClientID,
		GrantedScopes:   scopes,
		RedirectUri:     value.RedirectURI,
		CodeChallenge:   value.CodeChallenge,
		Nonce:           value.Nonce,
		MaxAge:          age,
		GrantedAt:       value.GrantedAt.UnixMicro(),
		AuthenticatedAt: nullTime(value.AuthenticatedAt),
		ExpiresAt:       value.ExpiresAt.UnixMicro(),
		DpopThumbprint:  value.DPoPThumbprint,
		Acr:             value.ACR,
		Amr:             amr,
		Version:         1,
	})
}

func insertAuthCode(ctx context.Context, q *dbsql.Queries, value storedAuthCode) error {
	return q.InsertOAuthAuthCode(ctx, dbsql.InsertOAuthAuthCodeParams{
		ID:          value.ID,
		GrantID:     value.GrantID,
		ValidUntil:  value.ValidUntil.UnixMicro(),
		DeleteAfter: value.StorageExpiresAt.UnixMicro(),
	})
}

func insertRefreshToken(ctx context.Context, q *dbsql.Queries, value storedRefreshToken) error {
	return q.InsertOAuthRefreshToken(ctx, dbsql.InsertOAuthRefreshTokenParams{
		ID:           value.ID,
		GrantID:      value.GrantID,
		ValidUntil:   value.ValidUntil.UnixMicro(),
		DeleteAfter:  value.StorageExpiresAt.UnixMicro(),
		ReplacedByID: value.ReplacedByTokenID,
	})
}

func updateRefreshToken(ctx context.Context, q *dbsql.Queries, value storedRefreshToken) error {
	rows, err := q.UpdateOAuthRefreshToken(ctx, dbsql.UpdateOAuthRefreshTokenParams{
		ID:           value.ID,
		GrantID:      value.GrantID,
		ValidUntil:   value.ValidUntil.UnixMicro(),
		DeleteAfter:  value.StorageExpiresAt.UnixMicro(),
		ReplacedByID: value.ReplacedByTokenID,
	})
	if err != nil {
		return err
	}
	if rows != 1 {
		return errStorageConflict
	}
	return nil
}

func (s *Storage) listRefreshSessions(ctx context.Context, query storageRefreshSessionQuery) ([]storedRefreshSession, error) {
	rows, err := dbsql.New(s.db).ListOAuthRefreshSessions(ctx, dbsql.ListOAuthRefreshSessionsParams{
		UserID: query.UserID, ClientID: query.ClientID, ActiveAt: query.ActiveAt.UnixMicro(),
		AfterGrantID: query.AfterGrantID, AfterLastUsed: query.AfterLastUsed.UnixMicro(), MaxRows: int64(query.Limit),
	})
	if err != nil {
		return nil, err
	}
	result := make([]storedRefreshSession, 0, len(rows))
	for _, row := range rows {
		session := storedRefreshSession{GrantID: row.GrantID, UserID: row.UserID, ClientID: row.ClientID,
			CreatedAt: timeFromMicros(row.GrantedAt), AuthenticatedAt: nullableTime(row.AuthenticatedAt),
			ExpiresAt: timeFromMicros(row.ExpiresAt), LastUsedAt: timeFromMicros(row.LastUsedAt), DPoPBound: row.DpopThumbprint != ""}
		if err := jsonv2.Unmarshal([]byte(row.GrantedScopes), &session.GrantedScopes); err != nil {
			return nil, err
		}
		if session.AuthenticatedAt.IsZero() {
			session.AuthenticatedAt = session.CreatedAt
		}
		result = append(result, session)
	}
	return result, nil
}

func (s *Storage) cleanup(ctx context.Context, options CleanupOptions) (CleanupResult, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return CleanupResult{}, err
	}
	defer tx.Rollback()
	q := dbsql.New(tx)
	cutoff := options.Before.UnixMicro()
	deleted := int64(0)
	remaining := int64(options.Limit)
	cleanups := []func(int64) (int64, error){
		func(limit int64) (int64, error) {
			return q.CleanupOAuthRefreshSessions(ctx, dbsql.CleanupOAuthRefreshSessionsParams{Cutoff: cutoff, MaxRows: limit})
		},
		func(limit int64) (int64, error) {
			return q.CleanupOAuthAuthCodes(ctx, dbsql.CleanupOAuthAuthCodesParams{Cutoff: cutoff, MaxRows: limit})
		},
		func(limit int64) (int64, error) {
			return q.CleanupOAuthRefreshTokens(ctx, dbsql.CleanupOAuthRefreshTokensParams{Cutoff: cutoff, MaxRows: limit})
		},
		func(limit int64) (int64, error) {
			return q.CleanupOAuthGrants(ctx, dbsql.CleanupOAuthGrantsParams{Cutoff: cutoff, MaxRows: limit})
		},
	}
	for _, cleanup := range cleanups {
		if remaining == 0 {
			break
		}
		count, err := cleanup(remaining)
		if err != nil {
			return CleanupResult{}, err
		}
		deleted += count
		remaining -= count
	}
	more, err := q.HasExpiredOAuthRecords(ctx, cutoff)
	if err != nil {
		return CleanupResult{}, err
	}
	if err := tx.Commit(); err != nil {
		return CleanupResult{}, err
	}
	return CleanupResult{Deleted: int(deleted), More: more}, nil
}
