package oauth2as

import (
	"context"
	"database/sql"
	jsonv2 "encoding/json/v2"
	"errors"
	"fmt"
	"strings"
	"time"

	"lds.li/passidp/internal/storage/dbsql"
)

// OAuth tables share a database with other PassIDP state.
const (
	tblGrants          = "oauth2as_grants"
	tblAuthCodes       = "oauth2as_authorization_codes"
	tblRefreshTokens   = "oauth2as_refresh_tokens"
	tblRefreshSessions = "oauth2as_refresh_sessions"
)

// Storage holds SQLite authorization-server state for one issuer.
// Construct it with [NewSQLStorage].
type Storage struct {
	db *sql.DB

	// commitHook, if set, is called before each Commit and aborts it with the
	// returned error. It is a test seam for fault injection.
	commitHook func(storageCommit) error
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

func (s *Storage) getAuthCode(ctx context.Context, id string) (*storedAuthCode, error) {
	row, err := dbsql.New(s.db).GetOAuthAuthCode(ctx, id)
	if err != nil {
		return nil, storageReadError(err)
	}
	return &storedAuthCode{ID: row.ID, GrantID: row.GrantID,
		ValidUntil: timeFromMicros(row.ValidUntil), StorageExpiresAt: timeFromMicros(row.DeleteAfter),
		storageVersion: uint64(row.Version)}, nil
}

func (s *Storage) getRefreshToken(ctx context.Context, id string) (*storedRefreshToken, error) {
	row, err := dbsql.New(s.db).GetOAuthRefreshToken(ctx, id)
	if err != nil {
		return nil, storageReadError(err)
	}
	return &storedRefreshToken{ID: row.ID, GrantID: row.GrantID,
		ValidUntil: timeFromMicros(row.ValidUntil), StorageExpiresAt: timeFromMicros(row.DeleteAfter),
		ReplacedByTokenID: row.ReplacedByID, storageVersion: uint64(row.Version)}, nil
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

func (s *Storage) commit(ctx context.Context, commit storageCommit) error {
	if err := validateStorageCommit(commit); err != nil {
		return err
	}
	if s.commitHook != nil {
		if err := s.commitHook(commit); err != nil {
			return err
		}
	}
	var err error
	for attempt := range 4 {
		err = s.commitOnce(ctx, commit)
		if err == nil || !retryableSQLError(err) {
			return err
		}
		if attempt == 3 {
			break
		}
		delay := time.Duration(1<<attempt) * time.Millisecond
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
	return err
}

func (s *Storage) commitOnce(ctx context.Context, commit storageCommit) error {
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return err
	}
	defer tx.Rollback()

	versions := make(map[storageRef]uint64, len(commit.Checks)+len(commit.Grants)+len(commit.AuthCodes)+len(commit.RefreshTokens)+len(commit.Sessions))
	for _, check := range commit.Checks {
		version, exists, err := s.version(ctx, tx, check.ref())
		if err != nil {
			return err
		}
		if check.Version == 0 {
			if exists {
				return errStorageConflict
			}
		} else if !exists || version != check.Version {
			return errStorageConflict
		}
		versions[check.ref()] = version
	}

	for i := range commit.Grants {
		ref := storageRef{Kind: storageKindGrant, ID: commit.Grants[i].ID}
		version, err := s.putVersion(ctx, tx, versions, ref)
		if err != nil {
			return err
		}
		if err := s.putGrant(ctx, tx, commit.Grants[i], version, version > 1); err != nil {
			if hasCreateCheck(commit.Checks, ref) && uniqueViolation(err) {
				return errStorageConflict
			}
			return fmt.Errorf("put grant %s: %w", commit.Grants[i].ID, err)
		}
	}
	for i := range commit.AuthCodes {
		ref := storageRef{Kind: storageKindAuthCode, ID: commit.AuthCodes[i].ID}
		version, err := s.putVersion(ctx, tx, versions, ref)
		if err != nil {
			return err
		}
		if err := s.putAuthCode(ctx, tx, commit.AuthCodes[i], version, version > 1); err != nil {
			if hasCreateCheck(commit.Checks, ref) && uniqueViolation(err) {
				return errStorageConflict
			}
			return fmt.Errorf("put auth code %s: %w", commit.AuthCodes[i].ID, err)
		}
	}
	for i := range commit.RefreshTokens {
		ref := storageRef{Kind: storageKindRefreshToken, ID: commit.RefreshTokens[i].ID}
		version, err := s.putVersion(ctx, tx, versions, ref)
		if err != nil {
			return err
		}
		if err := s.putRefreshToken(ctx, tx, commit.RefreshTokens[i], version, version > 1); err != nil {
			if hasCreateCheck(commit.Checks, ref) && uniqueViolation(err) {
				return errStorageConflict
			}
			return fmt.Errorf("put refresh token %s: %w", commit.RefreshTokens[i].ID, err)
		}
	}
	for i := range commit.Sessions {
		ref := storageRef{Kind: storageKindSession, ID: commit.Sessions[i].GrantID}
		version, err := s.putVersion(ctx, tx, versions, ref)
		if err != nil {
			return err
		}
		if err := s.putSession(ctx, tx, commit.Sessions[i], version, version > 1); err != nil {
			if hasCreateCheck(commit.Checks, ref) && uniqueViolation(err) {
				return errStorageConflict
			}
			return fmt.Errorf("put refresh session %s: %w", commit.Sessions[i].GrantID, err)
		}
	}
	for _, ref := range commit.Deletes {
		if err := s.deleteRef(ctx, tx, ref); err != nil {
			return fmt.Errorf("delete %s %s: %w", ref.Kind, ref.ID, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	return nil
}

func uniqueViolation(err error) bool {
	return strings.Contains(strings.ToLower(err.Error()), "unique constraint failed")
}

func retryableSQLError(err error) bool {
	message := strings.ToLower(err.Error())
	return strings.Contains(message, "database is locked") ||
		strings.Contains(message, "database table is locked") ||
		strings.Contains(message, "sqlite_busy")
}

func (s *Storage) putVersion(ctx context.Context, tx *sql.Tx, versions map[storageRef]uint64, ref storageRef) (uint64, error) {
	if version, ok := versions[ref]; ok {
		return version + 1, nil
	}
	version, exists, err := s.version(ctx, tx, ref)
	if err != nil {
		return 0, err
	}
	if !exists {
		version = 0
	}
	return version + 1, nil
}

func (s *Storage) version(ctx context.Context, tx *sql.Tx, ref storageRef) (uint64, bool, error) {
	q := dbsql.New(tx)
	var version int64
	var err error
	switch ref.Kind {
	case storageKindGrant:
		version, err = q.GetOAuthGrantVersion(ctx, ref.ID)
	case storageKindAuthCode:
		version, err = q.GetOAuthAuthCodeVersion(ctx, ref.ID)
	case storageKindRefreshToken:
		version, err = q.GetOAuthRefreshTokenVersion(ctx, ref.ID)
	case storageKindSession:
		version, err = q.GetOAuthRefreshSessionVersion(ctx, ref.ID)
	default:
		return 0, false, fmt.Errorf("oauth2as: unsupported storage kind %q", ref.Kind)
	}
	if errors.Is(err, sql.ErrNoRows) {
		return 0, false, nil
	}
	return uint64(version), err == nil, err
}

func (s *Storage) putGrant(ctx context.Context, tx *sql.Tx, value storedGrant, version uint64, exists bool) error {
	q := dbsql.New(tx)
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
	if exists {
		return q.UpdateOAuthGrant(ctx, dbsql.UpdateOAuthGrantParams{
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
			Version:         int64(version),
		})
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
		Version:         int64(version),
	})
}

func (s *Storage) putAuthCode(ctx context.Context, tx *sql.Tx, value storedAuthCode, version uint64, exists bool) error {
	q := dbsql.New(tx)
	if exists {
		return q.UpdateOAuthAuthCode(ctx, dbsql.UpdateOAuthAuthCodeParams{
			ID:          value.ID,
			GrantID:     value.GrantID,
			ValidUntil:  value.ValidUntil.UnixMicro(),
			DeleteAfter: value.StorageExpiresAt.UnixMicro(),
			Version:     int64(version),
		})
	}
	return q.InsertOAuthAuthCode(ctx, dbsql.InsertOAuthAuthCodeParams{
		ID:          value.ID,
		GrantID:     value.GrantID,
		ValidUntil:  value.ValidUntil.UnixMicro(),
		DeleteAfter: value.StorageExpiresAt.UnixMicro(),
		Version:     int64(version),
	})
}

func (s *Storage) putRefreshToken(ctx context.Context, tx *sql.Tx, value storedRefreshToken, version uint64, exists bool) error {
	q := dbsql.New(tx)
	if exists {
		return q.UpdateOAuthRefreshToken(ctx, dbsql.UpdateOAuthRefreshTokenParams{
			ID:           value.ID,
			GrantID:      value.GrantID,
			ValidUntil:   value.ValidUntil.UnixMicro(),
			DeleteAfter:  value.StorageExpiresAt.UnixMicro(),
			ReplacedByID: value.ReplacedByTokenID,
			Version:      int64(version),
		})
	}
	return q.InsertOAuthRefreshToken(ctx, dbsql.InsertOAuthRefreshTokenParams{
		ID:           value.ID,
		GrantID:      value.GrantID,
		ValidUntil:   value.ValidUntil.UnixMicro(),
		DeleteAfter:  value.StorageExpiresAt.UnixMicro(),
		ReplacedByID: value.ReplacedByTokenID,
		Version:      int64(version),
	})
}

func (s *Storage) putSession(ctx context.Context, tx *sql.Tx, value storedRefreshSession, version uint64, exists bool) error {
	q := dbsql.New(tx)
	if exists {
		return q.UpdateOAuthRefreshSession(ctx, dbsql.UpdateOAuthRefreshSessionParams{
			GrantID:    value.GrantID,
			ExpiresAt:  value.ExpiresAt.UnixMicro(),
			LastUsedAt: value.LastUsedAt.UnixMicro(),
			Version:    int64(version),
		})
	}
	return q.InsertOAuthRefreshSession(ctx, dbsql.InsertOAuthRefreshSessionParams{
		GrantID:    value.GrantID,
		ExpiresAt:  value.ExpiresAt.UnixMicro(),
		LastUsedAt: value.LastUsedAt.UnixMicro(),
		Version:    int64(version),
	})
}

func (s *Storage) deleteRef(ctx context.Context, tx *sql.Tx, ref storageRef) error {
	q := dbsql.New(tx)
	switch ref.Kind {
	case storageKindGrant:
		return q.DeleteOAuthGrant(ctx, ref.ID)
	case storageKindAuthCode:
		return q.DeleteOAuthAuthCode(ctx, ref.ID)
	case storageKindRefreshToken:
		return q.DeleteOAuthRefreshToken(ctx, ref.ID)
	case storageKindSession:
		return q.DeleteOAuthRefreshSession(ctx, ref.ID)
	default:
		return fmt.Errorf("oauth2as: unsupported storage kind %q", ref.Kind)
	}
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
