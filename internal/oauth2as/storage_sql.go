package oauth2as

import (
	"context"
	"database/sql"
	"database/sql/driver"
	jsonv2 "encoding/json/v2"
	"errors"
	"fmt"
	"strings"
	"time"
)

// OAuth tables share a database with other PassIDP state.
const (
	tblSchemaMigrations = "oauth2as_schema_migrations"
	tblGrants           = "oauth2as_grants"
	tblAuthCodes        = "oauth2as_authorization_codes"
	tblRefreshTokens    = "oauth2as_refresh_tokens"
	tblRefreshSessions  = "oauth2as_refresh_sessions"
	idxGrantOwner       = "oauth2as_grant_owner_idx"
	idxGrantExpiry      = "oauth2as_grant_expiry_idx"
	idxCodeExpiry       = "oauth2as_code_expiry_idx"
	idxCodeGrant        = "oauth2as_code_grant_idx"
	idxTokenExpiry      = "oauth2as_token_expiry_idx"
	idxTokenGrant       = "oauth2as_token_grant_idx"
	idxSessionActive    = "oauth2as_session_active_idx"
)

// Storage holds SQLite authorization-server state for one issuer.
// Construct it with [NewSQLStorage].
type Storage struct {
	db         *sql.DB
	migrations []sqlMigration

	// commitHook, if set, is called before each Commit and aborts it with the
	// returned error. It is a test seam for fault injection.
	commitHook func(storageCommit) error
}

// NewSQLStorage returns SQLite-backed storage using db. It does not connect to
// the database or apply migrations. Call [Storage.Migrate] before serving
// traffic.
func NewSQLStorage(db *sql.DB) (*Storage, error) {
	if db == nil {
		return nil, errors.New("oauth2as: SQL database is required")
	}
	return &Storage{db: db, migrations: sqlMigrations()}, nil
}

func (s *Storage) conn(ctx context.Context) (*sql.Conn, error) {
	conn, err := s.db.Conn(ctx)
	if err != nil {
		return nil, err
	}
	if _, err := conn.ExecContext(ctx, "PRAGMA foreign_keys = ON"); err != nil {
		conn.Close()
		return nil, fmt.Errorf("enable SQLite foreign keys: %w", err)
	}
	return conn, nil
}

func timeFromMicros(value int64) time.Time { return time.UnixMicro(value).UTC() }

func (s *Storage) getGrant(ctx context.Context, id string) (*storedGrant, error) {
	conn, err := s.conn(ctx)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	grant, version, err := s.scanGrant(ctx, conn, id)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	grant.ID = id
	grant.storageVersion = version
	return &grant, nil
}

func (s *Storage) getAuthCode(ctx context.Context, id string) (*storedAuthCode, error) {
	conn, err := s.conn(ctx)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	code, version, err := s.scanAuthCode(ctx, conn, id)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	code.ID = id
	code.storageVersion = version
	return &code, nil
}

func (s *Storage) getRefreshToken(ctx context.Context, id string) (*storedRefreshToken, error) {
	conn, err := s.conn(ctx)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	token, version, err := s.scanRefreshToken(ctx, conn, id)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	token.ID = id
	token.storageVersion = version
	return &token, nil
}

type sqlQueryer interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func (s *Storage) scanGrant(ctx context.Context, q sqlQueryer, id string) (storedGrant, uint64, error) {
	var (
		grant   storedGrant
		version uint64
	)
	err := q.QueryRowContext(ctx, "SELECT user_id, client_id, granted_scopes, redirect_uri, code_challenge, nonce, max_age, granted_at, authenticated_at, expires_at, dpop_thumbprint, acr, amr, version FROM "+tblGrants+" WHERE id = ?", id).Scan(
		&grant.UserID, &grant.ClientID, jsonArray(&grant.GrantedScopes), &grant.RedirectURI, &grant.CodeChallenge, &grant.Nonce, &grant.MaxAge,
		s.timeOf(&grant.GrantedAt), s.nullTime(&grant.AuthenticatedAt), s.timeOf(&grant.ExpiresAt),
		&grant.DPoPThumbprint,
		&grant.ACR, jsonArray(&grant.AMR), &version,
	)
	if err != nil {
		return storedGrant{}, 0, err
	}
	return grant, version, nil
}

func (s *Storage) scanAuthCode(ctx context.Context, q sqlQueryer, id string) (storedAuthCode, uint64, error) {
	var (
		code    storedAuthCode
		version uint64
	)
	err := q.QueryRowContext(ctx, "SELECT grant_id, valid_until, delete_after, version FROM "+tblAuthCodes+" WHERE id = ?", id).Scan(&code.GrantID, s.timeOf(&code.ValidUntil), s.timeOf(&code.StorageExpiresAt), &version)
	if err != nil {
		return storedAuthCode{}, 0, err
	}
	return code, version, nil
}

func (s *Storage) scanRefreshToken(ctx context.Context, q sqlQueryer, id string) (storedRefreshToken, uint64, error) {
	var (
		token   storedRefreshToken
		version uint64
	)
	err := q.QueryRowContext(ctx, "SELECT grant_id, valid_until, delete_after, replaced_by_id, version FROM "+tblRefreshTokens+" WHERE id = ?", id).Scan(&token.GrantID, s.timeOf(&token.ValidUntil), s.timeOf(&token.StorageExpiresAt), &token.ReplacedByTokenID, &version)
	if err != nil {
		return storedRefreshToken{}, 0, err
	}
	return token, version, nil
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
	conn, err := s.conn(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	tx, err := conn.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
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
	table, idColumn, err := s.tableForKind(ref.Kind)
	if err != nil {
		return 0, false, err
	}
	query := "SELECT version FROM " + table + " WHERE " + idColumn + " = ?"
	var version uint64
	err = tx.QueryRowContext(ctx, query, ref.ID).Scan(&version)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, false, nil
	}
	return version, err == nil, err
}

func (s *Storage) tableForKind(kind storageKind) (table, idColumn string, err error) {
	switch kind {
	case storageKindGrant:
		return tblGrants, "id", nil
	case storageKindAuthCode:
		return tblAuthCodes, "id", nil
	case storageKindRefreshToken:
		return tblRefreshTokens, "id", nil
	case storageKindSession:
		return tblRefreshSessions, "grant_id", nil
	default:
		return "", "", fmt.Errorf("oauth2as: unsupported storage kind %q", kind)
	}
}

func (s *Storage) putGrant(ctx context.Context, tx *sql.Tx, value storedGrant, version uint64, exists bool) error {
	return s.upsert(ctx, tx, exists,
		"INSERT INTO "+tblGrants+" (id, user_id, client_id, granted_scopes, redirect_uri, code_challenge, nonce, max_age, granted_at, authenticated_at, expires_at, dpop_thumbprint, acr, amr, version) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
		"UPDATE "+tblGrants+" SET user_id = ?, client_id = ?, granted_scopes = ?, redirect_uri = ?, code_challenge = ?, nonce = ?, max_age = ?, granted_at = ?, authenticated_at = ?, expires_at = ?, dpop_thumbprint = ?, acr = ?, amr = ?, version = ? WHERE id = ?",
		[]any{value.ID, value.UserID, value.ClientID, jsonArray(&value.GrantedScopes), value.RedirectURI, value.CodeChallenge, value.Nonce, value.MaxAge, s.timeOf(&value.GrantedAt), s.nullTime(&value.AuthenticatedAt), s.timeOf(&value.ExpiresAt), value.DPoPThumbprint, value.ACR, jsonArray(&value.AMR), version},
		[]any{value.UserID, value.ClientID, jsonArray(&value.GrantedScopes), value.RedirectURI, value.CodeChallenge, value.Nonce, value.MaxAge, s.timeOf(&value.GrantedAt), s.nullTime(&value.AuthenticatedAt), s.timeOf(&value.ExpiresAt), value.DPoPThumbprint, value.ACR, jsonArray(&value.AMR), version, value.ID})
}

func (s *Storage) putAuthCode(ctx context.Context, tx *sql.Tx, value storedAuthCode, version uint64, exists bool) error {
	return s.upsert(ctx, tx, exists,
		"INSERT INTO "+tblAuthCodes+" (id, grant_id, valid_until, delete_after, version) VALUES (?, ?, ?, ?, ?)",
		"UPDATE "+tblAuthCodes+" SET grant_id = ?, valid_until = ?, delete_after = ?, version = ? WHERE id = ?",
		[]any{value.ID, value.GrantID, s.timeOf(&value.ValidUntil), s.timeOf(&value.StorageExpiresAt), version},
		[]any{value.GrantID, s.timeOf(&value.ValidUntil), s.timeOf(&value.StorageExpiresAt), version, value.ID})
}

func (s *Storage) putRefreshToken(ctx context.Context, tx *sql.Tx, value storedRefreshToken, version uint64, exists bool) error {
	return s.upsert(ctx, tx, exists,
		"INSERT INTO "+tblRefreshTokens+" (id, grant_id, valid_until, delete_after, replaced_by_id, version) VALUES (?, ?, ?, ?, ?, ?)",
		"UPDATE "+tblRefreshTokens+" SET grant_id = ?, valid_until = ?, delete_after = ?, replaced_by_id = ?, version = ? WHERE id = ?",
		[]any{value.ID, value.GrantID, s.timeOf(&value.ValidUntil), s.timeOf(&value.StorageExpiresAt), value.ReplacedByTokenID, version},
		[]any{value.GrantID, s.timeOf(&value.ValidUntil), s.timeOf(&value.StorageExpiresAt), value.ReplacedByTokenID, version, value.ID})
}

func (s *Storage) putSession(ctx context.Context, tx *sql.Tx, value storedRefreshSession, version uint64, exists bool) error {
	return s.upsert(ctx, tx, exists,
		"INSERT INTO "+tblRefreshSessions+" (grant_id, expires_at, last_used_at, version) VALUES (?, ?, ?, ?)",
		"UPDATE "+tblRefreshSessions+" SET expires_at = ?, last_used_at = ?, version = ? WHERE grant_id = ?",
		[]any{value.GrantID, s.timeOf(&value.ExpiresAt), s.timeOf(&value.LastUsedAt), version},
		[]any{s.timeOf(&value.ExpiresAt), s.timeOf(&value.LastUsedAt), version, value.GrantID})
}

func (s *Storage) upsert(ctx context.Context, tx *sql.Tx, exists bool, insert, update string, insertArgs, updateArgs []any) error {
	query, args := insert, insertArgs
	if exists {
		query, args = update, updateArgs
	}
	_, err := tx.ExecContext(ctx, query, args...)
	return err
}

func (s *Storage) deleteRef(ctx context.Context, tx *sql.Tx, ref storageRef) error {
	table, idColumn, err := s.tableForKind(ref.Kind)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, "DELETE FROM "+table+" WHERE "+idColumn+" = ?", ref.ID)
	return err
}

func (s *Storage) listRefreshSessions(ctx context.Context, query storageRefreshSessionQuery) ([]storedRefreshSession, error) {
	conn, err := s.conn(ctx)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	statement := "SELECT rs.grant_id, g.user_id, g.client_id, g.granted_scopes, g.granted_at, g.authenticated_at, rs.expires_at, rs.last_used_at, g.dpop_thumbprint FROM " +
		tblRefreshSessions + " rs JOIN " + tblGrants + " g ON g.id = rs.grant_id WHERE g.user_id = ? AND rs.expires_at > ?"
	args := []any{query.UserID, s.timeOf(&query.ActiveAt)}
	if query.ClientID != "" {
		statement += " AND g.client_id = ?"
		args = append(args, query.ClientID)
	}
	if query.AfterGrantID != "" {
		statement += " AND (rs.last_used_at < ? OR (rs.last_used_at = ? AND rs.grant_id > ?))"
		after := s.timeOf(&query.AfterLastUsed)
		args = append(args, after, after, query.AfterGrantID)
	}
	statement += " ORDER BY rs.last_used_at DESC, rs.grant_id ASC LIMIT ?"
	args = append(args, query.Limit)

	rows, err := conn.QueryContext(ctx, statement, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]storedRefreshSession, 0, query.Limit)
	for rows.Next() {
		var (
			session    storedRefreshSession
			thumbprint string
		)
		if err := rows.Scan(
			&session.GrantID, &session.UserID, &session.ClientID, jsonArray(&session.GrantedScopes),
			s.timeOf(&session.CreatedAt), s.nullTime(&session.AuthenticatedAt), s.timeOf(&session.ExpiresAt), s.timeOf(&session.LastUsedAt),
			&thumbprint,
		); err != nil {
			return nil, err
		}
		session.DPoPBound = thumbprint != ""
		grant := storedGrant{AuthenticatedAt: session.AuthenticatedAt, GrantedAt: session.CreatedAt}
		session.AuthenticatedAt = authTimeFromGrant(&grant)
		result = append(result, session)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return result, nil
}

func (s *Storage) cleanup(ctx context.Context, options CleanupOptions) (CleanupResult, error) {
	conn, err := s.conn(ctx)
	if err != nil {
		return CleanupResult{}, err
	}
	defer conn.Close()
	tx, err := conn.BeginTx(ctx, nil)
	if err != nil {
		return CleanupResult{}, err
	}
	defer tx.Rollback()
	cutoff := s.timeOf(&options.Before)
	deleted := 0
	remaining := options.Limit
	for _, target := range []struct {
		table, id, expiry string
	}{
		{tblRefreshSessions, "grant_id", "expires_at"},
		{tblAuthCodes, "id", "delete_after"},
		{tblRefreshTokens, "id", "delete_after"},
		{tblGrants, "id", "expires_at"},
	} {
		if remaining == 0 {
			break
		}
		query := "DELETE FROM " + target.table + " WHERE " + target.id + " IN (SELECT " + target.id +
			" FROM " + target.table + " WHERE " + target.expiry + " <= ? ORDER BY " + target.expiry + " LIMIT ?)"
		result, err := tx.ExecContext(ctx, query, cutoff, remaining)
		if err != nil {
			return CleanupResult{}, err
		}
		count, err := result.RowsAffected()
		if err != nil {
			return CleanupResult{}, err
		}
		deleted += int(count)
		remaining -= int(count)
	}
	more, err := s.hasExpired(ctx, tx, cutoff)
	if err != nil {
		return CleanupResult{}, err
	}
	if err := tx.Commit(); err != nil {
		return CleanupResult{}, err
	}
	return CleanupResult{Deleted: deleted, More: more}, nil
}

func (s *Storage) hasExpired(ctx context.Context, tx *sql.Tx, cutoff any) (bool, error) {
	query := "SELECT EXISTS (" +
		"SELECT 1 FROM " + tblRefreshSessions + " WHERE expires_at <= ? " +
		"UNION ALL SELECT 1 FROM " + tblAuthCodes + " WHERE delete_after <= ? " +
		"UNION ALL SELECT 1 FROM " + tblRefreshTokens + " WHERE delete_after <= ? " +
		"UNION ALL SELECT 1 FROM " + tblGrants + " WHERE expires_at <= ?" +
		")"
	var exists bool
	err := tx.QueryRowContext(ctx, query, cutoff, cutoff, cutoff, cutoff).Scan(&exists)
	return exists, err
}

type sqlMigration struct {
	version int
	name    string
	up      []string
}

// Migrate applies pending schema migrations. It is safe to call on every process start.
// The version 3 upgrade discards existing OAuth grants, codes, tokens, and sessions.
func (s *Storage) Migrate(ctx context.Context) error {
	var err error
	for attempt := range 4 {
		err = s.migrateOnce(ctx)
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

func (s *Storage) migrateOnce(ctx context.Context) error {
	conn, err := s.conn(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()

	tx, err := conn.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return err
	}
	defer tx.Rollback()

	if _, err := tx.ExecContext(ctx, "CREATE TABLE IF NOT EXISTS "+tblSchemaMigrations+" ("+
		"version BIGINT PRIMARY KEY, "+
		"name TEXT NOT NULL, "+
		"applied_at INTEGER NOT NULL"+
		")"); err != nil {
		return fmt.Errorf("create schema migrations table: %w", err)
	}

	rows, err := tx.QueryContext(ctx, "SELECT version FROM "+tblSchemaMigrations)
	if err != nil {
		return err
	}
	applied := make(map[int]struct{})
	for rows.Next() {
		var version int
		if err := rows.Scan(&version); err != nil {
			rows.Close()
			return err
		}
		applied[version] = struct{}{}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()

	// Versions 1 and 2 are replaced by the transactional reset in version 3.
	known := map[int]struct{}{1: {}, 2: {}}
	for _, migration := range s.migrations {
		known[migration.version] = struct{}{}
	}
	for version := range applied {
		if _, ok := known[version]; !ok {
			return fmt.Errorf("oauth2as: database schema version %d is newer than this library", version)
		}
	}

	now := time.Now()
	for _, migration := range s.migrations {
		if _, ok := applied[migration.version]; ok {
			continue
		}
		for _, statement := range migration.up {
			if _, err := tx.ExecContext(ctx, statement); err != nil {
				return fmt.Errorf("apply migration %d %s: %w", migration.version, migration.name, err)
			}
		}
		if _, err := tx.ExecContext(ctx,
			"INSERT INTO "+tblSchemaMigrations+" (version, name, applied_at) VALUES (?, ?, ?)",
			migration.version, migration.name, s.timeOf(&now)); err != nil {
			return fmt.Errorf("record migration %d %s: %w", migration.version, migration.name, err)
		}
	}
	return tx.Commit()
}

func sqlMigrations() []sqlMigration {
	return []sqlMigration{{
		version: 3,
		name:    "token_digest_schema",
		// Existing OAuth grants and tokens are intentionally discarded. The reset is
		// transactional and runs once; other tables in the shared database are untouched.
		up: []string{
			"DROP TABLE IF EXISTS " + tblRefreshSessions,
			"DROP TABLE IF EXISTS " + tblRefreshTokens,
			"DROP TABLE IF EXISTS " + tblAuthCodes,
			"DROP TABLE IF EXISTS " + tblGrants,
			`CREATE TABLE oauth2as_grants (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    client_id TEXT NOT NULL,
    granted_scopes JSON NOT NULL,
    redirect_uri TEXT NOT NULL,
    code_challenge TEXT NOT NULL,
    nonce TEXT NOT NULL,
    max_age INTEGER,
    granted_at INTEGER NOT NULL,
    authenticated_at INTEGER,
    expires_at INTEGER NOT NULL,
    dpop_thumbprint TEXT NOT NULL,
    acr TEXT NOT NULL,
    amr JSON NOT NULL,
    version INTEGER NOT NULL CHECK (version > 0)
   )`,
			"CREATE INDEX " + idxGrantOwner + " ON " + tblGrants + " (user_id, client_id, id)",
			"CREATE INDEX " + idxGrantExpiry + " ON " + tblGrants + " (expires_at)",
			`CREATE TABLE oauth2as_authorization_codes (
    id TEXT PRIMARY KEY,
    grant_id TEXT NOT NULL REFERENCES oauth2as_grants(id) ON DELETE CASCADE,
    valid_until INTEGER NOT NULL,
    delete_after INTEGER NOT NULL,
    version INTEGER NOT NULL CHECK (version > 0)
   )`,
			"CREATE INDEX " + idxCodeExpiry + " ON " + tblAuthCodes + " (delete_after)",
			"CREATE INDEX " + idxCodeGrant + " ON " + tblAuthCodes + " (grant_id)",
			`CREATE TABLE oauth2as_refresh_tokens (
    id TEXT PRIMARY KEY,
    grant_id TEXT NOT NULL REFERENCES oauth2as_grants(id) ON DELETE CASCADE,
    valid_until INTEGER NOT NULL,
    delete_after INTEGER NOT NULL,
    replaced_by_id TEXT NOT NULL,
    version INTEGER NOT NULL CHECK (version > 0)
   )`,
			"CREATE INDEX " + idxTokenExpiry + " ON " + tblRefreshTokens + " (delete_after)",
			"CREATE INDEX " + idxTokenGrant + " ON " + tblRefreshTokens + " (grant_id)",
			`CREATE TABLE oauth2as_refresh_sessions (
    grant_id TEXT PRIMARY KEY REFERENCES oauth2as_grants(id) ON DELETE CASCADE,
    expires_at INTEGER NOT NULL,
    last_used_at INTEGER NOT NULL,
    version INTEGER NOT NULL CHECK (version > 0)
   )`,
			"CREATE INDEX " + idxSessionActive + " ON " + tblRefreshSessions + " (expires_at, last_used_at, grant_id)",
		},
	}}
}

func jsonArray[T any](v *T) *sqlJSON[T] {
	return &sqlJSON[T]{v: v, emptyArray: true}
}

func (s *Storage) timeOf(t *time.Time) *sqlTime {
	return &sqlTime{t: t}
}

func (s *Storage) nullTime(t *time.Time) *sqlTime {
	return &sqlTime{t: t, nullable: true}
}

type sqlJSON[T any] struct {
	v          *T
	emptyArray bool
}

func (j *sqlJSON[T]) Scan(src any) error {
	if j == nil || j.v == nil {
		return fmt.Errorf("oauth2as: json scan into nil")
	}
	if src == nil {
		var zero T
		*j.v = zero
		return nil
	}
	var data []byte
	switch v := src.(type) {
	case []byte:
		data = v
	case string:
		data = []byte(v)
	default:
		return fmt.Errorf("oauth2as: unsupported json type %T", src)
	}
	if len(data) == 0 || string(data) == "null" {
		var zero T
		*j.v = zero
		return nil
	}
	return jsonv2.Unmarshal(data, j.v)
}

func (j *sqlJSON[T]) Value() (driver.Value, error) {
	if j == nil || j.v == nil {
		return j.emptyValue(), nil
	}
	data, err := jsonv2.Marshal(*j.v)
	if err != nil {
		return nil, err
	}
	if len(data) == 0 || string(data) == "null" {
		return j.emptyValue(), nil
	}
	return string(data), nil
}

func (j *sqlJSON[T]) emptyValue() driver.Value {
	if j != nil && j.emptyArray {
		return "[]"
	}
	return nil
}

type sqlTime struct {
	t        *time.Time
	nullable bool
}

func (t *sqlTime) Scan(src any) error {
	if t == nil || t.t == nil {
		return fmt.Errorf("oauth2as: time scan into nil")
	}
	if src == nil {
		*t.t = time.Time{}
		return nil
	}
	value, ok := src.(int64)
	if !ok {
		return fmt.Errorf("oauth2as: unsupported time type %T", src)
	}
	*t.t = time.UnixMicro(value).UTC()
	return nil
}

func (t *sqlTime) Value() (driver.Value, error) {
	if t == nil || t.t == nil || (t.nullable && t.t.IsZero()) {
		return nil, nil
	}
	return t.t.UnixMicro(), nil
}
