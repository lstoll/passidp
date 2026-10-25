package oauth2as

import (
	"bytes"
	"context"
	"database/sql"
	"database/sql/driver"
	jsonv2 "encoding/json/v2"
	"errors"
	"fmt"
	"hash/fnv"
	"regexp"
	"strings"
	"time"
)

// SQLDialect identifies a supported database/sql dialect.
type SQLDialect string

const (
	// SQLDialectPostgreSQL selects PostgreSQL-compatible SQL.
	SQLDialectPostgreSQL SQLDialect = "postgresql"
	// SQLDialectSQLite selects SQLite-compatible SQL.
	SQLDialectSQLite SQLDialect = "sqlite"
)

// SQLStorageOptions configures SQL-backed storage.
type SQLStorageOptions struct {
	// Dialect selects the SQL dialect and is required.
	Dialect SQLDialect
	// TablePrefix prefixes every table and index. It defaults to "oauth2as".
	TablePrefix string
}

var sqlTablePrefixPattern = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)

type sqlNames struct {
	prefix           string
	schemaMigrations string
	grants           string
	authCodes        string
	refreshTokens    string
	refreshSessions  string
	grantOwnerIndex  string
	grantExpiryIdx   string
	codeExpiryIdx    string
	codeGrantIdx     string
	tokenExpiryIdx   string
	tokenGrantIdx    string
	sessionActive    string
}

func makeSQLNames(prefix string, dialect SQLDialect) (sqlNames, error) {
	if prefix == "" {
		prefix = "oauth2as"
	}
	if !sqlTablePrefixPattern.MatchString(prefix) {
		return sqlNames{}, fmt.Errorf("oauth2as: invalid SQL table prefix %q", prefix)
	}
	n := sqlNames{
		prefix:           prefix,
		schemaMigrations: prefix + "_schema_migrations",
		grants:           prefix + "_grants",
		authCodes:        prefix + "_authorization_codes",
		refreshTokens:    prefix + "_refresh_tokens",
		refreshSessions:  prefix + "_refresh_sessions",
		grantOwnerIndex:  prefix + "_grant_owner_idx",
		grantExpiryIdx:   prefix + "_grant_expiry_idx",
		codeExpiryIdx:    prefix + "_code_expiry_idx",
		codeGrantIdx:     prefix + "_code_grant_idx",
		tokenExpiryIdx:   prefix + "_token_expiry_idx",
		tokenGrantIdx:    prefix + "_token_grant_idx",
		sessionActive:    prefix + "_session_active_idx",
	}
	if dialect == SQLDialectPostgreSQL {
		for _, identifier := range []string{
			n.schemaMigrations, n.grants, n.authCodes, n.refreshTokens, n.refreshSessions,
			n.grantOwnerIndex, n.grantExpiryIdx, n.codeExpiryIdx, n.codeGrantIdx,
			n.tokenExpiryIdx, n.tokenGrantIdx, n.sessionActive,
		} {
			if len(identifier) > 63 {
				return sqlNames{}, fmt.Errorf("oauth2as: SQL identifier %q exceeds PostgreSQL's 63-byte limit", identifier)
			}
		}
	}
	return n, nil
}

type sqlStorage struct {
	db         *sql.DB
	dialect    SQLDialect
	names      sqlNames
	migrations []sqlMigration
}

var _ storageBackend = (*sqlStorage)(nil)

// NewSQLStorage returns relational storage backed by db. It does not connect
// to the database or apply migrations. Call [Storage.Migrate] before serving
// traffic.
func NewSQLStorage(db *sql.DB, options SQLStorageOptions) (*Storage, error) {
	if db == nil {
		return nil, errors.New("oauth2as: SQL database is required")
	}
	if options.Dialect != SQLDialectPostgreSQL && options.Dialect != SQLDialectSQLite {
		return nil, fmt.Errorf("oauth2as: unsupported SQL dialect %q", options.Dialect)
	}
	names, err := makeSQLNames(options.TablePrefix, options.Dialect)
	if err != nil {
		return nil, err
	}
	return &Storage{backend: &sqlStorage{
		db:         db,
		dialect:    options.Dialect,
		names:      names,
		migrations: sqlMigrations(options.Dialect, names),
	}}, nil
}

func (s *sqlStorage) bind(query string) string {
	if s.dialect != SQLDialectPostgreSQL {
		return query
	}
	var b strings.Builder
	arg := 1
	for _, r := range query {
		if r == '?' {
			fmt.Fprintf(&b, "$%d", arg)
			arg++
		} else {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func (s *sqlStorage) conn(ctx context.Context) (*sql.Conn, error) {
	conn, err := s.db.Conn(ctx)
	if err != nil {
		return nil, err
	}
	if s.dialect == SQLDialectSQLite {
		if _, err := conn.ExecContext(ctx, "PRAGMA foreign_keys = ON"); err != nil {
			conn.Close()
			return nil, fmt.Errorf("enable SQLite foreign keys: %w", err)
		}
	}
	return conn, nil
}

func timeFromMicros(value int64) time.Time { return time.UnixMicro(value).UTC() }

func truncateTime(t time.Time) time.Time {
	if t.IsZero() {
		return t
	}
	return t.UTC().Truncate(time.Microsecond)
}

// sqliteTimeFormat is fixed-width UTC so TEXT timestamps sort chronologically.
const sqliteTimeFormat = "2006-01-02T15:04:05.000000Z"

func (s *sqlStorage) GetGrant(ctx context.Context, id string) (storedGrant, error) {
	conn, err := s.conn(ctx)
	if err != nil {
		return storedGrant{}, err
	}
	defer conn.Close()
	grant, version, err := s.scanGrant(ctx, conn, id)
	if errors.Is(err, sql.ErrNoRows) {
		return storedGrant{}, ErrNotFound
	}
	if err != nil {
		return storedGrant{}, err
	}
	grant.ID = id
	grant.storageVersion = version
	return grant, nil
}

func (s *sqlStorage) GetAuthCode(ctx context.Context, id string) (storedAuthCode, error) {
	conn, err := s.conn(ctx)
	if err != nil {
		return storedAuthCode{}, err
	}
	defer conn.Close()
	code, version, err := s.scanAuthCode(ctx, conn, id)
	if errors.Is(err, sql.ErrNoRows) {
		return storedAuthCode{}, ErrNotFound
	}
	if err != nil {
		return storedAuthCode{}, err
	}
	code.ID = id
	code.storageVersion = version
	return code, nil
}

func (s *sqlStorage) GetRefreshToken(ctx context.Context, id string) (storedRefreshToken, error) {
	conn, err := s.conn(ctx)
	if err != nil {
		return storedRefreshToken{}, err
	}
	defer conn.Close()
	token, version, err := s.scanRefreshToken(ctx, conn, id)
	if errors.Is(err, sql.ErrNoRows) {
		return storedRefreshToken{}, ErrNotFound
	}
	if err != nil {
		return storedRefreshToken{}, err
	}
	token.ID = id
	token.storageVersion = version
	return token, nil
}

type sqlQueryer interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func (s *sqlStorage) scanGrant(ctx context.Context, q sqlQueryer, id string) (storedGrant, uint64, error) {
	var (
		grant   storedGrant
		version uint64
	)
	err := q.QueryRowContext(ctx, s.bind(
		"SELECT user_id, client_id, granted_scopes, request, granted_at, authenticated_at, expires_at, additional_state, metadata, encrypted_metadata, acr, amr, version FROM "+s.names.grants+" WHERE id = ?",
	), id).Scan(
		&grant.UserID, &grant.ClientID, jsonArray(&grant.GrantedScopes), jsonOf(&grant.Request),
		s.timeOf(&grant.GrantedAt), s.nullTime(&grant.AuthenticatedAt), s.timeOf(&grant.ExpiresAt),
		jsonOf(&grant.AdditionalState), nullOf(&grant.Metadata), nullOf(&grant.EncryptedMetadata),
		nullOf(&grant.ACR), jsonArray(&grant.AMR), &version,
	)
	if err != nil {
		return storedGrant{}, 0, err
	}
	return grant, version, nil
}

func (s *sqlStorage) scanAuthCode(ctx context.Context, q sqlQueryer, id string) (storedAuthCode, uint64, error) {
	var (
		code    storedAuthCode
		version uint64
	)
	err := q.QueryRowContext(ctx, s.bind(
		"SELECT grant_id, code, valid_until, delete_after, encrypted_grant_key, version FROM "+s.names.authCodes+" WHERE id = ?",
	), id).Scan(&code.GrantID, &code.Code, s.timeOf(&code.ValidUntil), s.timeOf(&code.StorageExpiresAt), nullOf(&code.EncryptedGrantKey), &version)
	if err != nil {
		return storedAuthCode{}, 0, err
	}
	return code, version, nil
}

func (s *sqlStorage) scanRefreshToken(ctx context.Context, q sqlQueryer, id string) (storedRefreshToken, uint64, error) {
	var (
		token   storedRefreshToken
		version uint64
	)
	err := q.QueryRowContext(ctx, s.bind(
		"SELECT grant_id, token, valid_until, delete_after, replaced_by_id, encrypted_grant_key, version FROM "+s.names.refreshTokens+" WHERE id = ?",
	), id).Scan(&token.GrantID, &token.Token, s.timeOf(&token.ValidUntil), s.timeOf(&token.StorageExpiresAt), nullOf(&token.ReplacedByTokenID), nullOf(&token.EncryptedGrantKey), &version)
	if err != nil {
		return storedRefreshToken{}, 0, err
	}
	return token, version, nil
}

func (s *sqlStorage) Commit(ctx context.Context, commit storageCommit) error {
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

func (s *sqlStorage) commitOnce(ctx context.Context, commit storageCommit) error {
	if err := validateStorageCommit(commit); err != nil {
		return err
	}
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
		version, exists, err := s.version(ctx, tx, check.ref(), true)
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
		if exists {
			versions[check.ref()] = version
		}
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

type sqlStateError interface {
	error
	SQLState() string
}

func uniqueViolation(err error) bool {
	var state sqlStateError
	if errors.As(err, &state) && state.SQLState() == "23505" {
		return true
	}
	return strings.Contains(strings.ToLower(err.Error()), "unique constraint failed")
}

func retryableSQLError(err error) bool {
	var state sqlStateError
	if errors.As(err, &state) { //nolint:modernize // AsType cannot target a capability interface on Go 1.27.
		switch state.SQLState() {
		case "40001", "40P01":
			return true
		}
	}
	message := strings.ToLower(err.Error())
	return strings.Contains(message, "database is locked") ||
		strings.Contains(message, "database table is locked") ||
		strings.Contains(message, "sqlite_busy")
}

func (s *sqlStorage) putVersion(ctx context.Context, tx *sql.Tx, versions map[storageRef]uint64, ref storageRef) (uint64, error) {
	if version, ok := versions[ref]; ok {
		return version + 1, nil
	}
	version, exists, err := s.version(ctx, tx, ref, true)
	if err != nil {
		return 0, err
	}
	if !exists {
		version = 0
	}
	return version + 1, nil
}

func (s *sqlStorage) version(ctx context.Context, tx *sql.Tx, ref storageRef, lock bool) (uint64, bool, error) {
	table, idColumn, err := s.tableForKind(ref.Kind)
	if err != nil {
		return 0, false, err
	}
	query := "SELECT version FROM " + table + " WHERE " + idColumn + " = ?"
	if lock && s.dialect == SQLDialectPostgreSQL {
		query += " FOR UPDATE"
	}
	var version uint64
	err = tx.QueryRowContext(ctx, s.bind(query), ref.ID).Scan(&version)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, false, nil
	}
	return version, err == nil, err
}

func (s *sqlStorage) tableForKind(kind storageKind) (table, idColumn string, err error) {
	switch kind {
	case storageKindGrant:
		return s.names.grants, "id", nil
	case storageKindAuthCode:
		return s.names.authCodes, "id", nil
	case storageKindRefreshToken:
		return s.names.refreshTokens, "id", nil
	case storageKindSession:
		return s.names.refreshSessions, "grant_id", nil
	default:
		return "", "", fmt.Errorf("oauth2as: unsupported storage kind %q", kind)
	}
}

func (s *sqlStorage) putGrant(ctx context.Context, tx *sql.Tx, value storedGrant, version uint64, exists bool) error {
	return s.upsert(ctx, tx, exists,
		"INSERT INTO "+s.names.grants+" (id, user_id, client_id, granted_scopes, request, granted_at, authenticated_at, expires_at, additional_state, metadata, encrypted_metadata, acr, amr, version) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
		"UPDATE "+s.names.grants+" SET user_id = ?, client_id = ?, granted_scopes = ?, request = ?, granted_at = ?, authenticated_at = ?, expires_at = ?, additional_state = ?, metadata = ?, encrypted_metadata = ?, acr = ?, amr = ?, version = ? WHERE id = ?",
		[]any{
			value.ID, value.UserID, value.ClientID, jsonArray(&value.GrantedScopes), jsonOf(&value.Request), s.timeOf(&value.GrantedAt), s.nullTime(&value.AuthenticatedAt),
			s.timeOf(&value.ExpiresAt), jsonOf(&value.AdditionalState), nullOf(&value.Metadata), nullOf(&value.EncryptedMetadata),
			nullOf(&value.ACR), jsonArray(&value.AMR), version,
		},
		[]any{
			value.UserID, value.ClientID, jsonArray(&value.GrantedScopes), jsonOf(&value.Request), s.timeOf(&value.GrantedAt), s.nullTime(&value.AuthenticatedAt),
			s.timeOf(&value.ExpiresAt), jsonOf(&value.AdditionalState), nullOf(&value.Metadata), nullOf(&value.EncryptedMetadata),
			nullOf(&value.ACR), jsonArray(&value.AMR), version, value.ID,
		})
}

func (s *sqlStorage) putAuthCode(ctx context.Context, tx *sql.Tx, value storedAuthCode, version uint64, exists bool) error {
	return s.upsert(ctx, tx, exists,
		"INSERT INTO "+s.names.authCodes+" (id, grant_id, code, valid_until, delete_after, encrypted_grant_key, version) VALUES (?, ?, ?, ?, ?, ?, ?)",
		"UPDATE "+s.names.authCodes+" SET grant_id = ?, code = ?, valid_until = ?, delete_after = ?, encrypted_grant_key = ?, version = ? WHERE id = ?",
		[]any{value.ID, value.GrantID, value.Code, s.timeOf(&value.ValidUntil), s.timeOf(&value.StorageExpiresAt), nullOf(&value.EncryptedGrantKey), version},
		[]any{value.GrantID, value.Code, s.timeOf(&value.ValidUntil), s.timeOf(&value.StorageExpiresAt), nullOf(&value.EncryptedGrantKey), version, value.ID})
}

func (s *sqlStorage) putRefreshToken(ctx context.Context, tx *sql.Tx, value storedRefreshToken, version uint64, exists bool) error {
	return s.upsert(ctx, tx, exists,
		"INSERT INTO "+s.names.refreshTokens+" (id, grant_id, token, valid_until, delete_after, replaced_by_id, encrypted_grant_key, version) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
		"UPDATE "+s.names.refreshTokens+" SET grant_id = ?, token = ?, valid_until = ?, delete_after = ?, replaced_by_id = ?, encrypted_grant_key = ?, version = ? WHERE id = ?",
		[]any{value.ID, value.GrantID, value.Token, s.timeOf(&value.ValidUntil), s.timeOf(&value.StorageExpiresAt), nullOf(&value.ReplacedByTokenID), nullOf(&value.EncryptedGrantKey), version},
		[]any{value.GrantID, value.Token, s.timeOf(&value.ValidUntil), s.timeOf(&value.StorageExpiresAt), nullOf(&value.ReplacedByTokenID), nullOf(&value.EncryptedGrantKey), version, value.ID})
}

func (s *sqlStorage) putSession(ctx context.Context, tx *sql.Tx, value storedRefreshSession, version uint64, exists bool) error {
	return s.upsert(ctx, tx, exists,
		"INSERT INTO "+s.names.refreshSessions+" (grant_id, expires_at, last_used_at, version) VALUES (?, ?, ?, ?)",
		"UPDATE "+s.names.refreshSessions+" SET expires_at = ?, last_used_at = ?, version = ? WHERE grant_id = ?",
		[]any{value.GrantID, s.timeOf(&value.ExpiresAt), s.timeOf(&value.LastUsedAt), version},
		[]any{s.timeOf(&value.ExpiresAt), s.timeOf(&value.LastUsedAt), version, value.GrantID})
}

func (s *sqlStorage) upsert(ctx context.Context, tx *sql.Tx, exists bool, insert, update string, insertArgs, updateArgs []any) error {
	query, args := insert, insertArgs
	if exists {
		query, args = update, updateArgs
	}
	_, err := tx.ExecContext(ctx, s.bind(query), args...)
	return err
}

func (s *sqlStorage) deleteRef(ctx context.Context, tx *sql.Tx, ref storageRef) error {
	table, idColumn, err := s.tableForKind(ref.Kind)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, s.bind("DELETE FROM "+table+" WHERE "+idColumn+" = ?"), ref.ID)
	return err
}

func (s *sqlStorage) ListRefreshSessions(ctx context.Context, query storageRefreshSessionQuery) ([]storedRefreshSession, error) {
	conn, err := s.conn(ctx)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	statement := "SELECT rs.grant_id, g.user_id, g.client_id, g.granted_scopes, g.granted_at, g.authenticated_at, rs.expires_at, rs.last_used_at FROM " +
		s.names.refreshSessions + " rs JOIN " + s.names.grants + " g ON g.id = rs.grant_id WHERE g.user_id = ? AND rs.expires_at > ?"
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

	rows, err := conn.QueryContext(ctx, s.bind(statement), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]storedRefreshSession, 0, query.Limit)
	for rows.Next() {
		var session storedRefreshSession
		if err := rows.Scan(
			&session.GrantID, &session.UserID, &session.ClientID, jsonArray(&session.GrantedScopes),
			s.timeOf(&session.CreatedAt), s.nullTime(&session.AuthenticatedAt), s.timeOf(&session.ExpiresAt), s.timeOf(&session.LastUsedAt),
		); err != nil {
			return nil, err
		}
		grant := storedGrant{AuthenticatedAt: session.AuthenticatedAt, GrantedAt: session.CreatedAt}
		session.AuthenticatedAt = authTimeFromGrant(&grant)
		result = append(result, session)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return result, nil
}

func (s *sqlStorage) Cleanup(ctx context.Context, options CleanupOptions) (CleanupResult, error) {
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
		{s.names.refreshSessions, "grant_id", "expires_at"},
		{s.names.authCodes, "id", "delete_after"},
		{s.names.refreshTokens, "id", "delete_after"},
		{s.names.grants, "id", "expires_at"},
	} {
		if remaining == 0 {
			break
		}
		query := "DELETE FROM " + target.table + " WHERE " + target.id + " IN (SELECT " + target.id +
			" FROM " + target.table + " WHERE " + target.expiry + " <= ? ORDER BY " + target.expiry + " LIMIT ?)"
		result, err := tx.ExecContext(ctx, s.bind(query), cutoff, remaining)
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

func (s *sqlStorage) hasExpired(ctx context.Context, tx *sql.Tx, cutoff any) (bool, error) {
	query := "SELECT EXISTS (" +
		"SELECT 1 FROM " + s.names.refreshSessions + " WHERE expires_at <= ? " +
		"UNION ALL SELECT 1 FROM " + s.names.authCodes + " WHERE delete_after <= ? " +
		"UNION ALL SELECT 1 FROM " + s.names.refreshTokens + " WHERE delete_after <= ? " +
		"UNION ALL SELECT 1 FROM " + s.names.grants + " WHERE expires_at <= ?" +
		")"
	var exists bool
	err := tx.QueryRowContext(ctx, s.bind(query), cutoff, cutoff, cutoff, cutoff).Scan(&exists)
	return exists, err
}

type sqlMigration struct {
	version int
	name    string
	up      []string
}

func (s *sqlStorage) Migrate(ctx context.Context) error {
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

func (s *sqlStorage) migrateOnce(ctx context.Context) error {
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

	if s.dialect == SQLDialectPostgreSQL {
		if _, err := tx.ExecContext(ctx, s.bind("SELECT pg_advisory_xact_lock(?)"), migrateLockKey(s.names.prefix)); err != nil {
			return fmt.Errorf("lock schema migrations: %w", err)
		}
	}

	_, _, _, ts := sqlColumnTypes(s.dialect)
	if _, err := tx.ExecContext(ctx, "CREATE TABLE IF NOT EXISTS "+s.names.schemaMigrations+" ("+
		"version BIGINT PRIMARY KEY, "+
		"name TEXT NOT NULL, "+
		"applied_at "+ts+" NOT NULL"+
		")"); err != nil {
		return fmt.Errorf("create schema migrations table: %w", err)
	}

	rows, err := tx.QueryContext(ctx, "SELECT version FROM "+s.names.schemaMigrations)
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

	known := make(map[int]struct{}, len(s.migrations))
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
		if _, err := tx.ExecContext(ctx, s.bind(
			"INSERT INTO "+s.names.schemaMigrations+" (version, name, applied_at) VALUES (?, ?, ?)",
		), migration.version, migration.name, s.timeOf(&now)); err != nil {
			return fmt.Errorf("record migration %d %s: %w", migration.version, migration.name, err)
		}
	}
	return tx.Commit()
}

func migrateLockKey(prefix string) int64 {
	sum := fnv.New64a()
	_, _ = sum.Write([]byte("oauth2as-migrate:"))
	_, _ = sum.Write([]byte(prefix))
	return int64(sum.Sum64())
}

func sqlColumnTypes(dialect SQLDialect) (blob, js, id, ts string) {
	if dialect == SQLDialectPostgreSQL {
		return "BYTEA", "JSONB", "UUID", "TIMESTAMPTZ"
	}
	// SQLite has no UUID or timestamptz. TEXT IDs store canonical UUID
	// strings; TEXT timestamps use sqliteTimeFormat so they sort in time order.
	return "BLOB", "JSON", "TEXT", "TEXT"
}

func sqlMigrations(dialect SQLDialect, n sqlNames) []sqlMigration {
	blob, js, id, ts := sqlColumnTypes(dialect)
	return []sqlMigration{{
		version: 1,
		name:    "initial_schema",
		up: []string{
			"CREATE TABLE " + n.grants + " (" +
				"id " + id + " PRIMARY KEY, " +
				"user_id TEXT NOT NULL, " +
				"client_id TEXT NOT NULL, " +
				"granted_scopes " + js + " NOT NULL, " +
				"request " + js + ", " +
				"granted_at " + ts + " NOT NULL, " +
				"authenticated_at " + ts + ", " +
				"expires_at " + ts + " NOT NULL, " +
				"additional_state " + js + ", " +
				"metadata " + blob + ", " +
				"encrypted_metadata " + blob + ", " +
				"acr TEXT, " +
				"amr " + js + ", " +
				"version BIGINT NOT NULL CHECK (version > 0)" +
				")",
			"CREATE INDEX " + n.grantOwnerIndex + " ON " + n.grants + " (user_id, client_id, id)",
			"CREATE INDEX " + n.grantExpiryIdx + " ON " + n.grants + " (expires_at)",
			"CREATE TABLE " + n.authCodes + " (" +
				"id " + id + " PRIMARY KEY, " +
				"grant_id " + id + " NOT NULL REFERENCES " + n.grants + "(id) ON DELETE CASCADE, " +
				"code " + blob + " NOT NULL, " +
				"valid_until " + ts + " NOT NULL, " +
				"delete_after " + ts + " NOT NULL, " +
				"encrypted_grant_key " + blob + ", " +
				"version BIGINT NOT NULL CHECK (version > 0)" +
				")",
			"CREATE INDEX " + n.codeExpiryIdx + " ON " + n.authCodes + " (delete_after)",
			"CREATE INDEX " + n.codeGrantIdx + " ON " + n.authCodes + " (grant_id)",
			"CREATE TABLE " + n.refreshTokens + " (" +
				"id " + id + " PRIMARY KEY, " +
				"grant_id " + id + " NOT NULL REFERENCES " + n.grants + "(id) ON DELETE CASCADE, " +
				"token " + blob + " NOT NULL, " +
				"valid_until " + ts + " NOT NULL, " +
				"delete_after " + ts + " NOT NULL, " +
				"replaced_by_id " + id + ", " +
				"encrypted_grant_key " + blob + ", " +
				"version BIGINT NOT NULL CHECK (version > 0)" +
				")",
			"CREATE INDEX " + n.tokenExpiryIdx + " ON " + n.refreshTokens + " (delete_after)",
			"CREATE INDEX " + n.tokenGrantIdx + " ON " + n.refreshTokens + " (grant_id)",
			"CREATE TABLE " + n.refreshSessions + " (" +
				"grant_id " + id + " PRIMARY KEY REFERENCES " + n.grants + "(id) ON DELETE CASCADE, " +
				"expires_at " + ts + " NOT NULL, " +
				"last_used_at " + ts + " NOT NULL, " +
				"version BIGINT NOT NULL CHECK (version > 0)" +
				")",
			"CREATE INDEX " + n.sessionActive + " ON " + n.refreshSessions + " (expires_at, last_used_at, grant_id)",
		},
	}}
}

func jsonOf[T any](v *T) *sqlJSON[T] {
	return &sqlJSON[T]{v: v}
}

func jsonArray[T any](v *T) *sqlJSON[T] {
	return &sqlJSON[T]{v: v, emptyArray: true}
}

func nullOf[T ~string | ~[]byte](v *T) *sqlNull[T] {
	return &sqlNull[T]{v: v}
}

func (s *sqlStorage) timeOf(t *time.Time) *sqlTime {
	return &sqlTime{t: t, dialect: s.dialect}
}

func (s *sqlStorage) nullTime(t *time.Time) *sqlTime {
	return &sqlTime{t: t, dialect: s.dialect, nullable: true}
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

type sqlNull[T ~string | ~[]byte] struct {
	v *T
}

func (n *sqlNull[T]) Scan(src any) error {
	if n == nil || n.v == nil {
		return fmt.Errorf("oauth2as: null scan into nil")
	}
	if src == nil {
		var zero T
		*n.v = zero
		return nil
	}
	switch dest := any(n.v).(type) {
	case *string:
		switch v := src.(type) {
		case string:
			*dest = v
		case []byte:
			*dest = string(v)
		default:
			return fmt.Errorf("oauth2as: unsupported string type %T", src)
		}
	case *[]byte:
		switch v := src.(type) {
		case []byte:
			*dest = bytes.Clone(v)
		case string:
			*dest = []byte(v)
		default:
			return fmt.Errorf("oauth2as: unsupported bytes type %T", src)
		}
	default:
		return fmt.Errorf("oauth2as: unsupported null dest %T", n.v)
	}
	return nil
}

func (n *sqlNull[T]) Value() (driver.Value, error) {
	if n == nil || n.v == nil {
		return nil, nil
	}
	switch v := any(*n.v).(type) {
	case string:
		if v == "" {
			return nil, nil
		}
		return v, nil
	case []byte:
		if len(v) == 0 {
			return nil, nil
		}
		return v, nil
	default:
		return nil, fmt.Errorf("oauth2as: unsupported null type %T", *n.v)
	}
}

type sqlTime struct {
	t        *time.Time
	dialect  SQLDialect
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
	switch v := src.(type) {
	case time.Time:
		*t.t = v.UTC().Truncate(time.Microsecond)
		return nil
	case string:
		return t.parse(v)
	case []byte:
		return t.parse(string(v))
	default:
		return fmt.Errorf("oauth2as: unsupported time type %T", src)
	}
}

func (t *sqlTime) parse(value string) error {
	parsed, err := time.Parse(sqliteTimeFormat, value)
	if err != nil {
		parsed, err = time.Parse(time.RFC3339Nano, value)
		if err != nil {
			return err
		}
	}
	*t.t = parsed.UTC().Truncate(time.Microsecond)
	return nil
}

func (t *sqlTime) Value() (driver.Value, error) {
	if t == nil || t.t == nil || (t.nullable && t.t.IsZero()) {
		return nil, nil
	}
	tt := truncateTime(*t.t)
	if t.dialect == SQLDialectSQLite {
		return tt.Format(sqliteTimeFormat), nil
	}
	return tt, nil
}
