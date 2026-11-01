package oauth2as

import (
	"context"
	"database/sql"
	"errors"

	"lds.li/passidp/internal/storage/dbsql"
)

// Table names used by tests that inspect storage directly.
const (
	tblGrants          = "oauth2as_grants"
	tblAuthCodes       = "oauth2as_authorization_codes"
	tblRefreshTokens   = "oauth2as_refresh_tokens"
	tblRefreshSessions = "oauth2as_refresh_sessions"
)

// storageFixtures groups related fixture records for test setup.
type storageFixtures struct {
	Grants        []storedGrant
	AuthCodes     []storedAuthCode
	RefreshTokens []storedRefreshToken
	Sessions      []storedRefreshSession
}

// seed creates or edits fixture records. Existing rows are updated in place,
// so tests can move records into states the server never writes itself.
func (s *Storage) seed(ctx context.Context, fixtures storageFixtures) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	q := dbsql.New(tx)

	for _, grant := range fixtures.Grants {
		var version int64
		err := tx.QueryRowContext(ctx, `SELECT version FROM oauth2as_grants WHERE id = ?`, grant.ID).Scan(&version)
		if errors.Is(err, sql.ErrNoRows) {
			if err := insertGrant(ctx, q, grant); err != nil {
				return err
			}
			continue
		} else if err != nil {
			return err
		}
		if grant.storageVersion == 0 {
			grant.storageVersion = uint64(version)
		}
		if err := updateGrantFixture(ctx, tx, grant); err != nil {
			return err
		}
	}
	for _, code := range fixtures.AuthCodes {
		res, err := tx.ExecContext(ctx, `UPDATE oauth2as_authorization_codes SET grant_id = ?, valid_until = ?, delete_after = ? WHERE id = ?`,
			code.GrantID, code.ValidUntil.UnixMicro(), code.StorageExpiresAt.UnixMicro(), code.ID)
		if err != nil {
			return err
		}
		if n, err := res.RowsAffected(); err != nil {
			return err
		} else if n == 0 {
			if err := insertAuthCode(ctx, q, code); err != nil {
				return err
			}
		}
	}
	for _, token := range fixtures.RefreshTokens {
		rows, err := q.UpdateOAuthRefreshToken(ctx, dbsql.UpdateOAuthRefreshTokenParams{
			ID: token.ID, GrantID: token.GrantID, ValidUntil: token.ValidUntil.UnixMicro(),
			DeleteAfter: token.StorageExpiresAt.UnixMicro(), ReplacedByID: token.ReplacedByTokenID,
		})
		if err != nil {
			return err
		}
		if rows == 0 {
			if err := insertRefreshToken(ctx, q, token); err != nil {
				return err
			}
		}
	}
	for _, session := range fixtures.Sessions {
		if err := q.UpsertOAuthRefreshSession(ctx, dbsql.UpsertOAuthRefreshSessionParams{GrantID: session.GrantID, ExpiresAt: session.ExpiresAt.UnixMicro(), LastUsedAt: session.LastUsedAt.UnixMicro()}); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func updateGrantFixture(ctx context.Context, tx *sql.Tx, value storedGrant) error {
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
	res, err := tx.ExecContext(ctx, `UPDATE oauth2as_grants SET user_id = ?, client_id = ?, granted_scopes = ?, redirect_uri = ?,
		code_challenge = ?, nonce = ?, max_age = ?, granted_at = ?, authenticated_at = ?, expires_at = ?,
		dpop_thumbprint = ?, acr = ?, amr = ?, version = version + 1
		WHERE id = ? AND version = ?`,
		value.UserID, value.ClientID, scopes, value.RedirectURI,
		value.CodeChallenge, value.Nonce, age, value.GrantedAt.UnixMicro(), nullTime(value.AuthenticatedAt), value.ExpiresAt.UnixMicro(),
		value.DPoPThumbprint, value.ACR, amr,
		value.ID, int64(value.storageVersion))
	if err != nil {
		return err
	}
	if n, err := res.RowsAffected(); err != nil {
		return err
	} else if n != 1 {
		return errStorageConflict
	}
	return nil
}

func (s *Storage) getAuthCode(ctx context.Context, id string) (*storedAuthCode, error) {
	var grantID string
	var validUntil, deleteAfter int64
	var consumedAt sql.NullInt64
	err := s.db.QueryRowContext(ctx, `SELECT grant_id, valid_until, delete_after, consumed_at FROM oauth2as_authorization_codes WHERE id = ?`, id).
		Scan(&grantID, &validUntil, &deleteAfter, &consumedAt)
	if err != nil {
		return nil, storageReadError(err)
	}
	return &storedAuthCode{ID: id, GrantID: grantID, ValidUntil: timeFromMicros(validUntil),
		StorageExpiresAt: timeFromMicros(deleteAfter), Consumed: consumedAt.Valid}, nil
}

func (s *Storage) getRefreshToken(ctx context.Context, id string) (*storedRefreshToken, error) {
	var grantID, replacedBy string
	var validUntil, deleteAfter int64
	err := s.db.QueryRowContext(ctx, `SELECT grant_id, valid_until, delete_after, replaced_by_id FROM oauth2as_refresh_tokens WHERE id = ?`, id).
		Scan(&grantID, &validUntil, &deleteAfter, &replacedBy)
	if err != nil {
		return nil, storageReadError(err)
	}
	return &storedRefreshToken{ID: id, GrantID: grantID, ValidUntil: timeFromMicros(validUntil),
		StorageExpiresAt: timeFromMicros(deleteAfter), ReplacedByTokenID: replacedBy}, nil
}
