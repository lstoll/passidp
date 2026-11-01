package oauth2as

import (
	"context"

	"lds.li/passidp/internal/storage/dbsql"
)

func (s *Storage) expireGrant(ctx context.Context, id string) error {
	return dbsql.New(s.db).DeleteOAuthGrant(ctx, id)
}

// Read each credential and its grant in one statement so their revisions agree.
func (s *Storage) getAuthCodeAndGrant(ctx context.Context, id string) (*storedAuthCode, *storedGrant, error) {
	row, err := dbsql.New(s.db).GetOAuthAuthCodeAndGrant(ctx, id)
	if err != nil {
		return nil, nil, storageReadError(err)
	}
	grant, err := decodeGrant(row.Oauth2asGrant)
	if err != nil {
		return nil, nil, err
	}
	code := row.Oauth2asAuthorizationCode
	return &storedAuthCode{ID: code.ID, GrantID: code.GrantID, ValidUntil: timeFromMicros(code.ValidUntil),
		StorageExpiresAt: timeFromMicros(code.DeleteAfter), Consumed: code.ConsumedAt.Valid}, grant, nil
}

func (s *Storage) getRefreshTokenAndGrant(ctx context.Context, id string) (*storedRefreshToken, *storedGrant, error) {
	row, err := dbsql.New(s.db).GetOAuthRefreshTokenAndGrant(ctx, id)
	if err != nil {
		return nil, nil, storageReadError(err)
	}
	grant, err := decodeGrant(row.Oauth2asGrant)
	if err != nil {
		return nil, nil, err
	}
	token := row.Oauth2asRefreshToken
	return &storedRefreshToken{ID: token.ID, GrantID: token.GrantID, ValidUntil: timeFromMicros(token.ValidUntil), StorageExpiresAt: timeFromMicros(token.DeleteAfter), ReplacedByTokenID: token.ReplacedByID}, grant, nil
}
