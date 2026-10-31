package oauth2as

import (
	"context"

	"uuid"
)

// These convenience methods are used by package tests to create records
// directly without reproducing the storage commit setup at each call site.
func (s *Storage) createGrant(ctx context.Context, grant *storedGrant) (string, error) {
	id := uuid.NewV4().String()
	grant.ID = id
	if err := s.commit(ctx, storageCommit{
		Checks: []storageCheck{{Kind: storageKindGrant, ID: id}},
		Grants: []storedGrant{*grant},
	}); err != nil {
		return "", err
	}
	grant.storageVersion = 1
	return id, nil
}

func (s *Storage) updateGrant(ctx context.Context, id string, grant *storedGrant) error {
	grant.ID = id
	if err := s.commit(ctx, storageCommit{
		Checks: []storageCheck{{Kind: storageKindGrant, ID: id, Version: grant.storageVersion}},
		Grants: []storedGrant{*grant},
	}); err != nil {
		return err
	}
	grant.storageVersion++
	return nil
}

func (s *Storage) createAuthCode(ctx context.Context, id string, code *storedAuthCode) error {
	code.ID = id
	err := s.commit(ctx, storageCommit{
		Checks:    []storageCheck{{Kind: storageKindAuthCode, ID: id}},
		AuthCodes: []storedAuthCode{*code},
	})
	if err == nil {
		code.storageVersion = 1
	}
	return err
}

func (s *Storage) createRefreshToken(ctx context.Context, id string, token *storedRefreshToken) error {
	token.ID = id
	err := s.commit(ctx, storageCommit{
		Checks:        []storageCheck{{Kind: storageKindRefreshToken, ID: id}},
		RefreshTokens: []storedRefreshToken{*token},
	})
	if err == nil {
		token.storageVersion = 1
	}
	return err
}
