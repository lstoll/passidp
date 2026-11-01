package oauth2as

import (
	"context"

	"uuid"
)

// These convenience methods are used by package tests to create records
// directly without repeating fixture setup at each call site.
func (s *Storage) createGrant(ctx context.Context, grant *storedGrant) (string, error) {
	id := uuid.NewV4().String()
	grant.ID = id
	if err := s.seed(ctx, storageFixtures{
		Grants: []storedGrant{*grant},
	}); err != nil {
		return "", err
	}
	grant.storageVersion = 1
	return id, nil
}

func (s *Storage) updateGrant(ctx context.Context, id string, grant *storedGrant) error {
	grant.ID = id
	if err := s.seed(ctx, storageFixtures{
		Grants: []storedGrant{*grant},
	}); err != nil {
		return err
	}
	grant.storageVersion++
	return nil
}

func (s *Storage) createAuthCode(ctx context.Context, id string, code *storedAuthCode) error {
	code.ID = id
	return s.seed(ctx, storageFixtures{
		AuthCodes: []storedAuthCode{*code},
	})
}

func (s *Storage) createRefreshToken(ctx context.Context, id string, token *storedRefreshToken) error {
	token.ID = id
	return s.seed(ctx, storageFixtures{
		RefreshTokens: []storedRefreshToken{*token},
	})
}
