package oauth2as

import (
	"context"
	"errors"
	"uuid"
)

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

func (s *Storage) expireGrant(ctx context.Context, id string) error {
	grant, err := s.getGrant(ctx, id)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return nil
		}
		return err
	}
	return s.commit(ctx, storageCommit{
		Checks:  []storageCheck{{Kind: storageKindGrant, ID: id, Version: grant.storageVersion}},
		Deletes: []storageRef{{Kind: storageKindGrant, ID: id}},
	})
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

func (s *Storage) getAuthCodeAndGrant(ctx context.Context, id string) (*storedAuthCode, *storedGrant, error) {
	code, err := s.getAuthCode(ctx, id)
	if err != nil {
		return nil, nil, err
	}
	grant, err := s.getGrant(ctx, code.GrantID)
	if err != nil {
		return nil, nil, err
	}
	return code, grant, nil
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

func (s *Storage) getRefreshTokenAndGrant(ctx context.Context, id string) (*storedRefreshToken, *storedGrant, error) {
	token, err := s.getRefreshToken(ctx, id)
	if err != nil {
		return nil, nil, err
	}
	grant, err := s.getGrant(ctx, token.GrantID)
	if err != nil {
		return nil, nil, err
	}
	return token, grant, nil
}

func tokenResponseCommit(grant *storedGrant, prepared *preparedTokenResponse) storageCommit {
	commit := storageCommit{Grants: []storedGrant{*grant}}
	if prepared.refreshToken != nil {
		token := *prepared.refreshToken
		token.ID = prepared.refreshTokenID
		session := *prepared.refreshSession
		commit.RefreshTokens = append(commit.RefreshTokens, token)
		commit.Sessions = append(commit.Sessions, session)
		commit.Checks = append(commit.Checks, storageCheck{Kind: storageKindRefreshToken, ID: token.ID})
	}
	return commit
}
