package oauth2as

import (
	"context"
	"errors"
)

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
