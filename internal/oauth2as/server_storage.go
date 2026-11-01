package oauth2as

import (
	"context"
	"errors"
	"fmt"
	"time"
	"uuid"

	"lds.li/passidp/internal/oauth2as/internal/token"
)

var (
	errGrantNotFound     = errors.New("grant not found")
	errGrantTokenInvalid = errors.New("grant token invalid")
	errGrantExpired      = errors.New("grant expired")
)

// loadedGrant holds a grant and the credential used to load it.
type loadedGrant struct {
	grant        *storedGrant
	authCode     *storedAuthCode
	refreshToken *storedRefreshToken
}

func (l *loadedGrant) dpopBound() bool {
	return l.grant.DPoPThumbprint != ""
}

func (s *Server) getGrantFromAuthCode(ctx context.Context, presentedCode string) (*loadedGrant, error) {
	codeID, err := token.Digest(presentedCode, token.AuthorizationCode)
	if err != nil {
		return nil, errGrantTokenInvalid
	}

	storedCode, grant, err := s.config.Storage.getAuthCodeAndGrant(ctx, codeID)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return nil, errGrantNotFound
		}
		return nil, fmt.Errorf("failed to get grant from auth code: %w", err)
	}

	// StorageExpiresAt is only a cleanup horizon; ValidUntil is the protocol
	// lifetime and must always be enforced by this package.
	now := s.now()
	if !storedCode.ValidUntil.After(now) || !storedCode.StorageExpiresAt.After(now) {
		return nil, errGrantExpired
	}

	if !grant.ExpiresAt.After(now) {
		return nil, errGrantExpired
	}

	loadedGrant := &loadedGrant{
		grant:    grant,
		authCode: storedCode,
	}

	return loadedGrant, nil
}

func (s *Server) getGrantFromRefreshToken(ctx context.Context, presentedToken string) (*loadedGrant, error) {
	tokenID, err := token.Digest(presentedToken, token.RefreshToken)
	if err != nil {
		return nil, errGrantTokenInvalid
	}

	storedToken, grant, err := s.config.Storage.getRefreshTokenAndGrant(ctx, tokenID)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return nil, errGrantNotFound
		}
		return nil, fmt.Errorf("failed to get grant from refresh token: %w", err)
	}

	// StorageExpiresAt is only a cleanup horizon. Refresh-token ValidUntil is
	// checked by the rotation flow because replaced tokens may remain usable
	// during their configured grace period.
	now := s.now()
	if !storedToken.StorageExpiresAt.After(now) {
		return nil, errGrantExpired
	}

	if !grant.ExpiresAt.After(now) {
		return nil, errGrantExpired
	}

	loadedGrant := &loadedGrant{
		grant:        grant,
		refreshToken: storedToken,
	}

	return loadedGrant, nil
}

// putGrantWithAuthCode creates the grant and auth code, returning grant ID and token string.
func (s *Server) putGrantWithAuthCode(ctx context.Context, loadedGrant *loadedGrant, codeExpiresAt time.Time) (grantID string, tokenString string, err error) {
	// Generate both IDs before writing so the grant and its authorization code
	// can be created in one atomic commit.
	grid := uuid.NewV4().String()
	raw, cid := token.New(token.AuthorizationCode)

	storedCode := &storedAuthCode{
		ID:               cid,
		GrantID:          grid,
		ValidUntil:       codeExpiresAt,
		StorageExpiresAt: loadedGrant.grant.ExpiresAt, // Keep code around as long as the grant
	}
	loadedGrant.grant.ID = grid
	if err := s.config.Storage.createGrantWithAuthCode(ctx, loadedGrant.grant, storedCode); err != nil {
		return "", "", fmt.Errorf("create grant and authorization code: %w", err)
	}
	loadedGrant.grant.storageVersion = 1

	return grid, raw, nil
}

// prepareRefreshToken creates the opaque token and its storage record without
// writing either the token or grant. The caller commits all related changes as
// one transaction after the response has been successfully built.
func prepareRefreshToken(grant *storedGrant, tokenExpiresAt time.Time) (string, *storedRefreshToken) {
	raw, id := token.New(token.RefreshToken)
	return raw, &storedRefreshToken{
		ID:               id,
		GrantID:          grant.ID,
		ValidUntil:       tokenExpiresAt,
		StorageExpiresAt: grant.ExpiresAt, // Keep consumed digests for replay detection.
	}
}
