package oauth2as

import (
	"context"
	"encoding/json"
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

// grantLoader is an interface that represents a loaded grant, regardless of
// how it was loaded (auth code or refresh token).
type grantLoader interface {
	Grant() *storedGrant
	GrantID() string
	AdditionalState() *storedAdditionalState
	SetAdditionalState(storedAdditionalState)
}

// loadedAuthCodeGrant represents a grant loaded via an authorization code.
// Auth codes are single use.
type loadedAuthCodeGrant struct {
	grant    *storedGrant
	grantID  string
	authCode *storedAuthCode

	additionalState storedAdditionalState
}

func (l *loadedAuthCodeGrant) Grant() *storedGrant { return l.grant }
func (l *loadedAuthCodeGrant) GrantID() string     { return l.grantID }
func (l *loadedAuthCodeGrant) AdditionalState() *storedAdditionalState {
	return &l.additionalState
}
func (l *loadedAuthCodeGrant) SetAdditionalState(state storedAdditionalState) {
	l.additionalState = state
}

// loadedRefreshTokenGrant represents a grant loaded via a refresh token.
// Refresh tokens support rotation and grace periods.
type loadedRefreshTokenGrant struct {
	grant        *storedGrant
	grantID      string
	refreshToken *storedRefreshToken

	additionalState storedAdditionalState
}

func (l *loadedRefreshTokenGrant) Grant() *storedGrant { return l.grant }
func (l *loadedRefreshTokenGrant) GrantID() string     { return l.grantID }
func (l *loadedRefreshTokenGrant) AdditionalState() *storedAdditionalState {
	return &l.additionalState
}
func (l *loadedRefreshTokenGrant) SetAdditionalState(state storedAdditionalState) {
	l.additionalState = state
}

func (s *Server) getGrantFromAuthCode(ctx context.Context, presentedCode string) (*loadedAuthCodeGrant, error) {
	parsedCode, err := token.ParseUserToken(presentedCode, tokenUsageAuthCode)
	if err != nil {
		return nil, errGrantTokenInvalid
	}

	storedCode, grant, err := s.config.Storage.getAuthCodeAndGrant(ctx, parsedCode.ID())
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

	_, err = parsedCode.Verify(storedCode.Code, storedCode.GrantID, grant.UserID)
	if err != nil {
		return nil, errGrantTokenInvalid
	}

	loadedGrant := &loadedAuthCodeGrant{
		grant:    grant,
		grantID:  storedCode.GrantID,
		authCode: storedCode,
	}

	if len(grant.AdditionalState) > 0 {
		if err := json.Unmarshal(grant.AdditionalState, &loadedGrant.additionalState); err != nil {
			return nil, fmt.Errorf("failed to unmarshal additional state: %w", err)
		}
	}

	return loadedGrant, nil
}

func (s *Server) getGrantFromRefreshToken(ctx context.Context, presentedToken string) (*loadedRefreshTokenGrant, error) {
	parsedToken, err := token.ParseUserToken(presentedToken, tokenUsageRefresh)
	if err != nil {
		return nil, errGrantTokenInvalid
	}

	storedToken, grant, err := s.config.Storage.getRefreshTokenAndGrant(ctx, parsedToken.ID())
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

	_, err = parsedToken.Verify(storedToken.Token, storedToken.GrantID, grant.UserID)
	if err != nil {
		return nil, errGrantTokenInvalid
	}

	loadedGrant := &loadedRefreshTokenGrant{
		grant:        grant,
		grantID:      storedToken.GrantID,
		refreshToken: storedToken,
	}

	if len(grant.AdditionalState) > 0 {
		if err := json.Unmarshal(grant.AdditionalState, &loadedGrant.additionalState); err != nil {
			return nil, fmt.Errorf("failed to unmarshal additional state: %w", err)
		}
	}

	return loadedGrant, nil
}

// putGrantWithAuthCode creates the grant and auth code, returning grant ID and token string.
func (s *Server) putGrantWithAuthCode(ctx context.Context, loadedGrant *loadedAuthCodeGrant, codeExpiresAt time.Time) (grantID string, tokenString string, err error) {
	addlb, err := json.Marshal(loadedGrant.additionalState)
	if err != nil {
		return "", "", fmt.Errorf("failed to marshal additional state: %w", err)
	}
	loadedGrant.grant.AdditionalState = addlb

	// Generate both IDs before writing so the grant and its authorization code
	// can be created in one atomic commit.
	grid := uuid.NewV4().String()
	cid := uuid.NewV4().String()
	tok, err := token.New(tokenUsageAuthCode, cid, grid, loadedGrant.grant.UserID)
	if err != nil {
		return "", "", fmt.Errorf("failed to generate authorization code: %w", err)
	}

	storedCode := &storedAuthCode{
		ID:               cid,
		GrantID:          grid,
		Code:             tok.Stored(),
		ValidUntil:       codeExpiresAt,
		StorageExpiresAt: loadedGrant.grant.ExpiresAt, // Keep code around as long as the grant

	}
	loadedGrant.grant.ID = grid
	if err := s.config.Storage.commit(ctx, storageCommit{
		Checks: []storageCheck{
			{Kind: storageKindGrant, ID: grid},
			{Kind: storageKindAuthCode, ID: cid},
		},
		Grants:    []storedGrant{*loadedGrant.grant},
		AuthCodes: []storedAuthCode{*storedCode},
	}); err != nil {
		return "", "", fmt.Errorf("create grant and authorization code: %w", err)
	}
	loadedGrant.grant.storageVersion = 1
	storedCode.storageVersion = 1

	return grid, tok.UserToken(), nil
}

// prepareRefreshToken creates the opaque token and its storage record without
// writing either the token or grant. The caller commits all related changes as
// one conditional batch after the response has been successfully built.
func prepareRefreshToken(loadedGrant *loadedRefreshTokenGrant, tokenExpiresAt time.Time) (tokenString string, tokenID string, storedToken *storedRefreshToken, err error) {
	addlb, err := json.Marshal(loadedGrant.additionalState)
	if err != nil {
		return "", "", nil, fmt.Errorf("failed to marshal additional state: %w", err)
	}
	loadedGrant.grant.AdditionalState = addlb

	if loadedGrant.grantID == "" {
		return "", "", nil, fmt.Errorf("grant ID is required")
	}
	tid := uuid.NewV4().String()
	tok, err := token.New(tokenUsageRefresh, tid, loadedGrant.grantID, loadedGrant.grant.UserID)
	if err != nil {
		return "", "", nil, fmt.Errorf("failed to generate refresh token: %w", err)
	}

	storedToken = &storedRefreshToken{
		GrantID:          loadedGrant.grantID,
		Token:            tok.Stored(),
		ValidUntil:       tokenExpiresAt,
		StorageExpiresAt: loadedGrant.grant.ExpiresAt, // Keep token around as long as the grant

	}
	return tok.UserToken(), tid, storedToken, nil
}
