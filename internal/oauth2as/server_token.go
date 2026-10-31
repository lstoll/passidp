package oauth2as

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"
	"uuid"

	"lds.li/oauth2ext/dpop"
	"lds.li/oauth2ext/jwt"
	"lds.li/oauth2ext/oidc"
	"lds.li/passidp/internal/oauth2as/oauth2proto"
)

const (
	claimGrantID = "grid"
)

type TokenHandler func(_ context.Context, req *TokenRequest) (*TokenResponse, error)

// IDTokenClaims contains application-selected identity claims. The server
// constructs the token envelope and binding claims.
type IDTokenClaims struct {
	Subject    string
	Additional map[string]any
}

// AccessTokenClaims contains application-selected authorization claims. The
// server constructs the token envelope and binding claims.
type AccessTokenClaims struct {
	Subject    string
	Audiences  []string
	Scopes     []string
	Additional map[string]any
}

// TokenRequest encapsulates the information from the initial request to the token
// endpoint. This is passed to the handler, to generate an appropriate response.
type TokenRequest struct {
	// Client is the authenticated client snapshot for this request. It is never persisted.
	Client *Client
	// GrantID is the ID of the grant that was used to obtain the token.
	GrantID string
	// UserID is the user ID that was granted access.
	UserID string
	// ClientID is the client ID that was used to obtain the token.
	ClientID string
	// GrantedScopes are the scopes that were granted.
	GrantedScopes []string
	// ACR is the Authentication Context Class Reference satisfied for this grant.
	ACR string
	// AMR lists the Authentication Methods References for this grant.
	AMR []string
	// AuthenticatedAt is when the End-User last actively authenticated.
	AuthenticatedAt time.Time
	// MaxAge is the max_age from the original authorization request, if any.
	MaxAge *int

	// IsRefresh indicates if this is a refresh token request.
	IsRefresh bool

	// DPoPBound indicates whether this grant is bound to a DPoP key. If true,
	// all token requests for this grant must include a valid DPoP proof.
	DPoPBound bool
	// DPoPProof includes the verified DPoP proof, if present.
	DPoPProof *dpop.Proof
}

// TokenResponse is returned by the token endpoint handler, indicating what it
// should actually return to the user.
type TokenResponse struct {
	// If zero, the configured default validity is used.
	IDTokenExpiry     time.Time
	AccessTokenExpiry time.Time

	// IDTokenClaims contains application-selected claims. Additional is for
	// custom claims and must not contain a server-managed or typed claim name.
	IDTokenClaims *IDTokenClaims
	// AccessTokenClaims contains application-selected claims. Additional is for
	// custom claims and must not contain a server-managed or typed claim name.
	AccessTokenClaims *AccessTokenClaims

	// RefreshTokenValidUntil indicates how long the returned refresh token should
	// be valid for, if one is issued. If zero, the default will be used.
	RefreshTokenValidUntil time.Time
}

// TokenHandler is used to handle the access token endpoint for code flow
// requests. This can handle both the initial access token request, as well as
// subsequent calls for refreshes.
//
// If a handler returns an error, it will be checked and the endpoint will
// respond to the user appropriately. The session will not be invalidated
// automatically, it it the responsibility of the handler to delete if it
// requires this. * If the error implements an `Unauthorized() bool` method and
// the result of calling this is true, the caller will be notified of an
// `invalid_grant`. The error text will be returned as the `error_description` *
// All other errors will result an an InternalServerError
//
// This will always return a response to the user, regardless of success or
// failure. As such, once returned the called can assume the HTTP request has
// been dealt with appropriately
//
// https://openid.net/specs/openid-connect-core-1_0.html#TokenEndpoint
// https://openid.net/specs/openid-connect-core-1_0.html#RefreshTokens
func (s *Server) TokenHandler(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}

	treq, err := oauth2proto.ParseTokenRequest(req)
	if err != nil {
		_ = oauth2proto.WriteError(w, req, err)
		return
	}

	var resp *oauth2proto.TokenResponse
	switch treq.GrantType {
	case oauth2proto.GrantTypeAuthorizationCode:
		resp, err = s.codeToken(req.Context(), req, treq)
	case oauth2proto.GrantTypeRefreshToken:
		resp, err = s.refreshToken(req.Context(), req, treq)
	default:
		err = &oauth2proto.TokenError{ErrorCode: oauth2proto.TokenErrorCodeInvalidGrant, Description: "invalid grant type", Cause: fmt.Errorf("grant type %s not handled", treq.GrantType)}
	}
	if err != nil {
		s.logger.WarnContext(req.Context(), "error in token handler", "grant-type", treq.GrantType, "err", err)
		_ = oauth2proto.WriteError(w, req, err)
		return
	}

	if err := oauth2proto.WriteTokenResponse(w, resp); err != nil {
		s.logger.ErrorContext(req.Context(), "error writing token response", "grant-type", treq.GrantType, "err", err)
		_ = oauth2proto.WriteError(w, req, err)
		return
	}
}

func (s *Server) codeToken(ctx context.Context, req *http.Request, treq *oauth2proto.TokenRequest) (*oauth2proto.TokenResponse, error) {
	if treq.Code == "" {
		return nil, &oauth2proto.TokenError{ErrorCode: oauth2proto.TokenErrorCodeInvalidRequest, Description: "code is required"}
	}

	loadedGrant, err := s.getGrantFromAuthCode(ctx, treq.Code)
	if err != nil {
		if errors.Is(err, errGrantTokenInvalid) {
			return nil, &oauth2proto.TokenError{ErrorCode: oauth2proto.TokenErrorCodeInvalidGrant, Description: "invalid code"}
		} else if errors.Is(err, errGrantExpired) {
			return nil, &oauth2proto.TokenError{ErrorCode: oauth2proto.TokenErrorCodeInvalidGrant, Description: "invalid code"}
		} else if errors.Is(err, errGrantNotFound) {
			return nil, &oauth2proto.TokenError{ErrorCode: oauth2proto.TokenErrorCodeInvalidGrant, Description: "invalid code"}
		}
		return nil, fmt.Errorf("failed to get grant by auth code: %w", err)
	}

	// Validate that the redirect_uri matches the one from the authorization request
	if treq.RedirectURI != loadedGrant.grant.RedirectURI {
		return nil, &oauth2proto.TokenError{ErrorCode: oauth2proto.TokenErrorCodeInvalidGrant, Description: "redirect URI mismatch"}
	}

	client, err := s.validateTokenClient(ctx, treq, loadedGrant.grant.ClientID)
	if err != nil {
		return nil, err
	}

	// Reject if PKCE is required but no code verifier was provided
	if !client.SkipPKCE && treq.CodeVerifier == "" {
		return nil, &oauth2proto.TokenError{ErrorCode: oauth2proto.TokenErrorCodeUnauthorizedClient, Description: "PKCE required, but code verifier not passed"}
	}

	// Verify the code verifier against the session data
	if treq.CodeVerifier != "" {
		if !verifyCodeChallenge(treq.CodeVerifier, loadedGrant.grant.CodeChallenge) {
			return nil, &oauth2proto.TokenError{ErrorCode: oauth2proto.TokenErrorCodeUnauthorizedClient, Description: "PKCE verification failed"}
		}
	}

	// Verify DPoP only after validating the code, client, redirect URI, and
	// PKCE. Otherwise unauthenticated invalid-code requests could fill the
	// bounded replay cache. Recording still occurs before handlers or storage
	// mutations, so a valid proof is consumed even if later work fails.
	dpopProof, err := s.verifyDPoPProof(s.config.Issuer, req, nil, "")
	if err != nil {
		if errors.Is(err, dpop.ErrProofReplay) {
			return nil, invalidDPoPProofError(err)
		}
		return nil, err
	}
	var dpopThumbprint string
	if dpopProof != nil {
		dpopThumbprint = dpopProof.Thumbprint
	}

	// Update the grant with DPoP thumbprint if present
	if dpopThumbprint != "" {
		loadedGrant.grant.DPoPThumbprint = dpopThumbprint
	}

	prepared, err := s.prepareTokenResponse(ctx, client, loadedGrant, false, dpopProof)
	if err != nil {
		return nil, err
	}

	commit := tokenResponseCommit(loadedGrant.grant, prepared)
	commit.Checks = append(commit.Checks,
		storageCheck{Kind: storageKindAuthCode, ID: loadedGrant.authCode.ID, Version: loadedGrant.authCode.storageVersion},
		storageCheck{Kind: storageKindGrant, ID: loadedGrant.grant.ID, Version: loadedGrant.grant.storageVersion},
	)
	commit.Deletes = append(commit.Deletes, storageRef{Kind: storageKindAuthCode, ID: loadedGrant.authCode.ID})
	if err := s.config.Storage.commit(ctx, commit); err != nil {
		if errors.Is(err, errStorageConflict) {
			return nil, &oauth2proto.TokenError{ErrorCode: oauth2proto.TokenErrorCodeInvalidGrant, Description: "authorization code already used"}
		}
		return nil, fmt.Errorf("committing authorization code exchange: %w", err)
	}
	return prepared.response, nil
}

func (s *Server) refreshToken(ctx context.Context, req *http.Request, treq *oauth2proto.TokenRequest) (_ *oauth2proto.TokenResponse, retErr error) {
	if treq.RefreshToken == "" {
		return nil, &oauth2proto.TokenError{ErrorCode: oauth2proto.TokenErrorCodeInvalidRequest, Description: "refresh token is required"}
	}

	loadedGrant, err := s.getGrantFromRefreshToken(ctx, treq.RefreshToken)
	if err != nil {
		if errors.Is(err, errGrantTokenInvalid) {
			return nil, &oauth2proto.TokenError{ErrorCode: oauth2proto.TokenErrorCodeInvalidGrant, Description: "invalid refresh token"}
		} else if errors.Is(err, errGrantExpired) {
			return nil, &oauth2proto.TokenError{ErrorCode: oauth2proto.TokenErrorCodeInvalidGrant, Description: "invalid refresh token"}
		} else if errors.Is(err, errGrantNotFound) {
			return nil, &oauth2proto.TokenError{ErrorCode: oauth2proto.TokenErrorCodeInvalidGrant, Description: "invalid refresh token"}
		}
		return nil, fmt.Errorf("failed to get grant by refresh token: %w", err)
	}

	client, err := s.validateTokenClient(ctx, treq, loadedGrant.grant.ClientID)
	if err != nil {
		return nil, err
	}

	replacedTokenID := loadedGrant.refreshToken.ReplacedByTokenID

	// Enforce DPoP binding if the grant was initiated with DPoP
	storedThumbprint := loadedGrant.grant.DPoPThumbprint

	var dpopProof *dpop.Proof
	if storedThumbprint != "" {
		dpopProof, err = s.verifyDPoPProof(s.config.Issuer, req, &storedThumbprint, "")
		if err != nil {
			if errors.Is(err, dpop.ErrProofReplay) {
				return nil, invalidDPoPProofError(err)
			}
			return nil, &oauth2proto.TokenError{ErrorCode: oauth2proto.TokenErrorCodeInvalidGrant, Description: "DPoP proof key mismatch"}
		}
		if dpopProof == nil || dpopProof.Thumbprint == "" {
			return nil, &oauth2proto.TokenError{ErrorCode: oauth2proto.TokenErrorCodeInvalidGrant, Description: "DPoP proof required"}
		}
	}

	// Authenticate the client and sender before reuse detection can revoke the grant.
	// ValidUntil on a replaced token is the end of its grace period.
	if !loadedGrant.refreshToken.ValidUntil.After(s.now()) {
		if loadedGrant.refreshToken.ReplacedByTokenID != "" {
			// Token is expired AND replaced. This means it was used, rotated,
			// and the grace period has passed. This is a likely replay/theft.
			if err := s.config.Storage.expireGrant(ctx, loadedGrant.grant.ID); err != nil {
				return nil, fmt.Errorf("failed to revoke grant on refresh token reuse: %w", err)
			}
			return nil, &oauth2proto.TokenError{ErrorCode: oauth2proto.TokenErrorCodeInvalidGrant, Description: "invalid refresh token"}
		}
		// Token is expired but not replaced. Just a normal expiration.
		return nil, &oauth2proto.TokenError{ErrorCode: oauth2proto.TokenErrorCodeInvalidGrant, Description: "invalid refresh token"}
	}

	prepared, err := s.prepareTokenResponse(ctx, client, loadedGrant, true, dpopProof)
	if err != nil {
		return nil, err
	}

	commit := tokenResponseCommit(loadedGrant.grant, prepared)
	commit.Checks = append(commit.Checks,
		storageCheck{Kind: storageKindGrant, ID: loadedGrant.grant.ID, Version: loadedGrant.grant.storageVersion},
		storageCheck{Kind: storageKindRefreshToken, ID: loadedGrant.refreshToken.ID, Version: loadedGrant.refreshToken.storageVersion},
	)
	if replacedTokenID != "" {
		commit.Deletes = append(commit.Deletes, storageRef{Kind: storageKindRefreshToken, ID: replacedTokenID})
	}
	if prepared.refreshToken == nil {
		commit.Deletes = append(commit.Deletes, storageRef{Kind: storageKindRefreshToken, ID: loadedGrant.refreshToken.ID})
		commit.Deletes = append(commit.Deletes, storageRef{Kind: storageKindSession, ID: loadedGrant.grant.ID})
	} else {
		// Retain consumed tokens through the grant lifetime, including with no
		// grace period, so later reuse can revoke the active replacement.
		if replacedTokenID == "" {
			loadedGrant.refreshToken.ValidUntil = s.now().Add(s.config.RefreshTokenRotationGracePeriod)
		}
		loadedGrant.refreshToken.ReplacedByTokenID = prepared.refreshToken.ID
		commit.RefreshTokens = append(commit.RefreshTokens, *loadedGrant.refreshToken)
	}

	if err := s.config.Storage.commit(ctx, commit); err != nil {
		if errors.Is(err, errStorageConflict) {
			return nil, &oauth2proto.TokenError{ErrorCode: oauth2proto.TokenErrorCodeInvalidGrant, Description: "refresh token already used"}
		}
		return nil, fmt.Errorf("committing refresh token rotation: %w", err)
	}
	return prepared.response, nil
}

// prepareTokenResponse invokes application policy and signs the response before any commit.
func (s *Server) prepareTokenResponse(ctx context.Context, client *Client, loaded *loadedGrant, isRefresh bool, proof *dpop.Proof) (*preparedTokenResponse, error) {
	grant := loaded.grant
	bound := loaded.dpopBound()
	response, err := s.config.TokenHandler(ctx, &TokenRequest{
		Client:          client,
		GrantID:         grant.ID,
		UserID:          grant.UserID,
		ClientID:        grant.ClientID,
		GrantedScopes:   slices.Clone(grant.GrantedScopes),
		ACR:             grant.ACR,
		AMR:             slices.Clone(grant.AMR),
		AuthenticatedAt: authTimeFromGrant(grant),
		MaxAge:          maxAgeFromGrant(grant),
		IsRefresh:       isRefresh,
		DPoPBound:       bound,
		DPoPProof:       proof,
	})
	if err != nil {
		var unauthorized unauthorizedErr
		if errors.As(err, &unauthorized) && unauthorized.Unauthorized() {
			return nil, &oauth2proto.TokenError{ErrorCode: oauth2proto.TokenErrorCodeInvalidGrant, Description: unauthorized.Error()}
		}
		return nil, &oauth2proto.HTTPError{Code: http.StatusInternalServerError, Message: "internal error", CauseMsg: "handler returned error", Cause: err}
	}
	algorithm := s.defaultIDTokenSigningAlgorithm()
	if client.IDTokenSigningAlgorithm != "" {
		algorithm = client.IDTokenSigningAlgorithm
	}
	return s.buildTokenResponse(ctx, algorithm, loaded, response, bound)
}

func invalidDPoPProofError(cause error) *oauth2proto.TokenError {
	return &oauth2proto.TokenError{ErrorCode: oauth2proto.TokenErrorCodeInvalidDPoPProof, Description: "invalid DPoP proof", Cause: cause}
}

type preparedTokenResponse struct {
	response       *oauth2proto.TokenResponse
	refreshToken   *storedRefreshToken
	refreshSession *storedRefreshSession
}

// buildTokenResponse creates and signs the complete response without changing
// storage. The caller atomically commits the prepared grant and token records.
func (s *Server) buildTokenResponse(ctx context.Context, idTokenAlgorithm jwt.Algorithm, loadedGrant *loadedGrant, tresp *TokenResponse, isDPoPBound bool) (*preparedTokenResponse, error) {
	var refreshToken string
	var storedRefreshToken *storedRefreshToken
	var refreshSession *storedRefreshSession
	if s.config.RefreshTokenValidity > 0 && slices.Contains(loadedGrant.grant.GrantedScopes, oidc.ScopeOfflineAccess) {
		rtUntil := tresp.RefreshTokenValidUntil
		if rtUntil.IsZero() {
			rtUntil = s.now().Add(s.config.RefreshTokenValidity)
		}

		// Cap the refresh token expiry at the grant's absolute expiration
		if rtUntil.After(loadedGrant.grant.ExpiresAt) {
			rtUntil = loadedGrant.grant.ExpiresAt
		}

		refreshToken, storedRefreshToken = prepareRefreshToken(loadedGrant.grant, rtUntil)
		grant := loadedGrant.grant
		refreshSession = &storedRefreshSession{
			GrantID:         loadedGrant.grant.ID,
			UserID:          grant.UserID,
			ClientID:        grant.ClientID,
			GrantedScopes:   slices.Clone(grant.GrantedScopes),
			CreatedAt:       grant.GrantedAt,
			AuthenticatedAt: authTimeFromGrant(grant),
			ExpiresAt:       rtUntil,
			LastUsedAt:      s.now(),
		}
	}

	grant := loadedGrant.grant
	ac, acExp, err := s.buildAccessTokenClaims(loadedGrant.grant.ID, grant, tresp)
	if err != nil {
		return nil, fmt.Errorf("building access token claims: %w", err)
	}

	accessTokenAlgorithm := s.accessTokenSigningAlgorithm()
	atSigned, err := s.config.Signer.Sign(ctx, ac.Claims, jwt.SignOptions{Type: ac.Type, Algorithm: accessTokenAlgorithm})
	if err != nil {
		return nil, fmt.Errorf("signing access token with algorithm %s: %w", accessTokenAlgorithm, err)
	}

	var extraParams map[string]any
	if slices.Contains(grant.GrantedScopes, oidc.ScopeOpenID) {
		idc, err := s.buildIDClaims(grant, tresp)
		if err != nil {
			return nil, fmt.Errorf("building ID token claims: %w", err)
		}
		idSigned, err := s.config.Signer.Sign(ctx, idc.Claims, jwt.SignOptions{Type: idc.Type, Algorithm: idTokenAlgorithm})
		if err != nil {
			return nil, fmt.Errorf("signing ID token with algorithm %s: %w", idTokenAlgorithm, err)
		}
		extraParams = map[string]any{"id_token": idSigned}
	}

	tokenType := "bearer"
	if isDPoPBound {
		tokenType = "DPoP"
	}

	return &preparedTokenResponse{
		response: &oauth2proto.TokenResponse{
			AccessToken:  atSigned,
			RefreshToken: refreshToken,
			TokenType:    tokenType,
			ExpiresIn:    acExp.Sub(s.now()),
			Scopes:       slices.Clone(grant.GrantedScopes),
			ExtraParams:  extraParams,
		},
		refreshToken:   storedRefreshToken,
		refreshSession: refreshSession,
	}, nil
}

func (s *Server) buildIDClaims(grant *storedGrant, tresp *TokenResponse) (signingInput, error) {
	idExp := tresp.IDTokenExpiry
	if idExp.IsZero() {
		idExp = s.now().Add(s.config.IDTokenValidity)
	}
	application := tresp.IDTokenClaims
	claims, err := additionalClaims(nil, idTokenReservedClaims)
	if application != nil {
		claims, err = additionalClaims(application.Additional, idTokenReservedClaims)
	}
	if err != nil {
		return signingInput{}, err
	}
	subject := grant.UserID
	if application != nil && application.Subject != "" {
		subject = application.Subject
	}
	claims["iss"] = s.config.Issuer
	claims["sub"] = subject
	claims["aud"] = grant.ClientID
	claims["iat"] = s.now().Unix()
	claims["exp"] = idExp.Unix()
	claims["auth_time"] = authTimeFromGrant(grant).Unix()
	if grant.Nonce != "" {
		claims["nonce"] = grant.Nonce
	}
	if grant.ACR != "" {
		claims["acr"] = grant.ACR
	}
	if len(grant.AMR) > 0 {
		claims["amr"] = slices.Clone(grant.AMR)
	}
	return signingInput{Type: "", Claims: claims}, nil
}

func (s *Server) buildAccessTokenClaims(grantID string, grant *storedGrant, tresp *TokenResponse) (_ signingInput, expiresAt time.Time, _ error) {
	atExp := tresp.AccessTokenExpiry
	if atExp.IsZero() {
		atExp = s.now().Add(s.config.AccessTokenValidity)
	}
	application := tresp.AccessTokenClaims
	claims, err := additionalClaims(nil, accessTokenReservedClaims)
	if application != nil {
		claims, err = additionalClaims(application.Additional, accessTokenReservedClaims)
	}
	if err != nil {
		return signingInput{}, time.Time{}, err
	}
	subject := grant.UserID
	if application != nil && application.Subject != "" {
		subject = application.Subject
	}
	audiences := []string{grant.ClientID}
	if application != nil && len(application.Audiences) > 0 {
		audiences = slices.Clone(application.Audiences)
	}
	scopes := slices.Clone(grant.GrantedScopes)
	if application != nil && len(application.Scopes) > 0 {
		scopes = slices.Clone(application.Scopes)
	}
	claims["iss"] = s.config.Issuer
	claims["sub"] = subject
	claims["aud"] = audiences
	claims["iat"] = s.now().Unix()
	claims["exp"] = atExp.Unix()
	claims["jti"] = uuid.NewV4().String()
	claims["client_id"] = grant.ClientID
	claims["scope"] = strings.Join(scopes, " ")
	claims[claimGrantID] = grantID

	if grant.DPoPThumbprint != "" {
		claims["cnf"] = map[string]any{"jkt": grant.DPoPThumbprint}
	}

	return signingInput{Type: "at+jwt", Claims: claims}, atExp, nil
}

var idTokenReservedClaims = map[string]struct{}{
	"iss": {}, "sub": {}, "aud": {}, "exp": {}, "iat": {}, "nbf": {}, "jti": {},
	"auth_time": {}, "nonce": {}, "azp": {}, "acr": {}, "amr": {}, "at_hash": {}, "c_hash": {},
}

var accessTokenReservedClaims = map[string]struct{}{
	"iss": {}, "sub": {}, "aud": {}, "exp": {}, "iat": {}, "nbf": {}, "jti": {},
	"client_id": {}, "scope": {}, "cnf": {}, claimGrantID: {},
}

func additionalClaims(additional map[string]any, reserved map[string]struct{}) (map[string]any, error) {
	claims := make(map[string]any, len(additional)+12)
	for name, value := range additional {
		if _, isReserved := reserved[name]; isReserved {
			return nil, fmt.Errorf("claim %q is managed by the authorization server", name)
		}
		claims[name] = value
	}
	return claims, nil
}

func verifyCodeChallenge(codeVerifier, storedCodeChallenge string) bool {
	h := sha256.New()
	h.Write([]byte(codeVerifier))
	hashedVerifier := h.Sum(nil)
	computedChallenge := base64.RawURLEncoding.EncodeToString(hashedVerifier)
	return computedChallenge == storedCodeChallenge
}

// verifyDPoPProof extracts and verifies the DPoP header from a request. Returns
// a verified [dpop.Proof] if a valid DPoP proof is provided, nil if no DPoP
// header is present (and none is required), or an error if the proof is invalid.
// A supplied proof is rejected when DPoP is not configured. When
// expectedThumbprint is non-nil, the proof's thumbprint must match it. When
// expectedAccessToken is non-empty, the proof's ath claim must bind that exact
// compact access token.
func (s *Server) verifyDPoPProof(iss string, req *http.Request, expectedThumbprint *string, expectedAccessToken string) (proof *dpop.Proof, err error) {
	dpopHeaders := req.Header.Values("DPoP")
	if len(dpopHeaders) == 0 || dpopHeaders[0] == "" {
		if expectedThumbprint != nil {
			return nil, fmt.Errorf("DPoP header required")
		}
		return nil, nil
	}
	if len(dpopHeaders) != 1 {
		return nil, fmt.Errorf("exactly one DPoP header is required")
	}
	dpopHeader := dpopHeaders[0]

	if s.config.DPoPVerifier == nil {
		return nil, fmt.Errorf("DPoP is not supported")
	}

	issURL, err := url.Parse(iss)
	if err != nil {
		return nil, fmt.Errorf("failed to parse issuer: %w", err)
	}
	expectedHTU := (&url.URL{
		Scheme:  issURL.Scheme,
		Host:    issURL.Host,
		Path:    req.URL.Path,
		RawPath: req.URL.RawPath,
	}).String()

	opts := &dpop.ValidatorOpts{
		ExpectedHTM:         new(req.Method),
		ExpectedHTU:         new(expectedHTU),
		ExpectedAccessToken: expectedAccessToken,
	}
	if expectedThumbprint == nil {
		opts.IgnoreThumbprint = true
	} else {
		opts.ExpectedThumbprint = *expectedThumbprint
	}

	// Verify the DPoP proof (verifier will validate HTM/HTU from request)
	validator, err := dpop.NewValidator(opts)
	if err != nil {
		return nil, fmt.Errorf("failed to create validator: %w", err)
	}
	res, err := s.config.DPoPVerifier.VerifyAndDecodeContext(req.Context(), dpopHeader, validator)
	if err != nil {
		return nil, fmt.Errorf("failed to verify DPoP proof: %w", err)
	}

	return res, nil
}
