package oauth2as

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"lds.li/passidp/internal/oauth2as/oauth2proto"
)

type AuthRequest struct {
	// ClientID is the client ID that is requesting authentication.
	ClientID string `json:"clientID,omitzero"`
	// RedirectURI the client specified. This is an OPTIONAL field, if not
	// passed will be set to the zero value. If provided, it will have been
	// validated.
	RedirectURI string `json:"redirectURI,omitzero"`
	// State is the state value that was passed in the request.
	State string `json:"state,omitzero"`
	// Scopes is the list of scopes that the client is requesting.
	Scopes []string `json:"scopes,omitzero"`
	// CodeChallenge is the PKCE code challenge. If it is provided, it will be
	// S256 format. If not provided, it will be an empty string.
	CodeChallenge string `json:"codeChallenge,omitzero"`
	// ACRValues is the list of ACR values that the client is requesting.
	ACRValues []string `json:"acrValues,omitzero"`
	// Nonce is the OIDC nonce from the authorization request.
	Nonce string `json:"nonce,omitzero"`
	// MaxAge is the OIDC max_age parameter. Nil means the parameter was omitted.
	// A pointer to 0 means re-authentication is required. Integrators should
	// compare [AuthTimeExceeded] against their session authentication time
	// before calling [Server.GrantAuth].
	MaxAge *int `json:"maxAge,omitzero"`

	// Raw is the raw URL values that were passed in the request.
	Raw url.Values `json:"raw,omitzero"`
}

func (s *Server) ParseAuthRequest(req *http.Request) (*AuthRequest, error) {
	authreq, err := oauth2proto.ParseAuthRequest(req)
	if err != nil {
		return nil, err
	}

	client, err := s.config.Clients.Client(req.Context(), authreq.ClientID)
	if err != nil {
		return nil, &oauth2proto.HTTPError{
			Code:     http.StatusInternalServerError,
			Cause:    err,
			CauseMsg: fmt.Sprintf("error checking client ID %s", authreq.ClientID),
		}
	}
	if client == nil {
		return nil, &oauth2proto.HTTPError{
			Code:     http.StatusBadRequest,
			Message:  "unknown client",
			CauseMsg: fmt.Sprintf("client ID %s is not valid", authreq.ClientID),
		}
	}

	validatedRedirectURI, err := validateAndResolveRedirectURI(authreq.RedirectURI, client.RedirectURIs, authreq.ClientID)
	if err != nil {
		return nil, &oauth2proto.HTTPError{
			Code:     http.StatusBadRequest,
			Message:  "invalid redirect URI",
			CauseMsg: err.Error(),
		}
	}
	authreq.RedirectURI = validatedRedirectURI

	redir, err := url.Parse(authreq.RedirectURI)
	if err != nil {
		return nil, &oauth2proto.HTTPError{
			Code:     http.StatusInternalServerError,
			Cause:    err,
			CauseMsg: fmt.Sprintf("failed to parse redirect URI %s", authreq.RedirectURI),
		}
	}

	switch authreq.ResponseType {
	case oauth2proto.ResponseTypeCode:
	default:
		return nil, &oauth2proto.AuthError{
			State:       authreq.State,
			Code:        oauth2proto.AuthErrorCodeUnsupportedResponseType,
			Description: fmt.Sprintf("response type %s is not supported", authreq.ResponseType),
			RedirectURI: redir.String(),
		}
	}

	var acrValues []string
	if authreq.Raw.Get("acr_values") != "" {
		acrValues = strings.Split(authreq.Raw.Get("acr_values"), " ")
	}

	return &AuthRequest{
		ClientID:      authreq.ClientID,
		RedirectURI:   redir.String(),
		State:         authreq.State,
		Scopes:        authreq.Scopes,
		CodeChallenge: authreq.CodeChallenge,
		ACRValues:     acrValues,
		Nonce:         authreq.Nonce,
		MaxAge:        authreq.MaxAge,
		Raw:           authreq.Raw,
	}, nil
}

type AuthGrant struct {
	// Request is the corresponding authorization request that we are granting
	// access for.
	Request *AuthRequest
	// GrantedScopes are the scopes that were actually granted.
	GrantedScopes []string
	// UserID is the user ID that was granted access. This is used to form the subject
	// claim, and is provided on subsequent actions.
	UserID string
	// AuthenticatedAt is when the End-User last actively authenticated. If zero,
	// [Server.GrantAuth] uses the current time. This value is emitted as the
	// auth_time claim in ID tokens.
	AuthenticatedAt time.Time
	// Metadata is arbitrary metadata that can be stored with the grant. Can be
	// used for auditing or tracking other information that is associated with
	// the grant. This is not sensitive, and can be accessed at any time.
	Metadata []byte
	// EncryptedMetadata is the encrypted metadata that can be stored with the
	// grant. This is only available to token callbacks. Can be used to store
	// sensitive, grant-specific information like upstream auth tokens.
	EncryptedMetadata []byte
	// ExpiresAt is the time at which the grant will expire. If zero, the
	// default grant validity will be used to calculate this.
	ExpiresAt time.Time
	// ACR is the Authentication Context Class Reference satisfied for this grant.
	ACR string
	// AMR lists the Authentication Methods References for this grant.
	AMR []string
}

func (s *Server) GrantAuth(ctx context.Context, grant *AuthGrant) (redirectURI string, _ error) {
	if grant.UserID == "" {
		return "", fmt.Errorf("user ID is required")
	}
	if grant.Request == nil {
		return "", fmt.Errorf("auth request is required")
	}

	now := s.now()
	expiresAt := grant.ExpiresAt
	if expiresAt.IsZero() {
		expiresAt = now.Add(s.config.GrantValidity)
	}

	authenticatedAt := grant.AuthenticatedAt
	if authenticatedAt.IsZero() {
		authenticatedAt = now
	}
	if authenticatedAt.After(now) {
		return "", fmt.Errorf("authentication time must not be in the future")
	}

	sg := &storedGrant{
		UserID:          grant.UserID,
		ClientID:        grant.Request.ClientID,
		GrantedScopes:   grant.GrantedScopes,
		Request:         grant.Request,
		GrantedAt:       now,
		AuthenticatedAt: authenticatedAt,
		ExpiresAt:       expiresAt, // Grant has absolute lifetime
		Metadata:        grant.Metadata,
		ACR:             grant.ACR,
		AMR:             slices.Clone(grant.AMR),
	}

	loadedGrant := &loadedAuthCodeGrant{
		grant:             sg,
		decryptedMetadata: grant.EncryptedMetadata,
	}

	_, authCodeString, err := s.putGrantWithAuthCode(ctx, loadedGrant, now.Add(s.config.CodeValidityTime))
	if err != nil {
		return "", fmt.Errorf("failed to put grant with auth code: %w", err)
	}

	// Validate and resolve the redirect URI
	client, err := s.config.Clients.Client(ctx, grant.Request.ClientID)
	if err != nil {
		return "", fmt.Errorf("error getting client %s: %w", grant.Request.ClientID, err)
	}
	if client == nil {
		return "", fmt.Errorf("client %s not found", grant.Request.ClientID)
	}

	redirURI, err := validateAndResolveRedirectURI(grant.Request.RedirectURI, client.RedirectURIs, grant.Request.ClientID)
	if err != nil {
		return "", err
	}

	redir, err := url.Parse(redirURI)
	if err != nil {
		return "", fmt.Errorf("failed to parse authreq's URI: %w", err)
	}

	codeResp := &oauth2proto.CodeAuthResponse{
		RedirectURI: redir,
		State:       grant.Request.State,
		Code:        authCodeString,
	}

	return codeResp.ToRedirectURI().String(), nil
}

// validateAndResolveRedirectURI validates the provided redirect URI against the
// list of registered redirects for a client. If no redirect URI is provided and
// the client has exactly one registered redirect, it returns that redirect.
// Otherwise, it validates that the provided redirect is in the registered list.
func validateAndResolveRedirectURI(redirectURI string, registeredRedirects []string, clientID string) (string, error) {
	if redirectURI == "" {
		if len(registeredRedirects) != 1 {
			return "", fmt.Errorf("client ID %s has multiple redirect URIs, but none were provided", clientID)
		}
		// Use the single registered redirect URI
		return registeredRedirects[0], nil
	}

	// Validate the provided redirect URI
	if !isValidRedirectURI(redirectURI, registeredRedirects) {
		return "", fmt.Errorf("redirect URI %s is not valid for client ID %s", redirectURI, clientID)
	}
	return redirectURI, nil
}
