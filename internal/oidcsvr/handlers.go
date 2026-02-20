package oidcsvr

import (
	"context"
	"crypto/sha256"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/google/uuid"
	"lds.li/oauth2ext/oauth2as"
	"lds.li/passidp/claims"
	"lds.li/passidp/internal/config"
	"lds.li/passidp/internal/policy"
)

// Client represents the client information that is used for our custom token
// handlers.
type Client interface {
	// ClaimsPolicy returns the CEL expression for modifying claims.
	ClaimsPolicy() string
	// AuthorizationPolicy returns the CEL expression for determining if a user
	// is authorized.
	AuthorizationPolicy() string
	// GrantValidity returns the validity time for grants.
	GrantValidity() *time.Duration
	// AccessIDTokenValidity returns the validity time for access/ID tokens. If
	// nil, the default validity time will be used.
	AccessIDTokenValidity() *time.Duration
	// RefreshValidity returns the validity time for refresh tokens.
	RefreshValidity() *time.Duration
	// DPoPRefreshValidity returns the validity time for refresh tokens when DPoP
	// is used.
	DPoPRefreshValidity() *time.Duration
}

// ClientSource defines the interface for retrieving client information
type ClientSource interface {
	GetClient(clientID string) (Client, bool)
}

type Handlers struct {
	Issuer  string
	Config  *config.Config
	Clients ClientSource
	Policy  *policy.PolicyEvaluator
}

func (h *Handlers) TokenHandler(ctx context.Context, req *oauth2as.TokenRequest) (_ *oauth2as.TokenResponse, retErr error) {
	slog.Info("token handler", "clientID", req.ClientID, "scopes", req.GrantedScopes)

	userUUID, err := uuid.Parse(req.UserID)
	if err != nil {
		return nil, fmt.Errorf("parse user ID: %w", err)
	}

	user, err := h.Config.Users.GetUser(userUUID)
	if err != nil {
		return nil, fmt.Errorf("get user: %w", err)
	}

	cl, ok := h.Clients.GetClient(req.ClientID)
	if !ok {
		return nil, fmt.Errorf("client %s not found", req.ClientID)
	}

	anyGroups := make([]any, len(user.Groups))
	for i, group := range user.Groups {
		anyGroups[i] = group
	}

	cb := claims.IDClaims_builder{
		Email:             new(user.Email),
		EmailVerified:     new(true),
		Picture:           new(gravatarURL(user.Email)),
		Name:              new(user.FullName),
		Groups:            user.Groups,
		PreferredUsername: new(user.PreferredUsername),
	}

	idClaims := cb.Build()

	if h.Policy != nil && cl.ClaimsPolicy() != "" {
		var err error
		idClaims, err = h.Policy.EvaluateClaims(cl.ClaimsPolicy(), idClaims, user)
		if err != nil {
			return nil, fmt.Errorf("evaluate claims policy: %w", err)
		}
	}

	resp := &oauth2as.TokenResponse{
		IDClaims: claims.JWTOptsFromIDClaims(idClaims),
	}

	// Determine refresh token validity
	var refreshValidity time.Duration

	if req.DPoPBound {
		if v := cl.DPoPRefreshValidity(); v != nil {
			refreshValidity = *v
		} else {
			refreshValidity = h.Config.DPoPRefreshValidity.Duration()
		}
	} else {
		if v := cl.RefreshValidity(); v != nil {
			refreshValidity = *v
		}
	}

	if refreshValidity > 0 {
		resp.RefreshTokenValidUntil = time.Now().Add(refreshValidity)
	}

	// Determine access/ID token validity
	var tokenValidity time.Duration
	if v := cl.AccessIDTokenValidity(); v != nil {
		tokenValidity = *v
	}

	if tokenValidity > 0 {
		resp.AccessTokenExpiry = time.Now().Add(tokenValidity)
		resp.IDTokenExpiry = time.Now().Add(tokenValidity)
	}

	slog.Info("token handler", "userID", userUUID.String(), "clientID", req.ClientID, "refreshRequested", req.IsRefresh, "refreshValidity", refreshValidity, "tokenValidity", tokenValidity, "dpopBound", req.DPoPBound)

	return resp, nil
}

func (h *Handlers) UserinfoHandler(ctx context.Context, uireq *oauth2as.UserinfoRequest) (*oauth2as.UserinfoResponse, error) {
	// TODO - the req should have the grant/scopes, so we can determine what to
	// give access to.

	userUUID, err := uuid.Parse(uireq.Subject)
	if err != nil {
		return nil, fmt.Errorf("parse user ID: %w", err)
	}

	user, err := h.Config.Users.GetUser(userUUID)
	if err != nil {
		return nil, fmt.Errorf("get user: %w", err)
	}

	nsp := strings.Split(user.FullName, " ")
	cl := struct {
		Email             string   `json:"email"`
		EmailVerified     bool     `json:"email_verified"`
		Picture           string   `json:"picture"`
		Name              string   `json:"name"`
		Groups            []string `json:"groups"`
		GivenName         string   `json:"given_name,omitempty"`
		FamilyName        string   `json:"family_name,omitempty"`
		PreferredUsername string   `json:"preferred_username,omitzero"`
	}{
		Email:             user.Email,
		EmailVerified:     true,
		Picture:           gravatarURL(user.Email),
		Name:              user.FullName,
		Groups:            user.Groups,
		PreferredUsername: user.PreferredUsername,
	}
	if len(nsp) == 2 {
		cl.GivenName = nsp[0]
		cl.FamilyName = nsp[1]
	}

	return &oauth2as.UserinfoResponse{
		Identity: &cl,
	}, nil
}

func gravatarURL(email string) string {
	hash := sha256.Sum256([]byte(email))
	return fmt.Sprintf("https://www.gravatar.com/avatar/%x.png", hash)
}
