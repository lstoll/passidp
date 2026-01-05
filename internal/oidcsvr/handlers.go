package oidcsvr

import (
	"context"
	"crypto/sha256"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/tink-crypto/tink-go/v2/jwt"
	"lds.li/oauth2ext/oauth2as"
	"lds.li/webauthn-oidc-idp/internal/clients"
	"lds.li/webauthn-oidc-idp/internal/queries"
)

// ClientSource defines the interface for retrieving client information
type ClientSource interface {
	GetClient(clientID string) (*clients.Client, bool)
}

type Handlers struct {
	Issuer  string
	Queries *queries.Queries
	Clients ClientSource
}

func (h *Handlers) TokenHandler(ctx context.Context, req *oauth2as.TokenRequest) (_ *oauth2as.TokenResponse, retErr error) {
	slog.Info("token handler", "clientID", req.ClientID, "scopes", req.GrantedScopes)

	userUUID, err := uuid.Parse(req.UserID)
	if err != nil {
		return nil, fmt.Errorf("parse user ID: %w", err)
	}

	user, err := h.Queries.GetUser(ctx, userUUID)
	if err != nil {
		return nil, fmt.Errorf("get user: %w", err)
	}

	cl, ok := h.Clients.GetClient(req.ClientID)
	if !ok {
		return nil, fmt.Errorf("client %s not found", req.ClientID)
	}

	// Get user's active group memberships for claims
	groupMemberships, err := h.Queries.GetUserActiveGroupMemberships(ctx, req.UserID)
	if err != nil {
		return nil, fmt.Errorf("get user group memberships: %w", err)
	}

	// Extract group names for claims
	var groupNames []any
	for _, membership := range groupMemberships {
		groupNames = append(groupNames, membership.GroupName)
	}

	idc := jwt.RawJWTOptions{
		CustomClaims: map[string]any{
			"email":          user.Email,
			"email_verified": true,
			"picture":        gravatarURL(user.Email),
			"name":           user.FullName,
			"groups":         groupNames,
		},
	}

	if cl.UseOverrideSubject && user.OverrideSubject.Valid {
		idc.Subject = &user.OverrideSubject.String
	}

	resp := &oauth2as.TokenResponse{
		IDClaims: &idc,
	}

	if cl.ParsedTokenValidity > 0 {
		resp.AccessTokenExpiry = time.Now().Add(cl.ParsedTokenValidity)
		resp.IDTokenExpiry = time.Now().Add(cl.ParsedTokenValidity)
	}

	return resp, nil
}

func (h *Handlers) UserinfoHandler(ctx context.Context, uireq *oauth2as.UserinfoRequest) (*oauth2as.UserinfoResponse, error) {
	// TODO - the req should have the grant/scopes, so we can determine what to
	// give access to.

	userUUID, err := uuid.Parse(uireq.Subject)
	if err != nil {
		return nil, fmt.Errorf("parse user ID: %w", err)
	}

	user, err := h.Queries.GetUser(ctx, userUUID)
	if err != nil {
		return nil, fmt.Errorf("get user: %w", err)
	}

	// Get user's active group memberships for claims
	groupMemberships, err := h.Queries.GetUserActiveGroupMemberships(ctx, uireq.Subject)
	if err != nil {
		return nil, fmt.Errorf("get user group memberships: %w", err)
	}

	// Extract group names for claims
	var groupNames []string
	for _, membership := range groupMemberships {
		groupNames = append(groupNames, membership.GroupName)
	}

	nsp := strings.Split(user.FullName, " ")
	cl := struct {
		Email         string   `json:"email"`
		EmailVerified bool     `json:"email_verified"`
		Picture       string   `json:"picture"`
		Name          string   `json:"name"`
		Groups        []string `json:"groups"`
		GivenName     string   `json:"given_name,omitempty"`
		FamilyName    string   `json:"family_name,omitempty"`
	}{
		Email:         user.Email,
		EmailVerified: true,
		Picture:       gravatarURL(user.Email),
		Name:          user.FullName,
		Groups:        groupNames,
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
