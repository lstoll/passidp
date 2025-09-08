package oidcsvr

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/lstoll/oauth2ext/jwt"
	"github.com/lstoll/oauth2ext/oauth2as"
	"github.com/lstoll/webauthn-oidc-idp/internal/clients"
	"github.com/lstoll/webauthn-oidc-idp/internal/queries"
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
	l := slog.With("grantID", req.GrantID, "userID", req.UserID, "clientID", req.ClientID, "scopes", req.GrantedScopes)
	l.InfoContext(ctx, "starting token handler")
	defer func() {
		if retErr != nil {
			l.ErrorContext(ctx, "token handler failed", "error", retErr)
		}
	}()

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
	var groupNames []string
	for _, membership := range groupMemberships {
		groupNames = append(groupNames, membership.GroupName)
	}

	idc := jwt.IDClaims{
		Extra: map[string]any{
			"email":          user.Email,
			"email_verified": true,
			"picture":        gravatarURL(user.Email),
			"name":           user.FullName,
			"groups":         groupNames,
		},
	}

	if cl.UseOverrideSubject && user.OverrideSubject.Valid {
		idc.Subject = user.OverrideSubject.String
	}

	resp := &oauth2as.TokenResponse{
		IDClaims: &idc,
	}

	if cl.ParsedTokenValidity > 0 {
		resp.AccessTokenExpiry = time.Now().Add(cl.ParsedTokenValidity)
		resp.IDTokenExpiry = time.Now().Add(cl.ParsedTokenValidity)
	}

	clJSON, err := json.Marshal(idc)
	if err != nil {
		return nil, fmt.Errorf("marshal client: %w", err)
	}
	l.Info("token handler issuing with claims", "claims", string(clJSON))

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

	cl := jwt.IDClaims{
		Issuer:  h.Issuer,
		Subject: uireq.Subject,
		Extra:   make(map[string]any),
	}
	cl.Extra["email"] = user.Email
	cl.Extra["email_verified"] = true
	cl.Extra["picture"] = gravatarURL(user.Email) // thank u tom
	cl.Extra["name"] = user.FullName
	cl.Extra["groups"] = groupNames
	nsp := strings.Split(user.FullName, " ")
	if len(nsp) == 2 {
		cl.Extra["given_name"] = nsp[0]
		cl.Extra["family_name"] = nsp[1]
	}
	return &oauth2as.UserinfoResponse{
		Identity: &cl,
	}, nil
}

func gravatarURL(email string) string {
	hash := sha256.Sum256([]byte(email))
	return fmt.Sprintf("https://www.gravatar.com/avatar/%x.png", hash)
}
