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
	"lds.li/webauthn-oidc-idp/internal/config"
	"lds.li/webauthn-oidc-idp/internal/queries"
)

// Client represents the client information that is used for our custom token
// handlers.
type Client interface {
	// UseOverrideSubject indicates that this client should use the override
	// subject for tokens/userinfo, if the user has one set.
	UseOverrideSubject() bool
	// AccessIDTokenValidity returns the validity time for access/ID tokens. If
	// 0, the default validity time will be used.
	AccessIDTokenValidity() time.Duration
	// RequiredGroups returns the list of group names that the user must be a
	// member of to access this client. If empty, no group membership is
	// required.
	RequiredGroups() []string
}

// ClientSource defines the interface for retrieving client information
type ClientSource interface {
	GetClient(clientID string) (Client, bool)
}

type Handlers struct {
	Issuer  string
	Queries *queries.Queries
	Config  *config.Config
	Clients ClientSource
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

	idc := jwt.RawJWTOptions{
		CustomClaims: map[string]any{
			"email":          user.Email,
			"email_verified": true,
			"picture":        gravatarURL(user.Email),
			"name":           user.FullName,
			"groups":         anyGroups,
		},
	}

	if cl.UseOverrideSubject() && user.OverrideSubject != "" {
		idc.Subject = &user.OverrideSubject
	}

	resp := &oauth2as.TokenResponse{
		IDClaims: &idc,
	}

	if cl.AccessIDTokenValidity() > 0 {
		resp.AccessTokenExpiry = time.Now().Add(cl.AccessIDTokenValidity())
		resp.IDTokenExpiry = time.Now().Add(cl.AccessIDTokenValidity())
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

	user, err := h.Config.Users.GetUser(userUUID)
	if err != nil {
		return nil, fmt.Errorf("get user: %w", err)
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
		Groups:        user.Groups,
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
