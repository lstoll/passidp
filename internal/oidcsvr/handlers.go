package oidcsvr

import (
	"context"
	"crypto/sha256"
	"fmt"
	"log/slog"
	"strings"
	"time"
	"uuid"

	"lds.li/passidp/internal/config"
	"lds.li/passidp/internal/oauth2as"
	"lds.li/passidp/internal/policy"
)

type Handlers struct {
	Issuer string
	Config *config.Config
	Policy *policy.PolicyEvaluator
}

func (h *Handlers) TokenHandler(ctx context.Context, req *oauth2as.TokenRequest) (_ *oauth2as.TokenResponse, retErr error) {
	slog.Info("token handler", "clientID", req.ClientID, "scopes", req.GrantedScopes)
	cl := req.Client
	if cl == nil {
		return nil, fmt.Errorf("authenticated client %s missing from token request", req.ClientID)
	}

	userUUID, err := uuid.Parse(req.UserID)
	if err != nil {
		return nil, fmt.Errorf("parse user ID: %w", err)
	}

	user, err := h.Config.Users.GetUser(userUUID)
	if err != nil {
		return nil, fmt.Errorf("get user: %w", err)
	}

	idClaims := defaultIDTokenClaims(user)

	if h.Policy != nil && cl.ClaimsPolicy != "" {
		var err error
		idClaims, err = h.Policy.EvaluateClaims(cl.ClaimsPolicy, idClaims, user)
		if err != nil {
			return nil, fmt.Errorf("evaluate claims policy: %w", err)
		}
	}

	resp := &oauth2as.TokenResponse{
		IDTokenClaims: idTokenClaimsFromMap(idClaims),
	}

	// Determine refresh token validity
	var refreshValidity time.Duration

	if req.DPoPBound {
		if cl.DPoPRefreshValidity != 0 {
			refreshValidity = cl.DPoPRefreshValidity
		} else {
			refreshValidity = h.Config.DPoPRefreshValidity.Duration()
		}
	} else {
		if cl.RefreshValidity != 0 {
			refreshValidity = cl.RefreshValidity
		}
	}

	if refreshValidity > 0 {
		resp.RefreshTokenValidUntil = time.Now().Add(refreshValidity)
	}

	// Determine access/ID token validity
	var tokenValidity time.Duration
	if cl.TokenValidity != 0 {
		tokenValidity = cl.TokenValidity
	}

	if tokenValidity > 0 {
		resp.AccessTokenExpiry = time.Now().Add(tokenValidity)
		resp.IDTokenExpiry = time.Now().Add(tokenValidity)
	}

	logAttrs := []any{
		slog.String("userID", userUUID.String()),
		slog.String("clientID", req.ClientID),
		slog.Bool("refreshRequested", req.IsRefresh),
		slog.Duration("refreshValidity", refreshValidity),
		slog.Duration("tokenValidity", tokenValidity),
		slog.Bool("dpopBound", req.DPoPBound),
	}
	if req.DPoPBound && req.DPoPProof != nil && len(req.DPoPProof.CertificateChain) > 0 {
		cert := req.DPoPProof.CertificateChain[0]
		logAttrs = append(logAttrs, slog.String("dpop-subject", cert.Subject.String()))
	}

	slog.Info("token handler", logAttrs...)

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
