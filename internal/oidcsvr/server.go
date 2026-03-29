package oidcsvr

import (
	"context"
	"encoding/gob"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/google/uuid"
	"lds.li/oauth2ext/oauth2as"
	"lds.li/oauth2ext/oauth2as/discovery"
	"lds.li/passidp/internal/auth"
	"lds.li/passidp/internal/config"
	"lds.li/passidp/internal/policy"
	"lds.li/passidp/internal/ratelimit"
	"lds.li/web"
	"lds.li/web/httperror"
)

func init() {
	gob.Register(&sessionAuthRequests{})
	gob.Register(&oauth2as.AuthRequest{})
}

const (
	sessionKeyAuthRequest = "authRequest"
)

type sessionAuthRequests struct {
	Requests map[string]oauth2as.AuthRequest
}

type Server struct {
	Auth      *auth.Authenticator
	OAuth2AS  *oauth2as.Server
	Discovery *discovery.OIDCConfigurationHandler
	Clients   ClientSource
	Config    *config.Config
	Policy    *policy.PolicyEvaluator
}

func (s *Server) AddHandlers(r *web.Server) {
	rl := &ratelimit.Middleware{
		Rate:  s.Config.Serving.AuthLimitRate,
		Burst: s.Config.Serving.AuthLimitBucket,
	}

	r.Handle("GET /authorization", rl.Wrap(web.BrowserHandlerFunc(s.HandleAuthorizationRequest)), auth.SkipAuthn)
	r.Handle("GET /resumeAuthorization", rl.Wrap(web.BrowserHandlerFunc(s.HandleAuthorizationRequestReturn)), auth.SkipAuthn)

	r.Handle("POST /token", rl.Wrap(http.HandlerFunc(s.OAuth2AS.TokenHandler)), auth.SkipAuthn)
	r.Handle("GET /userinfo", http.HandlerFunc(s.OAuth2AS.UserinfoHandler), auth.SkipAuthn)
	r.Handle("GET /.well-known/openid-configuration", s.Discovery, auth.SkipAuthn)
	r.Handle("GET /.well-known/jwks.json", s.Discovery, auth.SkipAuthn)
}

func (s *Server) HandleAuthorizationRequest(ctx context.Context, w web.ResponseWriter, r *web.Request) error {
	authReq, err := s.OAuth2AS.ParseAuthRequest(r.RawRequest())
	if err != nil {
		return err
	}

	userID, ok := auth.UserIDFromContext(ctx)
	if !ok {
		// stash req in session, set return to with ID.
		sessAuthReqs, ok := r.Session().Get(sessionKeyAuthRequest).(*sessionAuthRequests)
		if !ok {
			sessAuthReqs = &sessionAuthRequests{
				Requests: make(map[string]oauth2as.AuthRequest),
			}
		}

		reqID := uuid.New().String()
		sessAuthReqs.Requests[reqID] = *authReq
		r.Session().Set(sessionKeyAuthRequest, sessAuthReqs)

		s.Auth.TriggerLogin(w, r.RawRequest(), "/resumeAuthorization?id="+reqID)
		return nil
	}

	redir, err := s.createGrant(ctx, authReq, *userID)
	if err != nil {
		return err
	}

	return w.WriteResponse(r, &web.RedirectResponse{
		URL:  redir,
		Code: http.StatusSeeOther,
	})
}

func (s *Server) HandleAuthorizationRequestReturn(ctx context.Context, w web.ResponseWriter, r *web.Request) error {
	userID, ok := auth.UserIDFromContext(ctx)
	if !ok {
		return httperror.BadRequestErrf("user not logged in")
	}
	reqID := r.URL().Query().Get("id")
	if reqID == "" {
		return httperror.BadRequestErrf("no request ID")
	}
	sessAuthReqs, ok := r.Session().Get(sessionKeyAuthRequest).(*sessionAuthRequests)
	if !ok {
		return httperror.BadRequestErrf("no requests in session")
	}

	authReq, ok := sessAuthReqs.Requests[reqID]
	if !ok {
		return httperror.BadRequestErrf("no request in session")
	}

	redir, err := s.createGrant(ctx, &authReq, *userID)
	if err != nil {
		return err
	}

	return w.WriteResponse(r, &web.RedirectResponse{
		URL:  redir,
		Code: http.StatusSeeOther,
	})
}

func (s *Server) createGrant(ctx context.Context, request *oauth2as.AuthRequest, userID uuid.UUID) (returnTo string, _ error) {
	// Get client configuration
	client, found := s.Clients.GetClient(request.ClientID)
	if !found {
		return "", httperror.BadRequestErrf("client %s not found", request.ClientID)
	}

	user, err := s.Config.Users.GetUser(userID)
	if err != nil {
		return "", fmt.Errorf("get user: %w", err)
	}

	// Check authorization policy if specified
	if s.Policy != nil && client.AuthorizationPolicy() != "" {
		authorized, err := s.Policy.EvaluateAuthorization(client.AuthorizationPolicy(), user)
		if err != nil {
			return "", fmt.Errorf("evaluate authorization policy: %w", err)
		}

		if !authorized {
			return "", httperror.ForbiddenErrf("user is not authorized for client %s by policy", request.ClientID)
		}
	}

	grant := &oauth2as.AuthGrant{
		Request: request,
		UserID:  userID.String(),
		// TODO - set scopes appropriately
		GrantedScopes: request.Scopes,
	}
	if client.GrantValidity() != nil {
		grant.ExpiresAt = time.Now().Add(*client.GrantValidity())
	}

	slog.InfoContext(ctx, "granting auth", "client-id", request.ClientID, "user-id", userID.String(), "scopes", request.Scopes, "grant-expires-at", grant.ExpiresAt)

	redir, err := s.OAuth2AS.GrantAuth(ctx, grant)
	if err != nil {
		return "", fmt.Errorf("grant auth: %w", err)
	}
	return redir, nil
}
