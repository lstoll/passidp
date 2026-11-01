package oidcsvr

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"
	"uuid"

	"lds.li/passidp/internal/appsession"
	"lds.li/passidp/internal/auth"
	"lds.li/passidp/internal/config"
	"lds.li/passidp/internal/oauth2as"
	"lds.li/passidp/internal/oauth2as/discovery"
	"lds.li/passidp/internal/oauth2as/oauth2proto"
	"lds.li/passidp/internal/policy"
	"lds.li/passidp/internal/ratelimit"
	"lds.li/web"
	"lds.li/web/httperror"
)

type Server struct {
	Auth      *auth.Authenticator
	OAuth2AS  *oauth2as.Server
	Discovery *discovery.OIDCConfigurationHandler
	Clients   oauth2as.ClientSource
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
		return writeOAuth2ProtoError(w, r, err)
	}

	userID, ok := auth.UserIDFromContext(ctx)
	if !ok || authTimeExceeded(ctx, authReq) {
		return s.stashAuthRequestAndLogin(ctx, w, r, authReq)
	}

	redir, err := s.createGrant(ctx, authReq, *userID)
	if err != nil {
		return writeOAuth2ProtoError(w, r, err)
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
	data := appsession.FromContext(ctx).Get()
	if data.AuthRequests == nil {
		return httperror.BadRequestErrf("no requests in session")
	}

	authReq, ok := data.AuthRequests[reqID]
	if !ok {
		return httperror.BadRequestErrf("no request in session")
	}

	redir, err := s.createGrant(ctx, &authReq, *userID)
	if err != nil {
		return writeOAuth2ProtoError(w, r, err)
	}

	return w.WriteResponse(r, &web.RedirectResponse{
		URL:  redir,
		Code: http.StatusSeeOther,
	})
}

func (s *Server) createGrant(ctx context.Context, request *oauth2as.AuthRequest, userID uuid.UUID) (returnTo string, _ error) {
	// Get client configuration
	client, err := s.Clients.Client(ctx, request.ClientID)
	if err != nil {
		return "", fmt.Errorf("get client: %w", err)
	}
	if client == nil {
		return "", httperror.BadRequestErrf("client %s not found", request.ClientID)
	}

	user, err := s.Config.Users.GetUser(userID)
	if err != nil {
		return "", fmt.Errorf("get user: %w", err)
	}

	// Check authorization policy if specified
	if s.Policy != nil && client.AuthorizationPolicy != "" {
		authorized, err := s.Policy.EvaluateAuthorization(client.AuthorizationPolicy, user)
		if err != nil {
			return "", fmt.Errorf("evaluate authorization policy: %w", err)
		}

		if !authorized {
			return "", &oauth2proto.AuthError{
				State:       request.State,
				Code:        oauth2proto.AuthErrorCodeAccessDenied,
				Description: fmt.Sprintf("user is not authorized for client %s", request.ClientID),
				RedirectURI: request.RedirectURI,
			}
		}
	}

	grant := &oauth2as.AuthGrant{
		Request: request,
		UserID:  userID.String(),
		// TODO - set scopes appropriately
		GrantedScopes: request.Scopes,
	}
	if authTime, ok := auth.AuthTimeFromContext(ctx); ok {
		grant.AuthenticatedAt = authTime
	}
	if client.GrantValidity != 0 {
		grant.ExpiresAt = time.Now().Add(client.GrantValidity)
	}

	slog.InfoContext(ctx, "granting auth", "client-id", request.ClientID, "user-id", userID.String(), "scopes", request.Scopes, "grant-expires-at", grant.ExpiresAt)

	redir, err := s.OAuth2AS.GrantAuth(ctx, grant)
	if err != nil {
		return "", fmt.Errorf("grant auth: %w", err)
	}
	return redir, nil
}

func (s *Server) stashAuthRequestAndLogin(ctx context.Context, w web.ResponseWriter, r *web.Request, authReq *oauth2as.AuthRequest) error {
	sess := appsession.FromContext(ctx)
	data := sess.Get()
	if data.AuthRequests == nil {
		data.AuthRequests = make(map[string]oauth2as.AuthRequest)
	}

	reqID := uuid.New().String()
	data.AuthRequests[reqID] = *authReq
	sess.Save()

	s.Auth.TriggerLogin(w, r.RawRequest(), "/resumeAuthorization?id="+reqID)
	return nil
}

func authTimeExceeded(ctx context.Context, authReq *oauth2as.AuthRequest) bool {
	if authReq.MaxAge == nil {
		return false
	}
	authTime, ok := auth.AuthTimeFromContext(ctx)
	if !ok {
		return false
	}
	return oauth2as.AuthTimeExceeded(authTime, *authReq.MaxAge, time.Now())
}

func writeOAuth2ProtoError(w web.ResponseWriter, r *web.Request, err error) error {
	if _, ok := errors.AsType[*oauth2proto.AuthError](err); ok {
		_ = oauth2proto.WriteError(w, r.RawRequest(), err)
		return nil
	}
	// The web error handler doesn't recognise oauth2proto.HTTPError and would
	// turn it into a 500, so write it here with its own status code.
	if herr, ok := errors.AsType[*oauth2proto.HTTPError](err); ok {
		level := slog.LevelWarn
		if herr.Code == 0 || herr.Code >= http.StatusInternalServerError {
			level = slog.LevelError
		}
		slog.Log(r.RawRequest().Context(), level, "oauth2 request failed", "err", err, "path", r.URL().Path)
		_ = oauth2proto.WriteError(w, r.RawRequest(), herr)
		return nil
	}
	return err
}
