package oidcsvr

import (
	"context"
	"encoding/gob"
	"fmt"
	"log/slog"
	"net/http"
	"slices"

	"github.com/google/uuid"
	"github.com/lstoll/oauth2ext/oauth2as"
	"github.com/lstoll/oauth2ext/oauth2as/discovery"
	"github.com/lstoll/web"
	"github.com/lstoll/web/httperror"
	"github.com/lstoll/webauthn-oidc-idp/internal/auth"
	"github.com/lstoll/webauthn-oidc-idp/internal/queries"
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
	DB        *queries.Queries
	Clients   ClientSource
}

func (s *Server) AddHandlers(r *web.Server) {
	r.Handle("GET /authorization", web.BrowserHandlerFunc(s.HandleAuthorizationRequest), auth.SkipAuthn)
	r.Handle("GET /resumeAuthorization", web.BrowserHandlerFunc(s.HandleAuthorizationRequestReturn), auth.SkipAuthn)

	r.Handle("POST /token", http.HandlerFunc(s.OAuth2AS.TokenHandler), auth.SkipAuthn)
	r.Handle("GET /userinfo", http.HandlerFunc(s.OAuth2AS.UserinfoHandler), auth.SkipAuthn)
	r.Handle("GET /.well-known/openid-configuration", s.Discovery, auth.SkipAuthn)
	r.Handle("GET /.well-known/jwks.json", s.Discovery, auth.SkipAuthn)
}

func (s *Server) HandleAuthorizationRequest(ctx context.Context, w web.ResponseWriter, r *web.Request) error {
	authReq, err := s.OAuth2AS.ParseAuthRequest(r.RawRequest())
	if err != nil {
		return err
	}

	slog.InfoContext(ctx,
		"starting authorization request",
		"clientID", authReq.ClientID,
		"redirectURI", authReq.RedirectURI,
		"state", authReq.State,
		"scopes", authReq.Scopes,
		"codeChallenge", authReq.CodeChallenge,
		"acrValues", authReq.ACRValues,
		"raw", authReq.Raw,
	)

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

func (s Server) createGrant(ctx context.Context, request *oauth2as.AuthRequest, userID uuid.UUID) (returnTo string, _ error) {
	// Get client configuration
	client, found := s.Clients.GetClient(request.ClientID)
	if !found {
		return "", httperror.BadRequestErrf("client %s not found", request.ClientID)
	}

	// Check required groups if any are specified
	if len(client.RequiredGroups) > 0 {
		// Get user's active group memberships
		groupMemberships, err := s.DB.GetUserActiveGroupMemberships(ctx, userID.String())
		if err != nil {
			return "", fmt.Errorf("get user group memberships: %w", err)
		}

		// Check if user is in any of the required groups
		hasRequiredGroup := slices.ContainsFunc(client.RequiredGroups, func(requiredGroup string) bool {
			return slices.ContainsFunc(groupMemberships, func(membership queries.GetUserActiveGroupMembershipsRow) bool {
				return membership.GroupName == requiredGroup
			})
		})

		if !hasRequiredGroup {
			return "", httperror.ForbiddenErrf("user is not a member of any required groups for client %s", request.ClientID)
		}
	}

	grant := &oauth2as.AuthGrant{
		Request: request,
		UserID:  userID.String(),
		// TODO - set scopes appropriately
		GrantedScopes: request.Scopes,
	}
	redir, err := s.OAuth2AS.GrantAuth(ctx, grant)
	if err != nil {
		return "", fmt.Errorf("grant auth: %w", err)
	}

	// TODO - GrantAuth should return the grant ID, might be useful?

	slog.InfoContext(ctx, "created grant", "userID", userID, "clientID", request.ClientID, "scopes", request.Scopes)

	return redir, nil
}
