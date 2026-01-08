package auth

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/gob"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"crawshaw.dev/jsonfile"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
	"lds.li/passidp/internal/config"
	"lds.li/passidp/internal/storage"
	"lds.li/passidp/internal/webcommon"
	"lds.li/web"
	"lds.li/web/httperror"
	"lds.li/web/session"
)

func init() {
	gob.Register(&authSess{})
}

type ctxKeySkipAuthn struct{}

var _ web.HandlerOpt = SkipAuthn

// SkipAuthn is a handler option that skips authentication for the request.
func SkipAuthn(r *http.Request) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), ctxKeySkipAuthn{}, true))
}

type Authenticator struct {
	Webauthn  *webauthn.WebAuthn
	CredStore *jsonfile.JSONFile[storage.CredentialStore]
	State     *storage.State
	Config    *config.Config
}

func (a *Authenticator) AddHandlers(r *web.Server) {
	r.Handle("GET /{$}", a.Middleware(web.BrowserHandlerFunc(a.HandleIndex)))
	r.Handle("GET /login", web.BrowserHandlerFunc(a.HandleLoginPage), SkipAuthn)
	r.Handle("GET /logout", web.BrowserHandlerFunc(a.Logout), SkipAuthn)
	r.Handle("POST /finishWebauthnLogin", web.BrowserHandlerFunc(a.DoLogin), SkipAuthn)

	// Grant management API
	r.Handle("GET /api/grants", a.Middleware(web.BrowserHandlerFunc(a.HandleListGrants)))
	r.Handle("DELETE /api/grants/", a.Middleware(web.BrowserHandlerFunc(a.HandleRevokeGrant)))
}

func (a *Authenticator) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		skip, ok := r.Context().Value(ctxKeySkipAuthn{}).(bool)
		if ok && skip {
			next.ServeHTTP(w, r)
			return
		}

		sess, _ := session.FromContext(r.Context())
		as, ok := sess.Get(authSessSessionKey).(*authSess)
		if !ok || !as.LoggedinUserID.Valid || time.Now().After(as.ExpiresAt) {
			a.TriggerLogin(w, r, r.URL.Path)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// HandleIndex is a temporary handler, just to get a webauthn UI up and running.
func (a *Authenticator) HandleIndex(ctx context.Context, w web.ResponseWriter, r *web.Request) error {
	userID, ok := UserIDFromContext(ctx)
	if !ok {
		return httperror.BadRequestErrf("user not logged in")
	}

	user, err := a.Config.Users.GetUser(*userID)
	if err != nil {
		return fmt.Errorf("get user: %w", err)
	}

	// Example: User not logged in
	return w.WriteResponse(r, &web.TemplateResponse{
		Name: "index.tmpl.html",
		Data: webcommon.LayoutData{
			Title:        "Login - IDP",
			UserLoggedIn: ok,
			Username:     user.Email,
			UserFullName: user.FullName,
			UserEmail:    user.Email,
		},
		Templates: templates,
	})
}

func (a *Authenticator) TriggerLogin(w http.ResponseWriter, r *http.Request, returnTo string) {
	// we'll want something to manually kick off the login flow, to use with
	// oauth2 as we'll want to process the request first. This should maybe take
	// a return to, and return the ID or something so the caller can link to it.
	// E.g process oauth2 start, get the URL to trigger a login, store the
	// oauth2 request info in the session, then send the user onwards to login.
	// The returnto should be called with the ID or something in the query
	// param.
	//
	// alt, the caller can include this in the returnto it generates.

	sess, _ := session.FromContext(r.Context())
	as, ok := sess.Get(authSessSessionKey).(*authSess)
	if !ok {
		as = &authSess{}
	}
	if as.Flows == nil {
		as.Flows = make(map[string]authSessFlow)
	}

	id := uuid.New()

	as.Flows[id.String()] = authSessFlow{
		ReturnTo:  returnTo,
		StartedAt: time.Now(),
	}

	sess.Set(authSessSessionKey, as)

	http.Redirect(w, r, fmt.Sprintf("/login?flow=%s", id.String()), http.StatusSeeOther)
}

func (a *Authenticator) HandleLoginPage(ctx context.Context, w web.ResponseWriter, r *web.Request) error {
	flowID := r.URL().Query().Get("flow")
	if flowID == "" {
		return httperror.BadRequestErrf("flow is required")
	}

	as, ok := r.Session().Get(authSessSessionKey).(*authSess)
	if !ok {
		return httperror.BadRequestErrf("auth missing from session")
	}

	flow, ok := as.Flows[flowID]
	if !ok {
		return httperror.BadRequestErrf("flow not found in session")
	}

	response, sessionData, err := a.Webauthn.BeginDiscoverableLogin(webauthn.WithUserVerification(protocol.VerificationRequired))
	if err != nil {
		return fmt.Errorf("starting discoverable login: BeginDiscoverableLogin: %w", err)
	}

	flow.WebauthnData = sessionData
	as.Flows[flowID] = flow
	r.Session().Set(authSessSessionKey, as)

	return w.WriteResponse(r, &web.TemplateResponse{
		Templates: templates,
		Name:      "login.tmpl.html",
		Data: loginData{
			LayoutData: webcommon.LayoutData{
				Title: "Login - IDP",
			},
			FlowID:            flowID,
			WebauthnChallenge: base64.RawURLEncoding.EncodeToString(response.Response.Challenge),
		},
	})
}

type loginRequest struct {
	FlowID                      string          `json:"flowID"`
	CredentialAssertionResponse json.RawMessage `json:"credentialAssertionResponse"`
}

type loginResponse struct {
	ReturnTo string `json:"returnTo"`
	Error    string `json:"error"`
}

func (a *Authenticator) DoLogin(ctx context.Context, w web.ResponseWriter, r *web.Request) error {
	var req loginRequest
	if err := r.UnmarshalJSONBody(&req); err != nil {
		return fmt.Errorf("unmarshalling login request: %w", err)
	}

	as, ok := r.Session().Get(authSessSessionKey).(*authSess)
	if !ok {
		return httperror.BadRequestErrf("auth missing from session")
	}

	flow, ok := as.Flows[req.FlowID]
	if !ok {
		return httperror.BadRequestErrf("flow not found in session")
	}

	if time.Since(flow.StartedAt) > authFlowValidFor {
		return httperror.BadRequestErrf("flow expired")
	}

	parsedResponse, err := protocol.ParseCredentialRequestResponseBody(bytes.NewReader(req.CredentialAssertionResponse))
	if err != nil {
		return fmt.Errorf("parsing credential assertion response: %w", err)
	}

	// Validate the login
	user, credential, err := a.Webauthn.ValidatePasskeyLogin(a.NewDiscoverableUserHandler(ctx), *flow.WebauthnData, parsedResponse)
	if err != nil {
		return fmt.Errorf("validating login: %w", err)
	}

	if err := a.CredStore.Write(func(cs *storage.CredentialStore) error {
		// TODO(lstoll) - what data is being updated here, if it's just the
		// counter we should maybe split that out into the working store, to
		// stop changing the file.
		var updated bool
		for _, cred := range cs.Credentials {
			if bytes.Equal(cred.CredentialID, credential.ID) {
				cred.CredentialData = credential
				updated = true
				break
			}
		}
		if !updated {
			return fmt.Errorf("no credential found for %s to update", credential.ID)
		}
		return nil
	}); err != nil {
		return fmt.Errorf("writing credential to store: %w", err)
	}

	// Set user ID in session
	delete(as.Flows, req.FlowID)
	// we cast it back to our type to make sure we get the real ID, not the
	// potentially legacy mapped ID.
	as.LoggedinUserID = uuid.NullUUID{UUID: user.(*WebAuthnUser).user.ID, Valid: true}
	as.ExpiresAt = time.Now().Add(a.Config.ParsedSessionDuration)
	r.Session().Set(authSessSessionKey, as)

	// Return the flow's returnTo URL
	return w.WriteResponse(r, &web.JSONResponse{
		Data: loginResponse{
			ReturnTo: flow.ReturnTo,
		},
	})
}

func (a *Authenticator) Logout(ctx context.Context, w web.ResponseWriter, r *web.Request) error {
	r.Session().Delete()
	return w.WriteResponse(r, &web.RedirectResponse{
		URL: "/",
	})
}

type grantInfo struct {
	ID        string   `json:"id"`
	ClientID  string   `json:"client_id"`
	Scopes    []string `json:"scopes"`
	GrantedAt string   `json:"granted_at"`
	ExpiresAt string   `json:"expires_at"`
}

type listGrantsResponse struct {
	Grants []grantInfo `json:"grants"`
}

func (a *Authenticator) HandleListGrants(ctx context.Context, w web.ResponseWriter, r *web.Request) error {
	userID, ok := UserIDFromContext(ctx)
	if !ok {
		return httperror.BadRequestErrf("user not logged in")
	}

	grants, err := a.State.OAuth2State().ListActiveGrantsForUser(ctx, userID.String())
	if err != nil {
		return fmt.Errorf("list active grants: %w", err)
	}

	var resp listGrantsResponse
	for _, g := range grants {
		resp.Grants = append(resp.Grants, grantInfo{
			ID:        g.ID.String(),
			ClientID:  g.ClientID,
			Scopes:    g.GrantedScopes,
			GrantedAt: g.GrantedAt.Format(time.RFC3339),
			ExpiresAt: g.ExpiresAt.Format(time.RFC3339),
		})
	}

	// Sort by most recent first
	sort.Slice(resp.Grants, func(i, j int) bool {
		return resp.Grants[i].GrantedAt > resp.Grants[j].GrantedAt
	})

	return w.WriteResponse(r, &web.JSONResponse{
		Data: resp,
	})
}

func (a *Authenticator) HandleRevokeGrant(ctx context.Context, w web.ResponseWriter, r *web.Request) error {
	userID, ok := UserIDFromContext(ctx)
	if !ok {
		return httperror.BadRequestErrf("user not logged in")
	}

	path := r.URL().Path
	prefix := "/api/grants/"
	grantIDStr, ok := strings.CutPrefix(path, prefix)
	if !ok || grantIDStr == "" {
		return httperror.BadRequestErrf("grant ID required")
	}

	grantID, err := uuid.Parse(grantIDStr)
	if err != nil {
		return httperror.BadRequestErrf("invalid grant ID: %w", err)
	}

	grant, err := a.State.OAuth2State().GetGrant(ctx, grantID)
	if err != nil {
		return fmt.Errorf("get grant: %w", err)
	}
	if grant == nil {
		return httperror.NotFoundErrf("grant not found")
	}
	if grant.UserID != userID.String() {
		return httperror.NotFoundErrf("grant not found")
	}

	if err := a.State.OAuth2State().RevokeGrant(ctx, grantID); err != nil {
		return fmt.Errorf("revoke grant: %w", err)
	}

	w.WriteHeader(http.StatusNoContent)
	return nil
}
