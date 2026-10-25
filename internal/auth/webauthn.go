package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
	"uuid"

	"filippo.io/passkey"
	"lds.li/passidp/internal/appsession"
	"lds.li/passidp/internal/config"
	"lds.li/passidp/internal/oauth2as"
	"lds.li/passidp/internal/ratelimit"
	"lds.li/passidp/internal/storage"
	"lds.li/passidp/internal/webcommon"
	"lds.li/web"
	"lds.li/web/httperror"
)

type ctxKeySkipAuthn struct{}

var _ web.HandlerOpt = SkipAuthn

// SkipAuthn is a handler option that skips authentication for the request.
func SkipAuthn(r *http.Request) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), ctxKeySkipAuthn{}, true))
}

type Authenticator struct {
	Passkey      *passkey.RelyingParty
	CredStore    *storage.CredentialFile
	OAuth2       *oauth2as.Server
	OAuth2Grants *storage.OAuth2Grants
	Config       *config.Config
}

func (a *Authenticator) AddHandlers(r *web.Server) {
	rl := &ratelimit.Middleware{
		Rate:  a.Config.Serving.AuthLimitRate,
		Burst: a.Config.Serving.AuthLimitBucket,
	}

	r.Handle("GET /{$}", a.Middleware(web.BrowserHandlerFunc(a.HandleIndex)))
	r.Handle("GET /login", rl.Wrap(web.BrowserHandlerFunc(a.HandleLoginPage)), SkipAuthn)
	r.Handle("POST /login/begin", rl.Wrap(web.BrowserHandlerFunc(a.BeginLogin)), SkipAuthn)
	r.Handle("GET /logout", web.BrowserHandlerFunc(a.Logout), SkipAuthn)
	r.Handle("POST /finishWebauthnLogin", rl.Wrap(web.BrowserHandlerFunc(a.DoLogin)), SkipAuthn)

	// Grant management API
	r.Handle("GET /api/grants", a.Middleware(web.BrowserHandlerFunc(a.HandleListGrants)))
	r.Handle("DELETE /api/grants/", a.Middleware(web.BrowserHandlerFunc(a.HandleRevokeGrant)))
	r.Handle("DELETE /api/grants", a.Middleware(web.BrowserHandlerFunc(a.HandleRevokeAllGrants)))

	r.Handle("GET /api/credentials", a.Middleware(web.BrowserHandlerFunc(a.HandleListCredentials)))
	r.Handle("DELETE /api/credentials/", a.Middleware(web.BrowserHandlerFunc(a.HandleDeleteCredential)))
}

func (a *Authenticator) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		skip, ok := r.Context().Value(ctxKeySkipAuthn{}).(bool)
		if ok && skip {
			next.ServeHTTP(w, r)
			return
		}

		as := appsession.FromContext(r.Context()).Get().Auth
		if as.LoggedInUserID == nil || time.Now().After(as.ExpiresAt) {
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

	q := url.Values{}
	if returnTo != "" {
		q.Set("return_to", returnTo)
	}
	u := "/login"
	if len(q) > 0 {
		u += "?" + q.Encode()
	}

	http.Redirect(w, r, u, http.StatusSeeOther)
}

func (a *Authenticator) HandleLoginPage(ctx context.Context, w web.ResponseWriter, r *web.Request) error {
	flowID := r.URL().Query().Get("flow")
	returnTo := r.URL().Query().Get("return_to")
	if returnTo == "" {
		returnTo = "/"
	}

	sess := appsession.FromContext(ctx)
	data := sess.Get()
	as := data.Auth
	if as.Flows == nil {
		as.Flows = make(map[string]appsession.AuthFlow)
	}

	if flowID != "" {
		if _, ok := as.Flows[flowID]; !ok {
			return httperror.BadRequestErrf("flow not found in session")
		}
	} else {
		flowID = uuid.New().String()
		as.Flows[flowID] = appsession.AuthFlow{
			ReturnTo:  returnTo,
			StartedAt: time.Now(),
		}
		data.Auth = as
		sess.Save()
	}

	return w.WriteResponse(r, &web.TemplateResponse{
		Templates: templates,
		Name:      "login.tmpl.html",
		Data: loginData{
			LayoutData: webcommon.LayoutData{
				Title: "Login - IDP",
			},
			FlowID: flowID,
		},
	})
}

type beginLoginRequest struct {
	FlowID string `json:"flowID"`
}

func (a *Authenticator) BeginLogin(ctx context.Context, w web.ResponseWriter, r *web.Request) error {
	var req beginLoginRequest
	if err := r.UnmarshalJSONBody(&req); err != nil {
		return fmt.Errorf("unmarshalling login begin request: %w", err)
	}
	if req.FlowID == "" {
		return httperror.BadRequestErrf("flow ID required")
	}

	sess := appsession.FromContext(ctx)
	data := sess.Get()
	as := data.Auth
	if as.Flows == nil {
		return httperror.BadRequestErrf("auth missing from session")
	}

	flow, ok := as.Flows[req.FlowID]
	if !ok {
		return httperror.BadRequestErrf("flow not found in session")
	}

	if !flow.StartedAt.IsZero() && time.Since(flow.StartedAt) > authFlowValidFor {
		return httperror.BadRequestErrf("flow expired")
	}

	request, optionsJSON, err := a.Passkey.NewLogin()
	if err != nil {
		return fmt.Errorf("starting discoverable login: %w", err)
	}

	var options any
	if err := json.Unmarshal(optionsJSON, &options); err != nil {
		return fmt.Errorf("encoding login options: %w", err)
	}

	flow.PasskeyRequest = request
	flow.StartedAt = time.Now()
	as.Flows[req.FlowID] = flow
	data.Auth = as
	sess.Save()

	return w.WriteResponse(r, &web.JSONResponse{Data: options})
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

	sess := appsession.FromContext(ctx)
	data := sess.Get()
	as := data.Auth
	if as.Flows == nil {
		return httperror.BadRequestErrf("auth missing from session")
	}

	flow, ok := as.Flows[req.FlowID]
	if !ok {
		return httperror.BadRequestErrf("flow not found in session")
	}

	if time.Since(flow.StartedAt) > authFlowValidFor {
		return httperror.BadRequestErrf("flow expired")
	}
	if len(flow.PasskeyRequest) == 0 {
		return httperror.BadRequestErrf("login not started")
	}

	parsed, err := passkey.ParseResponse(req.CredentialAssertionResponse)
	if err != nil {
		return fmt.Errorf("parsing credential assertion response: %w", err)
	}

	cfgUser, err := a.lookupUser(parsed.UnauthenticatedUserID())
	if err != nil {
		return fmt.Errorf("validating login: %w", err)
	}

	var records []string
	a.CredStore.Read(func(cs *storage.CredentialStore) {
		records = cs.PasskeyRecords(cfgUser.ID)
	})

	if _, err := a.Passkey.Login(parsed, flow.PasskeyRequest, records); err != nil {
		return fmt.Errorf("validating login: %w", err)
	}

	if err := a.CredStore.Write(func(cs *storage.CredentialStore) error {
		cs.RememberHandle(cfgUser.ID, []byte(parsed.UnauthenticatedUserID()), cfgUser.PasskeyHandleAliases())
		return nil
	}); err != nil {
		return fmt.Errorf("record passkey handle: %w", err)
	}

	delete(as.Flows, req.FlowID)
	id := cfgUser.ID
	as.LoggedInUserID = &id
	now := time.Now()
	as.AuthenticatedAt = now
	as.ExpiresAt = now.Add(a.Config.SessionDuration.Duration())
	data.Auth = as
	sess.Reset()

	return w.WriteResponse(r, &web.JSONResponse{
		Data: loginResponse{
			ReturnTo: flow.ReturnTo,
		},
	})
}

func (a *Authenticator) Logout(ctx context.Context, w web.ResponseWriter, r *web.Request) error {
	sess := appsession.FromContext(ctx)
	sess.Delete()
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
	DPoPBound bool     `json:"dpop_bound"`
}

type listGrantsResponse struct {
	Grants []grantInfo `json:"grants"`
}

func (a *Authenticator) HandleListGrants(ctx context.Context, w web.ResponseWriter, r *web.Request) error {
	userID, ok := UserIDFromContext(ctx)
	if !ok {
		return httperror.BadRequestErrf("user not logged in")
	}

	var resp listGrantsResponse
	var cursor string
	for {
		page, err := a.OAuth2.ListRefreshSessions(ctx, oauth2as.RefreshSessionQuery{UserID: userID.String(), Cursor: cursor})
		if err != nil {
			return fmt.Errorf("list active grants: %w", err)
		}
		dpopBound := map[string]bool{}
		if a.OAuth2Grants != nil && len(page.Sessions) > 0 {
			grantIDs := make([]string, len(page.Sessions))
			for i, grant := range page.Sessions {
				grantIDs[i] = grant.GrantID
			}
			var err error
			dpopBound, err = a.OAuth2Grants.DPoPBound(ctx, grantIDs)
			if err != nil {
				return fmt.Errorf("lookup dpop-bound grants: %w", err)
			}
		}
		for _, grant := range page.Sessions {
			resp.Grants = append(resp.Grants, grantInfo{
				ID:        grant.GrantID,
				ClientID:  grant.ClientID,
				Scopes:    grant.GrantedScopes,
				GrantedAt: grant.CreatedAt.Format(time.RFC3339),
				ExpiresAt: grant.ExpiresAt.Format(time.RFC3339),
				DPoPBound: dpopBound[grant.GrantID],
			})
		}
		if page.NextCursor == "" {
			break
		}
		cursor = page.NextCursor
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

	if err := a.OAuth2.RevokeRefreshSession(ctx, userID.String(), grantIDStr); err != nil {
		if errors.Is(err, oauth2as.ErrNotFound) {
			return httperror.NotFoundErrf("grant not found")
		}
		return fmt.Errorf("revoke grant: %w", err)
	}

	w.WriteHeader(http.StatusNoContent)
	return nil
}

func (a *Authenticator) HandleRevokeAllGrants(ctx context.Context, w web.ResponseWriter, r *web.Request) error {
	userID, ok := UserIDFromContext(ctx)
	if !ok {
		return httperror.BadRequestErrf("user not logged in")
	}

	for {
		page, err := a.OAuth2.ListRefreshSessions(ctx, oauth2as.RefreshSessionQuery{UserID: userID.String()})
		if err != nil {
			return fmt.Errorf("list grants for revocation: %w", err)
		}
		if len(page.Sessions) == 0 {
			break
		}
		for _, grant := range page.Sessions {
			if err := a.OAuth2.RevokeRefreshSession(ctx, userID.String(), grant.GrantID); err != nil && !errors.Is(err, oauth2as.ErrNotFound) {
				return fmt.Errorf("revoke grant: %w", err)
			}
		}
	}

	w.WriteHeader(http.StatusNoContent)
	return nil
}
