package auth

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/gob"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
	"lds.li/web"
	"lds.li/web/httperror"
	"lds.li/web/session"
	"lds.li/webauthn-oidc-idp/internal/config"
	"lds.li/webauthn-oidc-idp/internal/queries"
	"lds.li/webauthn-oidc-idp/internal/webcommon"
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
	Webauthn *webauthn.WebAuthn
	Queries  *queries.Queries
	Config   *config.Config
}

func (a *Authenticator) AddHandlers(r *web.Server) {
	r.Handle("GET /{$}", a.Middleware(web.BrowserHandlerFunc(a.HandleIndex)))
	r.Handle("GET /login", web.BrowserHandlerFunc(a.HandleLoginPage), SkipAuthn)
	r.Handle("GET /logout", web.BrowserHandlerFunc(a.Logout), SkipAuthn)
	r.Handle("POST /finishWebauthnLogin", web.BrowserHandlerFunc(a.DoLogin), SkipAuthn)
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
		if !ok || !as.LoggedinUserID.Valid {
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

	// Example: User not logged in
	return w.WriteResponse(r, &web.TemplateResponse{
		Name: "index.tmpl.html",
		Data: webcommon.LayoutData{
			Title:        "Login - IDP",
			UserLoggedIn: ok,
			Username:     userID.String(),
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

	// Update credential data
	cb, err := json.Marshal(credential)
	if err != nil {
		return fmt.Errorf("marshalling credential: %w", err)
	}

	if err := a.Queries.UpdateCredentialDataByCredentialID(ctx, cb, credential.ID); err != nil {
		return fmt.Errorf("updating credential: %w", err)
	}

	// Set user ID in session
	delete(as.Flows, req.FlowID)
	// we cast it back to our type to make sure we get the real ID, not the
	// potentially legacy mapped ID.
	as.LoggedinUserID = uuid.NullUUID{UUID: user.(*WebAuthnUser).user.ID, Valid: true}
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
