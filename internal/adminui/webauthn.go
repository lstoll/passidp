package adminui

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/gob"
	"encoding/json"
	"fmt"

	"crawshaw.dev/jsonfile"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
	"lds.li/web"
	"lds.li/web/session"
	"lds.li/webauthn-oidc-idp/internal/auth"
	"lds.li/webauthn-oidc-idp/internal/config"
	"lds.li/webauthn-oidc-idp/internal/storage"
	"lds.li/webauthn-oidc-idp/internal/webcommon"
)

func init() {
	gob.Register(&pendingWebauthnEnrollment{})
}

const pendingWebauthnEnrollmentSessionKey = "pending_webauthn_enrollment"

// pendingWebauthnEnrollment tracks enrollment info across an authenticator
// registration.
type pendingWebauthnEnrollment struct {
	ForUserID           string                `json:"for_user_id,omitempty"`
	KeyName             string                `json:"key_name,omitempty"`
	WebauthnSessionData *webauthn.SessionData `json:"webauthn_session_data,omitempty"`
	// ReturnTo redirects the user here after the key is registered.
	ReturnTo string `json:"return_to,omitempty"`
}

type registerData struct {
	webcommon.LayoutData
}

type WebAuthnManager struct {
	config    *config.Config
	credStore *jsonfile.JSONFile[storage.CredentialStore]
	webauthn  *webauthn.WebAuthn
}

func NewWebAuthnManager(config *config.Config, credStore *jsonfile.JSONFile[storage.CredentialStore], webauthn *webauthn.WebAuthn) *WebAuthnManager {
	return &WebAuthnManager{
		config:    config,
		credStore: credStore,
		webauthn:  webauthn,
	}
}

func (w *WebAuthnManager) AddHandlers(websvr *web.Server) {
	websvr.Handle("POST /registration/begin", web.BrowserHandlerFunc(w.beginRegistration))
	websvr.Handle("POST /registration/finish", web.BrowserHandlerFunc(w.finishRegistration))
	websvr.Handle("GET /registration", web.BrowserHandlerFunc(w.registration))
}

// registration is a page used to add a new key. It should handle either a user
// in the session (from the logged in keys page), or a boostrap token and user
// id as query params for an inactive user.
func (w *WebAuthnManager) registration(ctx context.Context, rw web.ResponseWriter, req *web.Request) error {
	// first, check the URL for a registration token and user id. If it exists,
	// check if we have the user and if they are active/with a matching token,
	// embed it in the page.
	uid := req.URL().Query().Get("user_id")
	et := req.URL().Query().Get("enrollment_token")
	if uid != "" && et != "" {
		// we want to enroll a user. Find them, and match the token
		var user *config.User
		user, err := w.config.Users.GetUserByStringID(uid)
		if err != nil {
			return fmt.Errorf("get user %s: %w", uid, err)
		}
		if user.EnrollmentKey == "" || subtle.ConstantTimeCompare([]byte(et), []byte(user.EnrollmentKey)) == 0 {
			return fmt.Errorf("either previous enrollment completed fine, or invalid enrollment")
		}
		sess := session.MustFromContext(ctx)
		sess.Set(pendingWebauthnEnrollmentSessionKey, &pendingWebauthnEnrollment{
			ForUserID: uid,
		})
	}

	// Get the pending enrollment from session
	sess := session.MustFromContext(ctx)
	pwe, ok := sess.Get(pendingWebauthnEnrollmentSessionKey).(*pendingWebauthnEnrollment)
	if !ok || pwe.ForUserID == "" {
		return fmt.Errorf("no enroll to user id set in session")
	}

	return rw.WriteResponse(req, &web.TemplateResponse{
		Templates: templates,
		Name:      "register.tmpl.html",
		Data: registerData{
			LayoutData: webcommon.LayoutData{
				Title: "Register Passkey - IDP",
			},
		},
	})
}

func (w *WebAuthnManager) beginRegistration(ctx context.Context, rw web.ResponseWriter, req *web.Request) error {
	sess := session.MustFromContext(ctx)

	pwe, ok := sess.Get(pendingWebauthnEnrollmentSessionKey).(*pendingWebauthnEnrollment)
	if !ok || pwe.ForUserID == "" {
		return fmt.Errorf("no enroll to user id set in session")
	}

	user, err := w.config.Users.GetUserByStringID(pwe.ForUserID)
	if err != nil {
		return fmt.Errorf("get user %s: %w", pwe.ForUserID, err)
	}

	// Get key name from query parameter
	keyName := req.URL().Query().Get("key_name")
	if keyName == "" {
		return fmt.Errorf("key name required")
	}

	authSelect := protocol.AuthenticatorSelection{
		RequireResidentKey: protocol.ResidentKeyRequired(),
		UserVerification:   protocol.VerificationRequired,
	}
	conveyancePref := protocol.ConveyancePreference(protocol.PreferDirectAttestation)

	options, sessionData, err := w.webauthn.BeginRegistration(auth.NewWebAuthnUser(user), webauthn.WithAuthenticatorSelection(authSelect), webauthn.WithConveyancePreference(conveyancePref))
	if err != nil {
		return fmt.Errorf("beginning registration: %w", err)
	}

	pwe.KeyName = keyName
	pwe.WebauthnSessionData = sessionData
	sess.Set(pendingWebauthnEnrollmentSessionKey, pwe)

	return rw.WriteResponse(req, &web.JSONResponse{
		Data: options,
	})
}

func (w *WebAuthnManager) finishRegistration(ctx context.Context, rw web.ResponseWriter, req *web.Request) error {
	sess := session.MustFromContext(ctx)

	pwe, ok := sess.Get(pendingWebauthnEnrollmentSessionKey).(*pendingWebauthnEnrollment)
	if !ok || pwe.ForUserID == "" {
		return fmt.Errorf("no enroll to user id set in session")
	}

	user, err := w.config.Users.GetUserByStringID(pwe.ForUserID)
	if err != nil {
		return fmt.Errorf("getting user %s: %w", pwe.ForUserID, err)
	}

	if pwe.WebauthnSessionData == nil {
		return fmt.Errorf("session data not in session")
	}
	sessionData := *pwe.WebauthnSessionData
	keyName := pwe.KeyName

	// purge the data from the session
	returnTo := pwe.ReturnTo
	sess.Set(pendingWebauthnEnrollmentSessionKey, nil)

	// Parse the credential creation request from the body
	var credentialRequest json.RawMessage
	if err := req.UnmarshalJSONBody(&credentialRequest); err != nil {
		return fmt.Errorf("unmarshalling credential request: %w", err)
	}

	parsedResponse, err := protocol.ParseCredentialCreationResponseBody(bytes.NewReader(credentialRequest))
	if err != nil {
		return fmt.Errorf("parsing credential creation response: %w", err)
	}

	credential, err := w.webauthn.CreateCredential(auth.NewWebAuthnUser(user), sessionData, parsedResponse)
	if err != nil {
		return fmt.Errorf("creating credential: %w", err)
	}

	if err := w.credStore.Write(func(cs *storage.CredentialStore) error {
		cs.Credentials = append(cs.Credentials, &storage.Credential{
			ID:             uuid.New(),
			CredentialID:   credential.ID,
			CredentialData: credential,
			Name:           keyName,
			UserID:         user.ID,
		})
		return nil
	}); err != nil {
		return fmt.Errorf("creating user credential: %w", err)
	}

	// Return success response
	return rw.WriteResponse(req, &web.JSONResponse{
		Data: map[string]interface{}{
			"success":  true,
			"message":  "Passkey registered successfully!",
			"returnTo": returnTo,
		},
	})
}
