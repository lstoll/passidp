package adminui

import (
	"bytes"
	"context"
	"encoding/gob"
	"encoding/json"
	"fmt"

	"crawshaw.dev/jsonfile"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
	"lds.li/passidp/internal/auth"
	"lds.li/passidp/internal/config"
	"lds.li/passidp/internal/storage"
	"lds.li/passidp/internal/webcommon"
	"lds.li/web"
	"lds.li/web/session"
)

func init() {
	gob.Register(&pendingWebauthnEnrollment{})
}

const pendingWebauthnEnrollmentSessionKey = "pending_webauthn_enrollment"

// pendingWebauthnEnrollment tracks enrollment info across an authenticator
// registration.
type pendingWebauthnEnrollment struct {
	ForUserID           string                `json:"for_user_id,omitempty"`
	EnrollmentID        string                `json:"enrollment_id,omitempty"`
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
	state     *storage.State
	webauthn  *webauthn.WebAuthn
}

func NewWebAuthnManager(config *config.Config, credStore *jsonfile.JSONFile[storage.CredentialStore], state *storage.State, webauthn *webauthn.WebAuthn) *WebAuthnManager {
	return &WebAuthnManager{
		config:    config,
		credStore: credStore,
		state:     state,
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
	// check if we have a pending enrollment with matching token.
	uid := req.URL().Query().Get("user_id")
	et := req.URL().Query().Get("enrollment_token")
	if uid != "" && et != "" {
		// we want to enroll a user. Check for pending enrollment in state DB
		userID, err := uuid.Parse(uid)
		if err != nil {
			return fmt.Errorf("invalid user_id: %w", err)
		}

		enrollment, err := w.state.PendingEnrollments().GetPendingEnrollmentByKey(et)
		if err != nil {
			return fmt.Errorf("invalid enrollment token: %w", err)
		}

		if enrollment.UserID != userID {
			return fmt.Errorf("enrollment user_id mismatch")
		}

		sess := session.MustFromContext(ctx)
		sess.Set(pendingWebauthnEnrollmentSessionKey, &pendingWebauthnEnrollment{
			ForUserID:    uid,
			EnrollmentID: enrollment.ID.String(),
		})
	}

	// Get the pending enrollment from session
	sess := session.MustFromContext(ctx)
	pwe, ok := sess.Get(pendingWebauthnEnrollmentSessionKey).(*pendingWebauthnEnrollment)
	if !ok || pwe.ForUserID == "" {
		return fmt.Errorf("no enroll to user id set in session")
	}

	user, err := w.config.Users.GetUserByStringID(pwe.ForUserID)
	if err != nil {
		return fmt.Errorf("get user %s: %w", pwe.ForUserID, err)
	}

	return rw.WriteResponse(req, &web.TemplateResponse{
		Templates: templates,
		Name:      "register.tmpl.html",
		Data: registerData{
			LayoutData: webcommon.LayoutData{
				Title:        "Register Passkey - IDP",
				UserLoggedIn: true,
				Username:     user.Email,
				UserFullName: user.FullName,
				UserEmail:    user.Email,
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

	// Get the enrollment ID from session
	if pwe.EnrollmentID == "" {
		return fmt.Errorf("no enrollment ID in session")
	}

	enrollmentID, err := uuid.Parse(pwe.EnrollmentID)
	if err != nil {
		return fmt.Errorf("invalid enrollment_id: %w", err)
	}

	enrollment, err := w.state.PendingEnrollments().GetPendingEnrollmentByID(enrollmentID)
	if err != nil {
		return fmt.Errorf("get pending enrollment: %w", err)
	}

	userID, err := uuid.Parse(pwe.ForUserID)
	if err != nil {
		return fmt.Errorf("invalid user_id: %w", err)
	}

	if enrollment.UserID != userID {
		return fmt.Errorf("enrollment user_id mismatch")
	}

	// Generate confirmation key
	confirmationKey := uuid.New().String()

	// Store the credential as a pending enrollment (not active yet)
	if err := w.state.PendingEnrollments().UpdatePendingEnrollment(enrollment.ID, credential.ID, credential, keyName, confirmationKey); err != nil {
		return fmt.Errorf("update pending enrollment: %w", err)
	}

	// Return success response with confirmation key
	return rw.WriteResponse(req, &web.JSONResponse{
		Data: map[string]interface{}{
			"success":          true,
			"message":          "Passkey registered successfully!",
			"confirmation_key": confirmationKey,
			"enrollment_id":    enrollment.ID.String(),
			"returnTo":         returnTo,
		},
	})
}
