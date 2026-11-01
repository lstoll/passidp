package adminui

import (
	"context"
	"encoding/json"
	"fmt"
	"uuid"

	"filippo.io/passkey"
	"lds.li/passidp/internal/admin"
	"lds.li/passidp/internal/appsession"
	"lds.li/passidp/internal/auth"
	"lds.li/passidp/internal/config"
	"lds.li/passidp/internal/storage"
	"lds.li/passidp/internal/webcommon"
	"lds.li/web"
)

type registerData struct {
	webcommon.LayoutData
}

type WebAuthnManager struct {
	config      *config.Config
	credStore   *storage.CredentialFile
	enrollments *storage.EnrollmentStore
	passkey     *passkey.RelyingParty
}

func NewWebAuthnManager(config *config.Config, credStore *storage.CredentialFile, enrollments *storage.EnrollmentStore, rp *passkey.RelyingParty) *WebAuthnManager {
	return &WebAuthnManager{
		config:      config,
		credStore:   credStore,
		enrollments: enrollments,
		passkey:     rp,
	}
}

func (w *WebAuthnManager) AddHandlers(websvr *web.Server) {
	websvr.Handle("POST /registration/begin", web.BrowserHandlerFunc(w.beginRegistration))
	websvr.Handle("POST /registration/finish", web.BrowserHandlerFunc(w.finishRegistration))
	websvr.Handle("GET /registration", web.BrowserHandlerFunc(w.registration))
}

// registration is a page used to add a new key. It should handle either a user
// in the session (from the logged in keys page), or a bootstrap token and user
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

		enrollment, err := w.enrollments.GetPendingEnrollmentByKey(et)
		if err != nil {
			return fmt.Errorf("invalid enrollment token: %w", err)
		}

		if enrollment.UserID != userID {
			return fmt.Errorf("enrollment user_id mismatch")
		}

		sess := appsession.FromContext(ctx)
		data := sess.Get()
		data.Enrollment = &appsession.Enrollment{
			ForUserID:    uid,
			EnrollmentID: enrollment.ID.String(),
		}
		sess.Save()
	} else if userID, ok := auth.UserIDFromContext(ctx); ok {
		sess := appsession.FromContext(ctx)
		data := sess.Get()
		data.Enrollment = &appsession.Enrollment{
			ForUserID: userID.String(),
			ReturnTo:  "/",
		}
		sess.Save()
	}

	// Get the pending enrollment from session
	pwe := appsession.FromContext(ctx).Get().Enrollment
	if pwe == nil || pwe.ForUserID == "" {
		return rw.WriteResponse(req, &web.RedirectResponse{
			URL: "/login?return_to=/registration",
		})
	}

	if pwe.EnrollmentID != "" {
		enrollmentID, err := uuid.Parse(pwe.EnrollmentID)
		if err != nil {
			return fmt.Errorf("invalid enrollment_id: %w", err)
		}
		if _, err := w.enrollments.GetPendingEnrollmentByID(enrollmentID); err != nil {
			return fmt.Errorf("invalid enrollment: %w", err)
		}
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
	sess := appsession.FromContext(ctx)
	data := sess.Get()
	pwe := data.Enrollment
	if err := w.checkEnrollment(ctx, pwe); err != nil {
		return err
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

	var (
		passkeyUserID string
		records       []string
	)
	w.credStore.Read(func(cs *storage.CredentialStore) {
		passkeyUserID, _ = cs.PasskeyUserID(user.ID)
		records = cs.PasskeyRecords(user.ID)
	})
	if passkeyUserID == "" {
		return fmt.Errorf("passkey user id missing for %s", user.ID)
	}

	optionsJSON, err := w.passkey.NewRegistration(passkey.User{
		ID:   passkeyUserID,
		Name: user.Email,
	}, passkey.RegistrationOptions{ExcludeCredentials: records})
	if err != nil {
		return fmt.Errorf("beginning registration: %w", err)
	}

	var options any
	if err := json.Unmarshal(optionsJSON, &options); err != nil {
		return fmt.Errorf("encoding registration options: %w", err)
	}

	pwe.KeyName = keyName
	data.Enrollment = pwe
	sess.Save()

	return rw.WriteResponse(req, &web.JSONResponse{
		Data: options,
	})
}

func (w *WebAuthnManager) finishRegistration(ctx context.Context, rw web.ResponseWriter, req *web.Request) error {
	sess := appsession.FromContext(ctx)
	data := sess.Get()
	pwe := data.Enrollment
	if err := w.checkEnrollment(ctx, pwe); err != nil {
		return err
	}

	if _, err := w.config.Users.GetUserByStringID(pwe.ForUserID); err != nil {
		return fmt.Errorf("getting user %s: %w", pwe.ForUserID, err)
	}

	keyName := pwe.KeyName

	// purge the data from the session
	returnTo := pwe.ReturnTo
	data.Enrollment = nil
	sess.Save()

	var credentialRequest json.RawMessage
	if err := req.UnmarshalJSONBody(&credentialRequest); err != nil {
		return fmt.Errorf("unmarshalling credential request: %w", err)
	}

	record, err := w.passkey.Register(credentialRequest)
	if err != nil {
		return fmt.Errorf("creating credential: %w", err)
	}

	userID, err := uuid.Parse(pwe.ForUserID)
	if err != nil {
		return fmt.Errorf("invalid user_id: %w", err)
	}

	if pwe.EnrollmentID != "" {
		enrollmentID, err := uuid.Parse(pwe.EnrollmentID)
		if err != nil {
			return fmt.Errorf("invalid enrollment_id: %w", err)
		}
		if err := admin.CompleteEnrollment(w.config, w.enrollments, w.credStore, userID, enrollmentID, record, keyName); err != nil {
			return err
		}
	} else if err := admin.StorePasskey(w.config, w.credStore, userID, record, keyName); err != nil {
		return err
	}

	return rw.WriteResponse(req, &web.JSONResponse{
		Data: map[string]any{
			"success":  true,
			"message":  "Passkey registered successfully!",
			"returnTo": returnTo,
		},
	})
}

func (w *WebAuthnManager) checkEnrollment(ctx context.Context, pwe *appsession.Enrollment) error {
	if pwe == nil || pwe.ForUserID == "" {
		return fmt.Errorf("no enroll to user id set in session")
	}
	if pwe.EnrollmentID != "" {
		enrollmentID, err := uuid.Parse(pwe.EnrollmentID)
		if err != nil {
			return fmt.Errorf("invalid enrollment_id: %w", err)
		}
		if _, err := w.enrollments.GetPendingEnrollmentByID(enrollmentID); err != nil {
			return fmt.Errorf("invalid enrollment: %w", err)
		}
		return nil
	}
	userID, ok := auth.UserIDFromContext(ctx)
	if !ok {
		return fmt.Errorf("not logged in")
	}
	if userID.String() != pwe.ForUserID {
		return fmt.Errorf("enrollment user mismatch")
	}
	return nil
}
