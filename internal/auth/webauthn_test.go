package auth

import (
	"database/sql"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/descope/virtualwebauthn"
	_ "github.com/mattn/go-sqlite3"

	"encoding/base64"

	"bytes"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
	"lds.li/web/session"
	"lds.li/web/webtest"
	dbpkg "lds.li/webauthn-oidc-idp/db"
	"lds.li/webauthn-oidc-idp/internal/config"
	"lds.li/webauthn-oidc-idp/internal/storage"
	"lds.li/webauthn-oidc-idp/internal/webcommon"
)

func TestWebauthnAuth(t *testing.T) {
	sqldb, err := sql.Open("sqlite3", "file:test.db?mode=memory&cache=shared")
	if err != nil {
		t.Fatalf("open in-memory database: %v", err)
	}
	t.Cleanup(func() {
		_ = sqldb.Close()
	})

	if err := dbpkg.Migrate(t.Context(), sqldb); err != nil {
		t.Fatalf("run migrations: %v", err)
	}

	wn, err := webauthn.New(&webauthn.Config{
		RPID:          "test",
		RPDisplayName: "Test",
		RPOrigins:     []string{"https://example.com"},
	})
	if err != nil {
		t.Fatalf("create webauthn: %v", err)
	}

	credStore, err := storage.NewCredentialStore(t.TempDir() + "/credential-store.json")
	if err != nil {
		t.Fatalf("create credential store: %v", err)
	}

	auth := &Authenticator{
		Webauthn:  wn,
		CredStore: credStore,
		Config:    &config.Config{ParsedSessionDuration: 1 * time.Hour},
	}

	t.Run("login", func(t *testing.T) {
		// Create a user with a registered credential
		authenticator, credential, _ := createUserWithCredential(t, auth)

		// We keep this as a pointer, so we can mutate and track it over time.
		// This feels bad though, we should update the lstoll/web test stuff to
		// handle this all better.
		as := &authSess{}

		lrw := httptest.NewRecorder()
		lrr := httptest.NewRequest("GET", "/needredir", nil)
		lrctx, _ := session.TestContext(lrr.Context(), nil)
		session.MustFromContext(lrctx).Set(authSessSessionKey, as)
		lrr = lrr.WithContext(lrctx)

		auth.TriggerLogin(lrw, lrr, "/dashboard")

		if lrw.Result().StatusCode != http.StatusSeeOther {
			t.Fatalf("expected redirect, got %d", lrw.Result().StatusCode)
		}
		if lrw.Result().Header.Get("Location") == "" {
			t.Fatalf("expected redirect, got no location")
		}

		req := webtest.NewRequest("GET", lrw.Result().Header.Get("Location"),
			webtest.RequestWithSessionValues(map[string]any{authSessSessionKey: as}),
			webtest.RequestWithStaticContent(webcommon.Static, "/static"),
		)

		rw := webtest.NewResponse()
		if err := auth.HandleLoginPage(req.RawRequest().Context(), rw, req); err != nil {
			t.Fatalf("handle login page: %v", err)
		}

		if rw.Result().StatusCode != http.StatusOK {
			t.Fatalf("expected status OK, got %d", rw.Result().StatusCode)
		}

		body, err := io.ReadAll(rw.Result().Body)
		if err != nil {
			t.Fatalf("read response body: %v", err)
		}

		reFlowID := regexp.MustCompile(`<div\s+data-flow-id="([^"]+)"`)
		reChallenge := regexp.MustCompile(`<div\s+data-webauthn-challenge="([^"]+)"`)

		flowIDMatch := reFlowID.FindSubmatch(body)
		if flowIDMatch == nil {
			t.Fatalf("could not find data-flow-id in response body")
		}
		extractedFlowID := string(flowIDMatch[1])

		challengeMatch := reChallenge.FindSubmatch(body)
		if challengeMatch == nil {
			t.Fatalf("could not find data-webauthn-challenge in response body")
		}
		extractedChallenge := string(challengeMatch[1])

		// Create assertion response using virtual authenticator
		challengeBytes, err := base64.RawURLEncoding.DecodeString(extractedChallenge)
		if err != nil {
			t.Fatalf("decode challenge: %v", err)
		}

		assertionResponse := virtualwebauthn.CreateAssertionResponse(
			virtualwebauthn.RelyingParty{
				ID:     "test",
				Name:   "Test",
				Origin: "https://example.com",
			},
			authenticator,
			credential,
			virtualwebauthn.AssertionOptions{
				Challenge:      challengeBytes,
				RelyingPartyID: "test",
			},
		)

		// Parse the assertion response to get the proper structure
		var assertionData map[string]any
		if err := json.Unmarshal([]byte(assertionResponse), &assertionData); err != nil {
			t.Fatalf("unmarshal assertion response: %v", err)
		}

		// Prepare login submission data
		loginData := map[string]any{
			"flowID":                      extractedFlowID,
			"credentialAssertionResponse": assertionData,
		}

		// Now submit the login request
		loginReq := webtest.NewRequest("POST", "/finishWebauthnLogin",
			// TODO - this only works because the previous session stuff mutates
			// the data in place. This isn't awesome, so we should make sure we
			// have a better way to track and update a session over time.
			webtest.RequestWithSessionValues(map[string]any{authSessSessionKey: as}),
			webtest.RequestWithJSONBody(loginData),
		)

		loginRw := webtest.NewResponse()
		if err := auth.DoLogin(loginReq.RawRequest().Context(), loginRw, loginReq); err != nil {
			t.Fatalf("do login: %v", err)
		}

		if loginRw.Result().StatusCode != http.StatusOK {
			t.Fatalf("expected login status OK, got %d", loginRw.Result().StatusCode)
		}

		loginResponseBody, err := io.ReadAll(loginRw.Result().Body)
		if err != nil {
			t.Fatalf("read login response body: %v", err)
		}

		t.Logf("login response: %s", string(loginResponseBody))

		// Parse the response to check for returnTo
		var loginResponse struct {
			ReturnTo string `json:"returnTo"`
			Error    string `json:"error"`
		}
		if err := json.Unmarshal(loginResponseBody, &loginResponse); err != nil {
			t.Fatalf("unmarshal login response: %v", err)
		}

		if loginResponse.Error != "" {
			t.Fatalf("login failed with error: %s", loginResponse.Error)
		}

		t.Logf("login successful, returnTo: %s", loginResponse.ReturnTo)

		if as.ExpiresAt.IsZero() {
			t.Fatal("ExpiresAt not set after login")
		}

		t.Run("session_expiry", func(t *testing.T) {
			// Manually expire the session
			as.ExpiresAt = time.Now().Add(-1 * time.Second)

			// Try to access a protected resource (e.g., HandleIndex)
			req := webtest.NewRequest("GET", "/",
				webtest.RequestWithSessionValues(map[string]any{authSessSessionKey: as}),
			)
			rw := webtest.NewResponse()

			// HandleIndex checks UserIDFromContext
			if err := auth.HandleIndex(req.RawRequest().Context(), rw, req); err == nil {
				t.Error("expected error due to expired session, got nil")
			} else {
				// The error message depends on implementation, but likely "user not logged in"
				if !strings.Contains(err.Error(), "user not logged in") {
					t.Errorf("expected 'user not logged in' error, got: %v", err)
				}
			}
		})
	})
}

// Helper function to create a user with a registered credential. When we re-do
// registration, we should probably replace this with that.
func createUserWithCredential(t *testing.T, auth *Authenticator) (virtualwebauthn.Authenticator, virtualwebauthn.Credential, uuid.UUID) {
	userID := uuid.New()
	webauthnHandle := uuid.New()

	auth.Config.Users = append(auth.Config.Users, &config.User{
		ID:             userID,
		Email:          "test@example.com",
		FullName:       "Test User",
		WebauthnHandle: webauthnHandle,
	})

	// Create a webauthn user for registration
	wu := &WebAuthnUser{
		user: &config.User{
			ID:             userID,
			Email:          "test@example.com",
			FullName:       "Test User",
			WebauthnHandle: webauthnHandle,
		},
		overrideID: webauthnHandle[:],
	}

	// Begin registration
	options, sessionData, err := auth.Webauthn.BeginRegistration(wu)
	if err != nil {
		t.Fatalf("begin registration: %v", err)
	}

	// Create virtual authenticator for registration
	authenticator := virtualwebauthn.NewAuthenticator()
	authenticator.Options.UserHandle = webauthnHandle[:]
	credential := virtualwebauthn.NewCredential(virtualwebauthn.KeyTypeEC2)
	authenticator.AddCredential(credential)

	// Create attestation response
	challengeBytes := []byte(options.Response.Challenge)

	attestationResponse := virtualwebauthn.CreateAttestationResponse(
		virtualwebauthn.RelyingParty{
			ID:     "test",
			Name:   "Test",
			Origin: "https://example.com",
		},
		authenticator,
		credential,
		virtualwebauthn.AttestationOptions{
			Challenge:       challengeBytes,
			RelyingPartyID:  "test",
			UserID:          string(webauthnHandle[:]),
			UserName:        "test@example.com",
			UserDisplayName: "Test User",
		},
	)

	// Create the credential using go-webauthn
	parsedResponse, err := protocol.ParseCredentialCreationResponseBody(bytes.NewReader([]byte(attestationResponse)))
	if err != nil {
		t.Fatalf("parse credential creation response: %v", err)
	}

	createdCredential, err := auth.Webauthn.CreateCredential(wu, *sessionData, parsedResponse)
	if err != nil {
		t.Fatalf("create credential: %v", err)
	}

	if err := auth.CredStore.Write(func(cs *storage.CredentialStore) error {
		cs.Credentials = append(cs.Credentials, &storage.Credential{
			ID:             uuid.New(),
			CredentialID:   createdCredential.ID,
			CredentialData: createdCredential,
			Name:           "Test Credential",
			UserID:         userID,
		})
		return nil
	}); err != nil {
		t.Fatalf("write credential to store: %v", err)
	}

	return authenticator, credential, webauthnHandle
}
