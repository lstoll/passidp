package auth

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/descope/virtualwebauthn"

	"uuid"

	"filippo.io/passkey"
	"lds.li/passidp/internal/appsession"
	"lds.li/passidp/internal/config"
	"lds.li/passidp/internal/storage"
	"lds.li/passidp/internal/webcommon"
	"lds.li/session"
	"lds.li/session/sessiontest"
	"lds.li/web"
	"lds.li/web/webtest"
)

const (
	testRPID   = "test.example.com"
	testOrigin = "https://example.com"
)

func TestWebauthnAuth(t *testing.T) {
	rp, err := passkey.NewRelyingParty(testRPID, testOrigin, passkey.Options{})
	if err != nil {
		t.Fatalf("create relying party: %v", err)
	}

	credStore, err := storage.NewCredentialFile(t.TempDir() + "/credential-store.json")
	if err != nil {
		t.Fatalf("create credential store: %v", err)
	}

	auth := &Authenticator{
		Passkey:   rp,
		CredStore: credStore,
		Config:    &config.Config{SessionDuration: config.JSONDuration(1 * time.Hour)},
	}

	t.Run("login_c2sp", func(t *testing.T) {
		authenticator, credential, _ := createUserWithPasskey(t, auth, nil)
		as := doTestLogin(t, auth, authenticator, credential)

		t.Run("session_expiry", func(t *testing.T) {
			as.ExpiresAt = time.Now().Add(-1 * time.Second)

			req, _ := requestWithSession(t, "GET", "/",
				appsession.Data{Auth: as},
			)
			rw := webtest.NewResponse()

			if err := auth.HandleIndex(req.RawRequest().Context(), rw, req); err == nil {
				t.Error("expected error due to expired session, got nil")
			} else if !strings.Contains(err.Error(), "user not logged in") {
				t.Errorf("expected 'user not logged in' error, got: %v", err)
			}
		})
	})

	t.Run("login_legacy_user_ids", func(t *testing.T) {
		t.Run("raw_uuid_bytes", func(t *testing.T) {
			handle := uuid.MustParse("70e0b33f-9ae9-4127-824b-7ad384c0de29")
			authenticator, credential, _ := createUserWithPasskey(t, auth, func(u *config.User) string {
				u.WebauthnHandle = handle
				return string(handle[:])
			})
			doTestLogin(t, auth, authenticator, credential)
		})
		t.Run("account_uuid_string", func(t *testing.T) {
			authenticator, credential, _ := createUserWithPasskey(t, auth, func(u *config.User) string {
				return u.ID.String()
			})
			doTestLogin(t, auth, authenticator, credential)
		})
		t.Run("override_subject", func(t *testing.T) {
			authenticator, credential, _ := createUserWithPasskey(t, auth, func(u *config.User) string {
				u.Metadata = map[string]any{"overrideSubject": "legacy-subject"}
				return "legacy-subject"
			})
			doTestLogin(t, auth, authenticator, credential)
		})
	})

	t.Run("login_imported_legacy_blob", func(t *testing.T) {
		authenticator, credential, userID := createUserWithPasskey(t, auth, nil)
		var (
			record  json.RawMessage
			name    string
			id      uuid.UUID
			created time.Time
		)
		auth.CredStore.Read(func(cs *storage.CredentialStore) {
			for _, pu := range cs.Users {
				if pu.AccountID != userID {
					continue
				}
				if len(pu.Passkeys) != 1 {
					t.Fatalf("expected 1 passkey, got %d", len(pu.Passkeys))
				}
				pk := pu.Passkeys[0]
				id, name, created = pk.ID, pk.Name, pk.CreatedAt
				blob, err := json.Marshal(map[string]any{
					"attestation": map[string][]byte{
						"authenticatorData": mustAuthDataFromRecord(t, pk.Record),
					},
				})
				if err != nil {
					t.Fatal(err)
				}
				record = blob
			}
		})
		if err := auth.CredStore.Write(func(cs *storage.CredentialStore) error {
			for _, pu := range cs.Users {
				if pu.AccountID == userID {
					pu.Passkeys = nil
				}
			}
			cs.Credentials = append(cs.Credentials, &storage.Credential{
				ID:             id,
				UserID:         userID,
				Name:           name,
				CredentialData: record,
				CreatedAt:      created,
			})
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		if err := auth.CredStore.ApplyConfig(auth.Config.Users, testRPID); err != nil {
			t.Fatal(err)
		}
		doTestLogin(t, auth, authenticator, credential)
	})
}

func TestLookupUser(t *testing.T) {
	rp, err := passkey.NewRelyingParty(testRPID, testOrigin, passkey.Options{})
	if err != nil {
		t.Fatal(err)
	}
	credStore, err := storage.NewCredentialFile(t.TempDir() + "/credential-store.json")
	if err != nil {
		t.Fatal(err)
	}

	accountID := uuid.MustParse("4854735c-5a01-4a2d-b7a0-330a5b5928a9")
	handle := uuid.MustParse("aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee")
	user := &config.User{
		ID:             accountID,
		Email:          "legacy@example.com",
		FullName:       "Legacy User",
		WebauthnHandle: handle,
		Metadata:       map[string]any{"overrideSubject": "custom-subject"},
	}
	if err := credStore.Write(func(cs *storage.CredentialStore) error {
		cs.EnsurePasskeyUser(accountID, user.PasskeyHandleAliases())
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	auth := &Authenticator{
		Passkey:   rp,
		CredStore: credStore,
		Config:    &config.Config{Users: config.Users{user}},
	}

	mustFind := func(t *testing.T, userID string) {
		t.Helper()
		got, err := auth.lookupUser(userID)
		if err != nil {
			t.Fatalf("lookup %q: %v", userID, err)
		}
		if got.ID != accountID {
			t.Fatalf("lookup %q: got %s, want %s", userID, got.ID, accountID)
		}
	}

	var passkeyUserID string
	credStore.Read(func(cs *storage.CredentialStore) {
		passkeyUserID, _ = cs.PasskeyUserID(accountID)
	})
	mustFind(t, passkeyUserID)
	mustFind(t, string(handle[:]))
	mustFind(t, accountID.String())
	mustFind(t, "custom-subject")
}

func doTestLogin(t *testing.T, auth *Authenticator, authenticator virtualwebauthn.Authenticator, credential virtualwebauthn.Credential) appsession.Auth {
	t.Helper()

	as := appsession.Auth{}

	lrw := httptest.NewRecorder()
	lrr := httptest.NewRequest("GET", "/needredir", nil)
	auth.TriggerLogin(lrw, lrr, "/dashboard")

	if lrw.Result().StatusCode != http.StatusSeeOther {
		t.Fatalf("expected redirect, got %d", lrw.Result().StatusCode)
	}
	if lrw.Result().Header.Get("Location") == "" {
		t.Fatalf("expected redirect, got no location")
	}

	if len(as.Flows) != 0 {
		t.Fatalf("expected no flows to be created in session during TriggerLogin, got %d", len(as.Flows))
	}

	req, change := requestWithSession(t, "GET", lrw.Result().Header.Get("Location"),
		appsession.Data{Auth: as},
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
	flowIDMatch := reFlowID.FindSubmatch(body)
	if flowIDMatch == nil {
		t.Fatalf("could not find data-flow-id in response body")
	}
	extractedFlowID := string(flowIDMatch[1])

	beginReq, beginChange := requestWithSession(t, "POST", "/login/begin",
		change.Data(),
		webtest.RequestWithJSONBody(map[string]any{"flowID": extractedFlowID}),
	)

	beginRw := webtest.NewResponse()
	if err := auth.BeginLogin(beginReq.RawRequest().Context(), beginRw, beginReq); err != nil {
		t.Fatalf("begin login: %v", err)
	}
	if beginRw.Result().StatusCode != http.StatusOK {
		t.Fatalf("expected begin status OK, got %d", beginRw.Result().StatusCode)
	}

	optionsJSON, err := io.ReadAll(beginRw.Result().Body)
	if err != nil {
		t.Fatalf("read begin response body: %v", err)
	}

	assertionOptions, err := virtualwebauthn.ParseAssertionOptions(string(optionsJSON))
	if err != nil {
		t.Fatalf("parse assertion options: %v", err)
	}

	assertionResponse := virtualwebauthn.CreateAssertionResponse(
		virtualwebauthn.RelyingParty{
			ID:     testRPID,
			Name:   "Test",
			Origin: testOrigin,
		},
		authenticator,
		credential,
		*assertionOptions,
	)

	loginData := map[string]any{
		"flowID":                      extractedFlowID,
		"credentialAssertionResponse": json.RawMessage(assertionResponse),
	}

	loginReq, loginChange := requestWithSession(t, "POST", "/finishWebauthnLogin",
		beginChange.Data(),
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

	as = loginChange.Data().Auth
	if as.ExpiresAt.IsZero() {
		t.Fatal("ExpiresAt not set after login")
	}
	if as.AuthenticatedAt.IsZero() {
		t.Fatal("AuthenticatedAt not set after login")
	}
	return as
}

func createUserWithPasskey(t *testing.T, auth *Authenticator, registrationUserID func(*config.User) string) (virtualwebauthn.Authenticator, virtualwebauthn.Credential, uuid.UUID) {
	t.Helper()
	userID := uuid.New()
	user := &config.User{
		ID:             userID,
		Email:          "c2sp-" + userID.String() + "@example.com",
		FullName:       "C2SP User",
		WebauthnHandle: uuid.New(),
	}
	var registerID string
	if registrationUserID != nil {
		registerID = registrationUserID(user)
	}
	auth.Config.Users = append(auth.Config.Users, user)

	var passkeyUserID string
	if err := auth.CredStore.Write(func(cs *storage.CredentialStore) error {
		pu := cs.EnsurePasskeyUser(userID, user.PasskeyHandleAliases())
		passkeyUserID = pu.PasskeyUserID
		if registerID != "" {
			passkeyUserID = registerID
		}
		return nil
	}); err != nil {
		t.Fatalf("ensure passkey user: %v", err)
	}

	var records []string
	auth.CredStore.Read(func(cs *storage.CredentialStore) {
		records = cs.PasskeyRecords(userID)
	})

	optionsJSON, err := auth.Passkey.NewRegistration(passkey.User{
		ID:   passkeyUserID,
		Name: user.Email,
	}, passkey.RegistrationOptions{ExcludeCredentials: records})
	if err != nil {
		t.Fatalf("begin registration: %v", err)
	}

	attestationOptions, err := virtualwebauthn.ParseAttestationOptions(string(optionsJSON))
	if err != nil {
		t.Fatalf("parse attestation options: %v", err)
	}

	authenticator := virtualwebauthn.NewAuthenticator()
	authenticator.Options.UserHandle = []byte(passkeyUserID)
	credential := virtualwebauthn.NewCredential(virtualwebauthn.KeyTypeEC2)
	authenticator.AddCredential(credential)

	attestationResponse := virtualwebauthn.CreateAttestationResponse(
		virtualwebauthn.RelyingParty{
			ID:     testRPID,
			Name:   "Test",
			Origin: testOrigin,
		},
		authenticator,
		credential,
		*attestationOptions,
	)

	record, err := auth.Passkey.Register([]byte(attestationResponse))
	if err != nil {
		t.Fatalf("register passkey: %v", err)
	}

	if err := auth.CredStore.Write(func(cs *storage.CredentialStore) error {
		cs.AddPasskey(userID, user.PasskeyHandleAliases(), &storage.Passkey{
			ID:        uuid.New(),
			Record:    record,
			Name:      "C2SP Credential",
			CreatedAt: time.Now(),
		})
		return nil
	}); err != nil {
		t.Fatalf("write passkey: %v", err)
	}

	return authenticator, credential, userID
}

func requestWithSession(t *testing.T, method, url string, data appsession.Data, opts ...webtest.RequestOpt) (*web.Request, *sessiontest.Change[appsession.Data]) {
	t.Helper()
	req := webtest.NewRequest(method, url, opts...)
	manager, err := session.NewKVManager[appsession.Data](session.NewMemoryKV(), nil)
	if err != nil {
		t.Fatal(err)
	}
	raw, change := sessiontest.WithSession(t, req.RawRequest(), manager, data)
	raw = raw.WithContext(appsession.WithManagerContext(raw.Context(), manager))
	return web.NewRequestFrom(raw), change
}

func mustAuthDataFromRecord(t *testing.T, record string) []byte {
	t.Helper()
	rest, ok := strings.CutPrefix(record, "$webauthn$v=1$")
	if !ok {
		t.Fatalf("not a passkey record: %s", record)
	}
	if _, payload, ok := strings.Cut(rest, "$"); ok {
		rest = payload
	}
	ad, err := base64.RawStdEncoding.DecodeString(rest)
	if err != nil {
		t.Fatal(err)
	}
	return ad
}
