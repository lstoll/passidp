package oauth2as

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"database/sql"
	jsonv2 "encoding/json/v2"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"uuid"

	"lds.li/oauth2ext/dpop"
	"lds.li/oauth2ext/jwt"
	_ "modernc.org/sqlite"
)

type clientSource struct{}

func (clientSource) Client(_ context.Context, clientID string) (*Client, error) {
	return &Client{
		ID:           clientID,
		Secrets:      []string{"client-secret"},
		RedirectURIs: []string{"https://client.example/callback"},
		SkipPKCE:     true,
	}, nil
}

// newSQLiteDB returns an isolated shared in-memory database. The DSN pragmas
// are applied to every connection opened by database/sql.
func newSQLiteDB(t *testing.T) *sql.DB {
	t.Helper()
	dsn := "file:" + uuid.NewV4().String() + "?mode=memory&cache=shared&_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxIdleConns(1)
	db.SetMaxOpenConns(4)
	t.Cleanup(func() { db.Close() })
	return db
}

// newMigratedSQLStorage returns SQLite storage on a fresh database with
// migrations applied (twice, to check idempotency).
func newMigratedSQLStorage(t *testing.T) (*sql.DB, *Storage) {
	t.Helper()
	db := newSQLiteDB(t)
	store, err := NewSQLStorage(db)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Migrate(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := store.Migrate(t.Context()); err != nil {
		t.Fatalf("idempotent migrate: %v", err)
	}
	return db, store
}

func TestSQLiteStorageE2E(t *testing.T) {
	db, store := newMigratedSQLStorage(t)
	assertSQLColumnTypes(t, db)

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := jwt.NewSigningIdentity(key, "", "")
	if err != nil {
		t.Fatal(err)
	}
	verificationKeys, err := jwt.NewVerificationKeySetFromSigner(signer)
	if err != nil {
		t.Fatal(err)
	}
	dpopKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	dpopSigner, err := jwt.NewSigningIdentity(dpopKey, "", "")
	if err != nil {
		t.Fatal(err)
	}
	server, err := NewServer(Config{
		Issuer:                          "https://issuer.example",
		Storage:                         store,
		Clients:                         clientSource{},
		Signer:                          signer,
		VerificationKeys:                verificationKeys,
		DPoPVerifier:                    &dpop.Verifier{},
		Logger:                          slog.New(slog.NewTextHandler(os.Stderr, nil)),
		RefreshTokenValidity:            time.Hour,
		RefreshTokenRotationGracePeriod: time.Minute,
		TokenHandler: func(context.Context, *TokenRequest) (*TokenResponse, error) {
			return &TokenResponse{}, nil
		},
		UserinfoHandler: func(context.Context, *UserinfoRequest) (*UserinfoResponse, error) {
			return &UserinfoResponse{Identity: map[string]any{"sub": "user-1"}}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	codeForm := tokenForm("authorization_code", authorize(t, server, "user-1"))
	tokens := raceToken(t, server, codeForm, dpopSigner, "concurrent code exchange")
	if tokens["token_type"] != "DPoP" {
		t.Fatalf("token_type = %v, want DPoP", tokens["token_type"])
	}
	refresh, _ := tokens["refresh_token"].(string)
	if refresh == "" {
		t.Fatal("token response has no refresh token")
	}
	refreshForm := tokenForm("refresh_token", refresh)
	raceToken(t, server, refreshForm, dpopSigner, "concurrent refresh rotation")
	// Once the winning rotation is committed, retrying the old token within the
	// configured grace period succeeds and advances the same token family.
	if exchange(t, server, refreshForm, dpopSigner)["access_token"] == "" {
		t.Fatal("refresh response has no access token")
	}

	var lastRefresh string
	for range 2 {
		issued := exchange(t, server, tokenForm("authorization_code", authorize(t, server, "user-1")), dpopSigner)
		lastRefresh, _ = issued["refresh_token"].(string)
	}
	seen := make(map[string]struct{})
	cursor := ""
	for range 4 {
		page, err := server.ListRefreshSessions(t.Context(), RefreshSessionQuery{UserID: "user-1", Limit: 1, Cursor: cursor})
		if err != nil {
			t.Fatal(err)
		}
		if len(page.Sessions) == 0 {
			break
		}
		if len(page.Sessions) != 1 {
			t.Fatalf("page size = %d, want 1", len(page.Sessions))
		}
		grantID := page.Sessions[0].GrantID
		if _, dup := seen[grantID]; dup {
			t.Fatalf("pagination repeated grant %s", grantID)
		}
		seen[grantID] = struct{}{}
		cursor = page.NextCursor
		if cursor == "" {
			break
		}
	}
	if len(seen) != 3 {
		t.Fatalf("paginated %d sessions, want 3", len(seen))
	}
	if cursor != "" {
		t.Fatal("expected pagination to end after 3 sessions")
	}

	page, err := server.ListRefreshSessions(t.Context(), RefreshSessionQuery{UserID: "user-1"})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Sessions) != 3 {
		t.Fatalf("got %d active refresh sessions, want 3", len(page.Sessions))
	}
	if !slices.Equal(page.Sessions[0].GrantedScopes, []string{"openid", "offline_access"}) {
		t.Fatalf("granted scopes = %q, want openid offline_access", page.Sessions[0].GrantedScopes)
	}
	if err := server.RevokeRefreshSession(t.Context(), "user-1", page.Sessions[0].GrantID); err != nil {
		t.Fatal(err)
	}
	page, err = server.ListRefreshSessions(t.Context(), RefreshSessionQuery{UserID: "user-1"})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Sessions) != 2 {
		t.Fatalf("got %d sessions after revocation, want 2", len(page.Sessions))
	}

	result, err := store.Cleanup(t.Context(), CleanupOptions{Before: time.Now().Add(24 * time.Hour), Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	if result.Deleted == 0 {
		t.Fatal("cleanup deleted no records")
	}
	page, err = server.ListRefreshSessions(t.Context(), RefreshSessionQuery{UserID: "user-1"})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Sessions) != 0 {
		t.Fatalf("got %d sessions after cleanup, want 0", len(page.Sessions))
	}
	if lastRefresh == "" {
		t.Fatal("missing refresh token for post-cleanup check")
	}
	status, body := tokenResponse(server, tokenForm("refresh_token", lastRefresh), dpopSigner)
	if status != http.StatusBadRequest || body["error"] != "invalid_grant" {
		t.Fatalf("refresh after cleanup = %d %v, want 400 invalid_grant", status, body)
	}
}

func assertSQLColumnTypes(t *testing.T, db *sql.DB) {
	t.Helper()
	var schema string
	if err := db.QueryRow(`SELECT sql FROM sqlite_master WHERE type = 'table' AND name = ?`, "oauth2as_grants").Scan(&schema); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"id TEXT PRIMARY KEY",
		"granted_at TEXT NOT NULL",
		"user_id TEXT NOT NULL",
		"granted_scopes JSON NOT NULL",
		"metadata BLOB",
	} {
		if !strings.Contains(schema, want) {
			t.Fatalf("sqlite oauth2as_grants schema = %s, want %q", schema, want)
		}
	}
}

func authorize(t *testing.T, server *Server, userID string) string {
	t.Helper()
	authURL := "https://issuer.example/authorize?" + url.Values{
		"response_type": {"code"},
		"client_id":     {"client-1"},
		"redirect_uri":  {"https://client.example/callback"},
		"scope":         {"openid offline_access"},
		"state":         {"state"},
	}.Encode()
	authRequest, err := server.ParseAuthRequest(httptest.NewRequest(http.MethodGet, authURL, nil))
	if err != nil {
		t.Fatal(err)
	}
	redirect, err := server.GrantAuth(t.Context(), &AuthGrant{
		Request:       authRequest,
		GrantedScopes: authRequest.Scopes,
		UserID:        userID,
	})
	if err != nil {
		t.Fatal(err)
	}
	redirectURL, err := url.Parse(redirect)
	if err != nil {
		t.Fatal(err)
	}
	code := redirectURL.Query().Get("code")
	if code == "" {
		t.Fatal("authorization response has no code")
	}
	return code
}

func tokenForm(grantType, credential string) url.Values {
	form := url.Values{
		"grant_type":    {grantType},
		"redirect_uri":  {"https://client.example/callback"},
		"client_id":     {"client-1"},
		"client_secret": {"client-secret"},
	}
	if grantType == "authorization_code" {
		form.Set("code", credential)
	} else {
		form.Set("refresh_token", credential)
	}
	return form
}

func raceToken(t *testing.T, server *Server, form url.Values, signer *jwt.SigningIdentity, name string) map[string]any {
	t.Helper()
	type tokenResult struct {
		status int
		body   map[string]any
	}
	results := make(chan tokenResult, 2)
	for range 2 {
		go func() {
			status, body := tokenResponse(server, form, signer)
			results <- tokenResult{status: status, body: body}
		}()
	}
	var winner map[string]any
	successes, failures := 0, 0
	for range 2 {
		result := <-results
		if result.status == http.StatusOK {
			successes++
			winner = result.body
			continue
		}
		failures++
		if result.status != http.StatusBadRequest || result.body["error"] != "invalid_grant" {
			t.Fatalf("%s loser = %d %v, want 400 invalid_grant", name, result.status, result.body)
		}
	}
	if successes != 1 || failures != 1 {
		t.Fatalf("%s produced %d successes and %d failures, want 1 each", name, successes, failures)
	}
	return winner
}

func exchange(t *testing.T, server *Server, form url.Values, signer *jwt.SigningIdentity) map[string]any {
	t.Helper()
	status, response := tokenResponse(server, form, signer)
	if status != http.StatusOK {
		t.Fatalf("token endpoint returned %d: %v", status, response)
	}
	return response
}

func tokenResponse(server *Server, form url.Values, signer *jwt.SigningIdentity) (int, map[string]any) {
	req := httptest.NewRequest(http.MethodPost, "https://issuer.example/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	proof, err := dpop.Sign(req.Context(), signer, dpop.ProofOptions{HTTPMethod: http.MethodPost, HTTPURI: "https://issuer.example/token"})
	if err != nil {
		return 0, map[string]any{"proof_error": err.Error()}
	}
	req.Header.Set("DPoP", proof)
	rec := httptest.NewRecorder()
	server.TokenHandler(rec, req)
	var response map[string]any
	if err := jsonv2.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		response = map[string]any{"decode_error": err.Error(), "body": rec.Body.String()}
	}
	return rec.Code, response
}

func TestSQLiteMigrateNewerSchema(t *testing.T) {
	db, store := newMigratedSQLStorage(t)

	var table string
	if err := db.QueryRow(`SELECT name FROM sqlite_master WHERE type = 'table' AND name = ?`, "oauth2as_grants").Scan(&table); err != nil {
		t.Fatalf("grants table missing: %v", err)
	}

	if _, err := db.Exec(`INSERT INTO oauth2as_schema_migrations (version, name, applied_at) VALUES (99, 'future', '1970-01-01T00:00:00.000000Z')`); err != nil {
		t.Fatal(err)
	}
	err := store.Migrate(t.Context())
	if err == nil || !strings.Contains(err.Error(), "newer than this library") {
		t.Fatalf("Migrate() error = %v, want newer-schema error", err)
	}
}

func TestSQLStorageConstructorValidation(t *testing.T) {
	if _, err := NewSQLStorage(nil); err == nil {
		t.Fatal("nil database accepted")
	}
}

func TestSQLiteStorageConformance(t *testing.T) {
	testStorage(t, func(t *testing.T) *Storage {
		_, store := newMigratedSQLStorage(t)
		return store
	})
}
