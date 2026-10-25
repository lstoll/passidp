package oauth2as_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"golang.org/x/oauth2"
	"lds.li/oauth2ext/oidc"
	"lds.li/passidp/internal/oauth2as"
)

func TestRefreshTokenRotationAndGrace(t *testing.T) {
	ctx := context.Background()
	const (
		clientID     = "client-id"
		clientSecret = "client-secret"
	)

	s := oauth2as.NewMemoryStorage()
	signer, jwtVerifier := getTestSigner(t)

	opcfg := oauth2as.Config{
		Issuer:           "http://localhost",
		Storage:          s,
		Signer:           signer,
		VerificationKeys: jwtVerifier,
		TokenHandler: func(_ context.Context, req *oauth2as.TokenRequest) (*oauth2as.TokenResponse, error) {
			return &oauth2as.TokenResponse{}, nil
		},
		UserinfoHandler: func(_ context.Context, _ *oauth2as.UserinfoRequest) (*oauth2as.UserinfoResponse, error) {
			return &oauth2as.UserinfoResponse{}, nil
		},
		Clients: staticClientSource{
			{
				ID:           clientID,
				Secrets:      []string{clientSecret},
				RedirectURLs: []string{"http://localhost/callback"},
				Opts:         []oauth2as.ClientOpt{oauth2as.ClientOptSkipPKCE()},
			},
		},
		RefreshTokenRotationGracePeriod: 1 * time.Second,
		RefreshTokenValidity:            1 * time.Hour,
		GrantValidity:                   1 * time.Hour,
	}

	op, err := oauth2as.NewServer(opcfg)
	if err != nil {
		t.Fatal(err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/token", op.TokenHandler)
	tsrv := httptest.NewServer(mux)
	defer tsrv.Close()

	o2 := &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Endpoint: oauth2.Endpoint{
			TokenURL: tsrv.URL + "/token",
		},
		RedirectURL: "http://localhost/callback",
		Scopes:      []string{oidc.ScopeOfflineAccess},
	}

	// 1. Manually create a grant and an initial refresh token
	authReq := &oauth2as.AuthRequest{
		ClientID:    clientID,
		RedirectURI: "http://localhost/callback",
		Scopes:      []string{oidc.ScopeOfflineAccess},
	}
	grant := &oauth2as.AuthGrant{
		Request:       authReq,
		GrantedScopes: authReq.Scopes,
		UserID:        "test-user",
	}

	redir, err := op.GrantAuth(ctx, grant)
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(redir)
	code := u.Query().Get("code")

	tok, err := o2.Exchange(ctx, code)
	if err != nil {
		t.Fatalf("initial exchange failed: %v", err)
	}

	rt1 := tok.RefreshToken
	if rt1 == "" {
		t.Fatal("no refresh token issued")
	}
	t.Logf("RT1: %s", rt1)

	// 2. Refresh for the first time (RT1 -> RT2)
	tok.Expiry = time.Now().Add(-1 * time.Hour) // Force refresh
	tok2, err := o2.TokenSource(ctx, tok).Token()
	if err != nil {
		t.Fatalf("first refresh failed: %v", err)
	}
	rt2 := tok2.RefreshToken
	t.Logf("RT2: %s", rt2)
	if rt2 == "" || rt2 == rt1 {
		t.Fatalf("RT2 should be new and different from RT1")
	}

	// 3. Retry with RT1 (Inside Grace Period)
	// According to Option 2: RT2 should be revoked, and RT3 issued.
	tok.RefreshToken = rt1
	tok.Expiry = time.Now().Add(-1 * time.Hour) // Force refresh
	tok3, err := o2.TokenSource(ctx, tok).Token()
	if err != nil {
		t.Fatalf("refresh with RT1 inside grace period failed: %v", err)
	}
	rt3 := tok3.RefreshToken
	t.Logf("RT3: %s", rt3)
	if rt3 == "" || rt3 == rt1 || rt3 == rt2 {
		t.Fatalf("RT3 should be new and different")
	}

	// Verify RT2 is now revoked (because we used RT1 again)
	_, err = o2.TokenSource(ctx, &oauth2.Token{RefreshToken: rt2, Expiry: time.Now().Add(-1 * time.Hour)}).Token()
	if err == nil {
		t.Error("RT2 should have been revoked when RT1 was reused")
	}

	// 4. Wait for grace period to expire
	time.Sleep(1100 * time.Millisecond)

	// 5. Try to use RT1 again (Outside Grace Period) -> Should revoke the grant
	_, err = o2.TokenSource(ctx, &oauth2.Token{RefreshToken: rt1, Expiry: time.Now().Add(-1 * time.Hour)}).Token()
	if err == nil {
		t.Error("RT1 outside grace period should have failed")
	}

	// 6. Verify RT3 is also gone because the whole grant was revoked
	_, err = o2.TokenSource(ctx, &oauth2.Token{RefreshToken: rt3, Expiry: time.Now().Add(-1 * time.Hour)}).Token()
	if err == nil {
		t.Error("RT3 should have been revoked because reuse was detected outside grace period")
	}
}
func TestConcurrentRefreshAttempts(t *testing.T) {
	ctx := context.Background()
	const (
		clientID     = "client-id"
		clientSecret = "client-secret"
	)

	s := oauth2as.NewMemoryStorage()
	signer, jwtVerifier := getTestSigner(t)

	opcfg := oauth2as.Config{
		Issuer:           "http://localhost",
		Storage:          s,
		Signer:           signer,
		VerificationKeys: jwtVerifier,
		TokenHandler: func(_ context.Context, req *oauth2as.TokenRequest) (*oauth2as.TokenResponse, error) {
			return &oauth2as.TokenResponse{}, nil
		},
		UserinfoHandler: func(_ context.Context, _ *oauth2as.UserinfoRequest) (*oauth2as.UserinfoResponse, error) {
			return &oauth2as.UserinfoResponse{}, nil
		},
		Clients: staticClientSource{
			{
				ID:           clientID,
				Secrets:      []string{clientSecret},
				RedirectURLs: []string{"http://localhost/callback"},
				Opts:         []oauth2as.ClientOpt{oauth2as.ClientOptSkipPKCE()},
			},
		},
		RefreshTokenRotationGracePeriod: 1 * time.Second,
		RefreshTokenValidity:            1 * time.Hour,
		GrantValidity:                   1 * time.Hour,
	}

	op, err := oauth2as.NewServer(opcfg)
	if err != nil {
		t.Fatal(err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/token", op.TokenHandler)
	tsrv := httptest.NewServer(mux)
	defer tsrv.Close()

	o2 := &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Endpoint: oauth2.Endpoint{
			TokenURL: tsrv.URL + "/token",
		},
		RedirectURL: "http://localhost/callback",
		Scopes:      []string{oidc.ScopeOfflineAccess},
	}

	// Create initial grant and get first refresh token
	authReq := &oauth2as.AuthRequest{
		ClientID:    clientID,
		RedirectURI: "http://localhost/callback",
		Scopes:      []string{oidc.ScopeOfflineAccess},
	}
	grant := &oauth2as.AuthGrant{
		Request:       authReq,
		GrantedScopes: authReq.Scopes,
		UserID:        "test-user",
	}

	redir, err := op.GrantAuth(ctx, grant)
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(redir)
	code := u.Query().Get("code")

	tok, err := o2.Exchange(ctx, code)
	if err != nil {
		t.Fatalf("initial exchange failed: %v", err)
	}

	rt1 := tok.RefreshToken
	if rt1 == "" {
		t.Fatal("no refresh token issued")
	}

	// Attempt to use the same refresh token concurrently
	tok.Expiry = time.Now().Add(-1 * time.Hour)

	type result struct {
		tok *oauth2.Token
		err error
	}
	results := make(chan result, 2)

	for range 2 {
		go func() {
			t, e := o2.TokenSource(ctx, &oauth2.Token{
				RefreshToken: rt1,
				Expiry:       time.Now().Add(-1 * time.Hour),
			}).Token()
			results <- result{tok: t, err: e}
		}()
	}

	// Collect results
	var successes int
	var failures int
	for range 2 {
		r := <-results
		if r.err == nil {
			successes++
		} else {
			failures++
		}
	}

	// At least one should succeed (first one wins)
	// The other may succeed or fail depending on timing and grace period
	if successes == 0 {
		t.Error("expected at least one concurrent refresh to succeed")
	}

	t.Logf("Concurrent refresh results: %d successes, %d failures", successes, failures)
}

func TestReplacedByTokenIDTracking(t *testing.T) {
	ctx := context.Background()
	const (
		clientID     = "client-id"
		clientSecret = "client-secret"
	)

	s := oauth2as.NewMemoryStorage()
	signer, jwtVerifier := getTestSigner(t)

	opcfg := oauth2as.Config{
		Issuer:           "http://localhost",
		Storage:          s,
		Signer:           signer,
		VerificationKeys: jwtVerifier,
		TokenHandler: func(_ context.Context, req *oauth2as.TokenRequest) (*oauth2as.TokenResponse, error) {
			return &oauth2as.TokenResponse{}, nil
		},
		UserinfoHandler: func(_ context.Context, _ *oauth2as.UserinfoRequest) (*oauth2as.UserinfoResponse, error) {
			return &oauth2as.UserinfoResponse{}, nil
		},
		Clients: staticClientSource{
			{
				ID:           clientID,
				Secrets:      []string{clientSecret},
				RedirectURLs: []string{"http://localhost/callback"},
				Opts:         []oauth2as.ClientOpt{oauth2as.ClientOptSkipPKCE()},
			},
		},
		RefreshTokenRotationGracePeriod: 1 * time.Second,
		RefreshTokenValidity:            1 * time.Hour,
		GrantValidity:                   1 * time.Hour,
	}

	op, err := oauth2as.NewServer(opcfg)
	if err != nil {
		t.Fatal(err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/token", op.TokenHandler)
	tsrv := httptest.NewServer(mux)
	defer tsrv.Close()

	o2 := &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Endpoint: oauth2.Endpoint{
			TokenURL: tsrv.URL + "/token",
		},
		RedirectURL: "http://localhost/callback",
		Scopes:      []string{oidc.ScopeOfflineAccess},
	}

	// Create initial grant
	authReq := &oauth2as.AuthRequest{
		ClientID:    clientID,
		RedirectURI: "http://localhost/callback",
		Scopes:      []string{oidc.ScopeOfflineAccess},
	}
	grant := &oauth2as.AuthGrant{
		Request:       authReq,
		GrantedScopes: authReq.Scopes,
		UserID:        "test-user",
	}

	redir, err := op.GrantAuth(ctx, grant)
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(redir)
	code := u.Query().Get("code")

	tok, err := o2.Exchange(ctx, code)
	if err != nil {
		t.Fatalf("initial exchange failed: %v", err)
	}

	rt1 := tok.RefreshToken

	// Perform refresh to create RT2
	tok.Expiry = time.Now().Add(-1 * time.Hour)
	tok2, err := o2.TokenSource(ctx, tok).Token()
	if err != nil {
		t.Fatalf("refresh failed: %v", err)
	}

	rt2 := tok2.RefreshToken
	if rt2 == "" || rt2 == rt1 {
		t.Fatal("expected new refresh token after rotation")
	}

	// Note: We can't directly access storage to verify ReplacedByTokenID
	// without exposing internal state, but we can verify behavior:
	// RT1 should still work within grace period
	tok.RefreshToken = rt1
	tok.Expiry = time.Now().Add(-1 * time.Hour)
	tok3, err := o2.TokenSource(ctx, tok).Token()
	if err != nil {
		t.Fatalf("RT1 should still work within grace period: %v", err)
	}

	rt3 := tok3.RefreshToken
	if rt3 == "" {
		t.Fatal("expected new refresh token")
	}

	// Verify that RT2 has been revoked (because RT1 was reused)
	_, err = o2.TokenSource(ctx, &oauth2.Token{
		RefreshToken: rt2,
		Expiry:       time.Now().Add(-1 * time.Hour),
	}).Token()
	if err == nil {
		t.Error("RT2 should have been revoked when RT1 was reused")
	}

	t.Log("Token rotation chain tracking verified")
}

func TestEncryptedMetadataWithRotation(t *testing.T) {
	ctx := context.Background()
	const (
		clientID     = "client-id"
		clientSecret = "client-secret"
	)

	s := oauth2as.NewMemoryStorage()
	signer, jwtVerifier := getTestSigner(t)

	const testMetadata = "secret-upstream-refresh-token"

	opcfg := oauth2as.Config{
		Issuer:           "http://localhost",
		Storage:          s,
		Signer:           signer,
		VerificationKeys: jwtVerifier,
		TokenHandler: func(_ context.Context, req *oauth2as.TokenRequest) (*oauth2as.TokenResponse, error) {
			// On initial grant, set encrypted metadata
			if !req.IsRefresh {
				return &oauth2as.TokenResponse{
					EncryptedMetadata: []byte(testMetadata),
				}, nil
			}

			// On refresh, verify we can still read the metadata
			if string(req.DecryptedMetadata) != testMetadata {
				t.Errorf("expected metadata %q, got %q", testMetadata, string(req.DecryptedMetadata))
			}

			// Return same metadata (re-encrypted with new token)
			return &oauth2as.TokenResponse{
				EncryptedMetadata: req.DecryptedMetadata,
			}, nil
		},
		UserinfoHandler: func(_ context.Context, _ *oauth2as.UserinfoRequest) (*oauth2as.UserinfoResponse, error) {
			return &oauth2as.UserinfoResponse{}, nil
		},
		Clients: staticClientSource{
			{
				ID:           clientID,
				Secrets:      []string{clientSecret},
				RedirectURLs: []string{"http://localhost/callback"},
				Opts:         []oauth2as.ClientOpt{oauth2as.ClientOptSkipPKCE()},
			},
		},
		RefreshTokenValidity: 1 * time.Hour,
		GrantValidity:        1 * time.Hour,
	}

	op, err := oauth2as.NewServer(opcfg)
	if err != nil {
		t.Fatal(err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/token", op.TokenHandler)
	tsrv := httptest.NewServer(mux)
	defer tsrv.Close()

	o2 := &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Endpoint: oauth2.Endpoint{
			TokenURL: tsrv.URL + "/token",
		},
		RedirectURL: "http://localhost/callback",
		Scopes:      []string{oidc.ScopeOfflineAccess},
	}

	// Create initial grant
	authReq := &oauth2as.AuthRequest{
		ClientID:    clientID,
		RedirectURI: "http://localhost/callback",
		Scopes:      []string{oidc.ScopeOfflineAccess},
	}
	grant := &oauth2as.AuthGrant{
		Request:       authReq,
		GrantedScopes: authReq.Scopes,
		UserID:        "test-user",
	}

	redir, err := op.GrantAuth(ctx, grant)
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(redir)
	code := u.Query().Get("code")

	tok, err := o2.Exchange(ctx, code)
	if err != nil {
		t.Fatalf("initial exchange failed: %v", err)
	}

	// Perform multiple refreshes to verify metadata survives rotation
	for i := range 3 {
		tok.Expiry = time.Now().Add(-1 * time.Hour)
		tok, err = o2.TokenSource(ctx, tok).Token()
		if err != nil {
			t.Fatalf("refresh %d failed: %v", i+1, err)
		}
		t.Logf("Refresh %d completed successfully", i+1)
	}

	t.Log("Encrypted metadata persisted correctly through multiple token rotations")
}
