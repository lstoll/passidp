package oauth2as_test

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"golang.org/x/oauth2"
	"lds.li/oauth2ext/oidc"
	"lds.li/oauth2ext/provider"
	"lds.li/passidp/internal/oauth2as"
	"lds.li/passidp/internal/oauth2as/discovery"
	"lds.li/passidp/internal/oauth2as/oauth2proto"
)

func TestEncryptedMetadataFlow(t *testing.T) {
	const (
		clientID         = "client-id"
		clientSecret     = "client-secret"
		expectedMetadata = "secret-metadata-payload"
	)

	ctx := context.Background()

	// Capture the metadata seen by the token handler
	var metadataSeenByHandler []byte
	// Channel to signal that the handler was called
	handlerCalled := make(chan struct{}, 1)

	callbackChan := make(chan string, 1)
	state := "state-val"

	cliSvr := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if errMsg := req.FormValue("error"); errMsg != "" {
			t.Errorf("error returned to callback %s: %s", errMsg, req.FormValue("error_description"))
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		code := req.FormValue("code")
		if code == "" {
			t.Error("no code in callback response")
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		callbackChan <- code
	}))
	defer cliSvr.Close()

	clientSource := staticClientSource{
		{
			ID:           clientID,
			Secrets:      []string{clientSecret},
			RedirectURIs: []string{cliSvr.URL},
			Public:       false,
			SkipPKCE:     true,
		},
	}

	s := newTestStorage(t)

	oidcSvrMux := http.NewServeMux()
	oidcSvr := httptest.NewServer(oidcSvrMux)
	t.Cleanup(oidcSvr.Close)

	signer, jwtVerifier := getTestSigner(t)

	opcfg := oauth2as.Config{
		Issuer:               oidcSvr.URL,
		Storage:              s,
		Signer:               signer,
		VerificationKeys:     jwtVerifier,
		RefreshTokenValidity: 1 * time.Hour,
		GrantValidity:        1 * time.Hour,
		TokenHandler: func(_ context.Context, req *oauth2as.TokenRequest) (*oauth2as.TokenResponse, error) {
			metadataSeenByHandler = req.DecryptedMetadata
			handlerCalled <- struct{}{}
			return &oauth2as.TokenResponse{}, nil
		},
		UserinfoHandler: func(_ context.Context, uireq *oauth2as.UserinfoRequest) (*oauth2as.UserinfoResponse, error) {
			return &oauth2as.UserinfoResponse{
				Identity: map[string]any{
					"sub": uireq.Subject,
				},
			}, nil
		},
		Clients: clientSource,
		Logger:  slog.New(slog.NewTextHandler(io.Discard, nil)),
	}

	op, err := oauth2as.NewServer(opcfg)
	if err != nil {
		t.Fatal(err)
	}

	oidcSvrMux.HandleFunc("/token", op.TokenHandler)
	oidcSvrMux.HandleFunc("/userinfo", op.UserinfoHandler)

	pmd := discovery.DefaultCoreMetadata(oidcSvr.URL)
	pmd.AuthorizationEndpoint = oidcSvr.URL + "/authorization"
	pmd.TokenEndpoint = oidcSvr.URL + "/token"
	pmd.UserinfoEndpoint = oidcSvr.URL + "/userinfo"
	pmd.IDTokenSigningAlgValuesSupported = []string{string("RS256"), string("ES256")}

	ch, err := discovery.NewOIDCConfigurationHandler(discovery.ConfigurationHandlerConfig{
		Metadata:         pmd,
		VerificationKeys: jwtVerifier,
	})
	if err != nil {
		t.Fatal(err)
	}
	oidcSvrMux.Handle("GET /.well-known/", ch)

	// Add authorization endpoint handler
	oidcSvrMux.HandleFunc("/authorization", func(w http.ResponseWriter, req *http.Request) {
		authReq, err := op.ParseAuthRequest(req)
		if err != nil {
			_ = oauth2proto.WriteError(w, req, err)
			return
		}

		grant := &oauth2as.AuthGrant{
			Request:           authReq,
			GrantedScopes:     authReq.Scopes,
			UserID:            "test-user",
			EncryptedMetadata: []byte(expectedMetadata), // Set the metadata here
		}

		redirectURI, err := op.GrantAuth(ctx, grant)
		if err != nil {
			t.Errorf("failed to grant auth: %v", err)
			http.Error(w, "authorization failed", http.StatusInternalServerError)
			return
		}

		http.Redirect(w, req, redirectURI, http.StatusFound)
	})

	provider, err := provider.DiscoverOIDCProvider(ctx, oidcSvr.URL)
	if err != nil {
		t.Fatal(err)
	}

	o2 := &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Endpoint:     provider.Endpoint(),
		RedirectURL:  cliSvr.URL,
		Scopes:       []string{oidc.ScopeOfflineAccess},
	}

	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := client.Get(o2.AuthCodeURL(state))
	if err != nil {
		t.Fatalf("error getting auth URL: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("expected status found, got %d", resp.StatusCode)
	}

	redirectURL := resp.Header.Get("Location")
	if redirectURL == "" {
		t.Fatal("no Location header in redirect response")
	}

	callbackResp, err := client.Get(redirectURL)
	if err != nil {
		t.Fatalf("error following redirect: %v", err)
	}
	callbackResp.Body.Close()

	var callbackCode string
	select {
	case callbackCode = <-callbackChan:
	case <-time.After(1 * time.Second):
		t.Fatal("waiting for callback timed out after 1s")
	}

	// Exchange Code for Token
	tok, err := o2.Exchange(ctx, callbackCode)
	if err != nil {
		t.Fatalf("error exchanging code %q for token: %v", callbackCode, err)
	}

	// Check if handler saw the metadata during code exchange
	select {
	case <-handlerCalled:
		if !bytes.Equal(metadataSeenByHandler, []byte(expectedMetadata)) {
			t.Errorf("metadata mismatch during code exchange. got %q, want %q", metadataSeenByHandler, expectedMetadata)
		}
	case <-time.After(1 * time.Second):
		t.Fatal("handler was not called during code exchange")
	}

	ts := o2.TokenSource(ctx, tok)

	// Perform refreshes
	for i := range 3 {
		t.Logf("refresh iter: %d", i)

		// Force refresh by expiring the token locally
		tok.Expiry = time.Now().Add(-1 * time.Second)

		// Using TokenSource to get a new token will trigger refresh
		nt, err := ts.Token()
		if err != nil {
			t.Fatalf("refresh failed: %v", err)
		}

		// Check if handler saw the metadata during refresh
		select {
		case <-handlerCalled:
			if !bytes.Equal(metadataSeenByHandler, []byte(expectedMetadata)) {
				t.Errorf("metadata mismatch during refresh %d. got %q, want %q", i, metadataSeenByHandler, expectedMetadata)
			}
		case <-time.After(1 * time.Second):
			t.Fatal("handler was not called during refresh")
		}

		tok = nt
	}
}
