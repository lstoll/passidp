package oauth2as_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/oauth2"
	"lds.li/oauth2ext/clitoken"
	"lds.li/oauth2ext/dpop"
	"lds.li/oauth2ext/jwt"
	"lds.li/oauth2ext/oauth2client"
	"lds.li/oauth2ext/oidc"
	"lds.li/oauth2ext/tokencache"
	"lds.li/passidp/internal/oauth2as"
	"lds.li/passidp/internal/oauth2as/internal"
)

func TestOAuth2ExtDPoPClientFlowAndRefresh(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()

	storage := newTestStorage(t)

	const clientID = "public-cli"
	clients := loopbackClientSource{id: clientID}
	signer := internal.NewTestSigner(t, jwt.ES256)
	verificationKeys, err := jwt.NewVerificationKeySetFromSigner(signer)
	if err != nil {
		t.Fatal(err)
	}
	replayStore, err := dpop.NewInMemoryReplayStore(100)
	if err != nil {
		t.Fatal(err)
	}
	handlerErrors := make(chan error, 2)
	authorizationRequests := make(chan url.Values, 1)
	mux := http.NewServeMux()
	issuerServer := httptest.NewServer(mux)
	t.Cleanup(issuerServer.Close)
	issuer := issuerServer.URL
	server, err := oauth2as.NewServer(oauth2as.Config{
		Issuer:               issuer,
		Storage:              storage,
		Clients:              clients,
		Signer:               signer,
		VerificationKeys:     verificationKeys,
		DPoPVerifier:         &dpop.Verifier{ReplayStore: replayStore},
		RefreshTokenValidity: time.Hour,
		GrantValidity:        4 * time.Hour,
		TokenHandler: func(context.Context, *oauth2as.TokenRequest) (*oauth2as.TokenResponse, error) {
			return &oauth2as.TokenResponse{}, nil
		},
		UserinfoHandler: func(_ context.Context, req *oauth2as.UserinfoRequest) (*oauth2as.UserinfoResponse, error) {
			return &oauth2as.UserinfoResponse{Identity: map[string]any{"sub": req.Subject, "name": "Test User"}}, nil
		},
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	mux.HandleFunc("GET /authorization", func(w http.ResponseWriter, req *http.Request) {
		select {
		case authorizationRequests <- req.URL.Query():
		default:
		}
		authReq, err := server.ParseAuthRequest(req)
		if err != nil {
			select {
			case handlerErrors <- fmt.Errorf("parse authorization request: %w", err):
			default:
			}
			http.Error(w, "invalid authorization request", http.StatusBadRequest)
			return
		}
		redirect, err := server.GrantAuth(req.Context(), &oauth2as.AuthGrant{
			Request:       authReq,
			GrantedScopes: authReq.Scopes,
			UserID:        "test-user",
		})
		if err != nil {
			select {
			case handlerErrors <- fmt.Errorf("grant authorization request: %w", err):
			default:
			}
			http.Error(w, "authorization failed", http.StatusInternalServerError)
			return
		}
		http.Redirect(w, req, redirect, http.StatusFound)
	})
	mux.HandleFunc("POST /token", server.TokenHandler)
	mux.HandleFunc("GET /userinfo", server.UserinfoHandler)

	clientConfig := &oauth2.Config{
		ClientID: clientID,
		Endpoint: oauth2.Endpoint{
			AuthURL:  issuer + "/authorization",
			TokenURL: issuer + "/token",
		},
		Scopes: []string{oidc.ScopeOpenID, oidc.ScopeOfflineAccess},
	}
	opener := &callbackOpener{client: &http.Client{
		Timeout: 4 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}}
	wrapped, err := (&clitoken.Config{
		OAuth2Client: clientConfig,
		ClientType:   oauth2client.PublicClient,
		Opener:       opener,
	}).TokenSource(ctx)
	if err != nil {
		t.Fatal(err)
	}
	cache := &clitoken.MemCredentialCache{}
	const cacheKey = "public-cli|openid offline_access"
	cacheSource, err := (&tokencache.Config{
		Issuer:              issuer,
		CacheKey:            cacheKey,
		WrappedSource:       wrapped,
		TokenSourceProvider: clientConfig,
		Cache:               cache,
		DPoPKeys:            cache,
	}).TokenSource(ctx)
	if err != nil {
		t.Fatal(err)
	}

	first, firstSigner, err := cacheSource.DPoPToken()
	if err != nil {
		select {
		case handlerErr := <-handlerErrors:
			t.Fatalf("initial token flow: %v (authorization handler: %v)", err, handlerErr)
		default:
			t.Fatalf("initial token flow: %v", err)
		}
	}
	if firstSigner == nil || first.TokenType != "DPoP" || first.RefreshToken == "" {
		t.Fatalf("initial token credentials = token type %q, refresh token present %t, signer %v", first.TokenType, first.RefreshToken != "", firstSigner != nil)
	}
	select {
	case authRequest := <-authorizationRequests:
		if authRequest.Get("code_challenge") == "" || authRequest.Get("code_challenge_method") != "S256" || authRequest.Get("dpop_jkt") != firstSigner.Thumbprint() {
			t.Fatalf("public PKCE and DPoP authorization parameters = %v", authRequest)
		}
	case <-ctx.Done():
		t.Fatal("authorization request was not observed")
	}
	if err := fetchUserinfo(ctx, cacheSource.Client(&http.Client{Timeout: 4 * time.Second}), issuer+"/userinfo"); err != nil {
		t.Fatalf("UserInfo with initial token: %v", err)
	}

	// The memory store retains the returned token. Expire it without depending
	// on the upstream cache's internal DPoP key namespace.
	oldRefreshToken := first.RefreshToken
	first.Expiry = time.Now().Add(-time.Minute)
	refreshed, refreshedSigner, err := cacheSource.DPoPToken()
	if err != nil {
		t.Fatalf("refresh cached token: %v", err)
	}
	if refreshed.RefreshToken == "" || refreshed.RefreshToken == oldRefreshToken {
		t.Fatalf("refresh token was not rotated: old present %t, new present %t, equal %t", oldRefreshToken != "", refreshed.RefreshToken != "", refreshed.RefreshToken == oldRefreshToken)
	}
	if refreshedSigner == nil || refreshedSigner.Thumbprint() != firstSigner.Thumbprint() {
		t.Fatalf("refresh changed DPoP key: first %v, refreshed %v", firstSigner, refreshedSigner)
	}
	if got := opener.calls.Load(); got != 1 {
		t.Fatalf("browser opener calls = %d after refresh, want 1", got)
	}
	if err := fetchUserinfo(ctx, cacheSource.Client(&http.Client{Timeout: 4 * time.Second}), issuer+"/userinfo"); err != nil {
		t.Fatalf("UserInfo with refreshed token: %v", err)
	}

	sessions, err := server.ListRefreshSessions(ctx, oauth2as.RefreshSessionQuery{UserID: "test-user"})
	if err != nil {
		t.Fatal(err)
	}
	if len(sessions.Sessions) != 1 || !sessions.Sessions[0].DPoPBound {
		t.Fatalf("active refresh sessions = %#v, want one DPoP-bound session", sessions.Sessions)
	}
	select {
	case handlerErr := <-handlerErrors:
		t.Fatalf("authorization handler error: %v", handlerErr)
	default:
	}
}

type loopbackClientSource struct{ id string }

func (s loopbackClientSource) Client(_ context.Context, clientID string) (*oauth2as.Client, error) {
	if clientID != s.id {
		return nil, nil
	}
	return &oauth2as.Client{
		ID:           s.id,
		Public:       true,
		RedirectURIs: []string{"http://127.0.0.1/callback"},
	}, nil
}

type callbackOpener struct {
	client *http.Client
	calls  atomic.Int32
}

func (o *callbackOpener) Open(ctx context.Context, authURL string) error {
	o.calls.Add(1)
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, authURL, nil)
	if err != nil {
		return err
	}
	response, err := o.client.Do(request)
	if err != nil {
		return fmt.Errorf("request authorization URL: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusFound {
		body, _ := io.ReadAll(io.LimitReader(response.Body, 4096))
		return fmt.Errorf("authorization response status %d: %s", response.StatusCode, strings.TrimSpace(string(body)))
	}
	location := response.Header.Get("Location")
	callbackURL, err := url.Parse(location)
	if err != nil {
		return fmt.Errorf("parse callback URL: %w", err)
	}
	if callbackURL.Scheme != "http" || callbackURL.Hostname() != "127.0.0.1" || callbackURL.Path != "/callback" {
		return fmt.Errorf("unexpected callback URL %q", location)
	}
	callbackRequest, err := http.NewRequestWithContext(ctx, http.MethodGet, location, nil)
	if err != nil {
		return err
	}
	callbackResponse, err := o.client.Do(callbackRequest)
	if err != nil {
		return fmt.Errorf("request callback URL: %w", err)
	}
	defer callbackResponse.Body.Close()
	if callbackResponse.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(callbackResponse.Body, 4096))
		return fmt.Errorf("callback status %d: %s", callbackResponse.StatusCode, strings.TrimSpace(string(body)))
	}
	return nil
}

func fetchUserinfo(ctx context.Context, client *http.Client, userinfoURL string) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, userinfoURL, nil)
	if err != nil {
		return err
	}
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(response.Body, 4096))
		return fmt.Errorf("UserInfo status %d: %s", response.StatusCode, strings.TrimSpace(string(body)))
	}
	var identity map[string]any
	if err := json.NewDecoder(response.Body).Decode(&identity); err != nil {
		return err
	}
	if identity["sub"] != "test-user" || identity["name"] != "Test User" {
		return fmt.Errorf("unexpected UserInfo identity: %#v", identity)
	}
	return nil
}
