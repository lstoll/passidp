package oauth2as_test

import (
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"slices"
	"sync"
	"testing"
	"time"

	"golang.org/x/oauth2"
	"lds.li/oauth2ext/jwt"
	"lds.li/oauth2ext/oidc"
	"lds.li/oauth2ext/provider"
	"lds.li/passidp/internal/oauth2as"
	"lds.li/passidp/internal/oauth2as/discovery"
	"lds.li/passidp/internal/oauth2as/internal"
)

func TestE2E(t *testing.T) {
	const (
		clientID     = "client-id"
		clientSecret = "client-secret"
	)

	for _, tc := range []struct {
		Name     string
		WithPKCE bool
	}{
		{
			Name: "Simple authorization",
		},
		{
			Name:     "Authorization with PKCE",
			WithPKCE: true,
		},
	} {
		t.Run(tc.Name, func(t *testing.T) {
			ctx := context.Background()

			callbackChan := make(chan string, 1)
			state := rand.Text()

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

				gotState := req.FormValue("state")
				if gotState == "" || gotState != state {
					t.Errorf("returned state doesn't match request state")

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
					RedirectURLs: []string{cliSvr.URL},
					Public:       tc.WithPKCE,
				},
			}
			if !tc.WithPKCE {
				clientSource[0].Opts = []oauth2as.ClientOpt{oauth2as.ClientOptSkipPKCE()}
			}

			s := oauth2as.NewMemoryStorage()

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
			oidcSvrMux.Handle("GET /.well-known/", ch) // can just do the whole well-known path here

			// Add authorization endpoint handler
			oidcSvrMux.HandleFunc("/authorization", func(w http.ResponseWriter, req *http.Request) {
				// Parse the authorization request
				authReq, err := op.ParseAuthRequest(req)
				if err != nil {
					t.Errorf("failed to parse auth request: %v", err)
					http.Error(w, "invalid request", http.StatusBadRequest)
					return
				}

				// Auto-grant the authorization (for testing purposes)
				grant := &oauth2as.AuthGrant{
					Request:       authReq,
					GrantedScopes: authReq.Scopes,
					UserID:        "test-user",
				}

				redirectURI, err := op.GrantAuth(ctx, grant)
				if err != nil {
					t.Errorf("failed to grant auth: %v", err)
					http.Error(w, "authorization failed", http.StatusInternalServerError)
					return
				}

				// Redirect to the callback with the authorization code
				http.Redirect(w, req, redirectURI, http.StatusFound)
			})

			provider, err := provider.DiscoverOIDCProvider(ctx, oidcSvr.URL)
			if err != nil {
				t.Fatal(err)
			}

			o2 := &oauth2.Config{
				ClientID: clientID,
				ClientSecret: func() string {
					if tc.WithPKCE {
						return ""
					}
					return clientSecret
				}(),
				Endpoint:    provider.Endpoint(),
				RedirectURL: cliSvr.URL,
				Scopes:      []string{oidc.ScopeOpenID, oidc.ScopeOfflineAccess},
			}

			var acopts []oauth2.AuthCodeOption
			verifier := oauth2.GenerateVerifier()
			if tc.WithPKCE {
				acopts = append(acopts, oauth2.S256ChallengeOption(verifier))
			}

			client := &http.Client{
				CheckRedirect: func(req *http.Request, via []*http.Request) error {
					return http.ErrUseLastResponse
				},
			}
			resp, err := client.Get(o2.AuthCodeURL(state, acopts...))
			if err != nil {
				t.Fatalf("error getting auth URL: %v", err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusFound {
				t.Fatalf("expected status found, got %d", resp.StatusCode)
			}

			// Follow the redirect manually to trigger the callback
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

			var eopts []oauth2.AuthCodeOption
			if tc.WithPKCE {
				eopts = append(eopts, oauth2.VerifierOption(verifier))
			}

			tok, err := o2.Exchange(ctx, callbackCode, eopts...)
			if err != nil {
				t.Fatalf("error exchanging code %q for token: %v", callbackCode, err)
			}

			ts := o2.TokenSource(ctx, tok)

			var uir map[string]any

			err = provider.Userinfo(ctx, ts, &uir)
			if err != nil {
				t.Fatalf("error fetching userinfo: %v", err)
			}

			t.Logf("initial userinfo response: %#v", uir)

			for i := range 5 {
				t.Logf("refresh iter: %d", i)
				currRT := tok.RefreshToken

				// TODO - how to do this?
				// if err := smgr.expireAccessTokens(ctx); err != nil {
				// 	t.Fatalf("expiring tokens: %v", err)
				// }
				tok.Expiry = time.Now().Add(-1 * time.Second) // needs to line up with remote change, else we won't refresh

				err := provider.Userinfo(ctx, ts, &uir)
				if err != nil {
					t.Fatalf("error fetching userinfo: %v", err)
				}

				t.Logf("subsequent userinfo response: %#v", uir)

				nt, err := ts.Token()
				if err != nil {
					t.Fatal(err)
				}

				if currRT == nt.RefreshToken {
					t.Fatal("userinfo should result in new refresh token")
				}

				tok = nt
			}
		})
	}
}

var (
	testSigner           jwt.Signer
	testVerificationKeys *jwt.VerificationKeySet
	testSignerOnce       sync.Once
)

func getTestSigner(t *testing.T) (jwt.Signer, *jwt.VerificationKeySet) {
	testSignerOnce.Do(func() {
		testSigner = internal.NewTestSigner(t, jwt.RS256, jwt.ES256)
		var err error
		testVerificationKeys, err = jwt.NewVerificationKeySetFromSigner(testSigner)
		if err != nil {
			t.Fatal(err)
		}
	})
	return testSigner, testVerificationKeys
}

type staticClient struct {
	ID           string
	Secrets      []string
	RedirectURLs []string
	Public       bool
	Opts         []oauth2as.ClientOpt
}

type staticClientSource []staticClient

func (c staticClientSource) IsValidClientID(ctx context.Context, clientID string) (ok bool, err error) {
	return slices.ContainsFunc(c, func(sc staticClient) bool {
		return sc.ID == clientID
	}), nil
}

func (c staticClientSource) ValidateClientSecret(ctx context.Context, clientID, clientSecret string) (ok bool, err error) {
	return slices.ContainsFunc(c, func(sc staticClient) bool {
		return sc.ID == clientID && slices.Contains(sc.Secrets, clientSecret)
	}), nil
}

func (c staticClientSource) ClientSecrets(ctx context.Context, clientID string) ([]string, error) {
	for _, sc := range c {
		if sc.ID == clientID {
			return sc.Secrets, nil
		}
	}
	return nil, fmt.Errorf("client not found")
}

func (c staticClientSource) RedirectURIs(ctx context.Context, clientID string) ([]string, error) {
	for _, sc := range c {
		if sc.ID == clientID {
			return sc.RedirectURLs, nil
		}
	}
	return nil, fmt.Errorf("client not found")
}

func (c staticClientSource) ClientOpts(ctx context.Context, clientID string) ([]oauth2as.ClientOpt, error) {
	for _, sc := range c {
		if sc.ID == clientID {
			opts := slices.Clone(sc.Opts)
			if sc.Public {
				opts = append(opts, oauth2as.ClientOptPublic())
			}
			return opts, nil
		}
	}
	return nil, fmt.Errorf("client not found")
}
