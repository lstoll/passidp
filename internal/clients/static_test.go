package clients

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/oauth2"
	"lds.li/oauth2ext/jwt"
	"lds.li/passidp/internal/config"
)

func TestStaticClients_Client(t *testing.T) {
	sc, err := NewStaticClients([]config.Client{
		{
			ID:           "public-client",
			RedirectURLs: []string{"http://127.0.0.1/callback"},
			Public:       true,
		},
		{
			ID:                  "confidential-client",
			RedirectURLs:        []string{"https://example.com/callback"},
			Secrets:             []string{"secret"},
			ClaimsPolicy:        "claims policy",
			AuthorizationPolicy: "authorization policy",
			GrantValidity:       config.JSONDuration(2 * time.Hour),
			TokenValidity:       config.JSONDuration(3 * time.Hour),
			RefreshValidity:     config.JSONDuration(4 * time.Hour),
			DPoPRefreshValidity: config.JSONDuration(5 * time.Hour),
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	pub, err := sc.Client(context.Background(), "public-client")
	if err != nil || pub == nil {
		t.Fatalf("Client: %v, %v", pub, err)
	}
	if !pub.Public || pub.SkipPKCE || len(pub.Secrets) != 0 || pub.IDTokenSigningAlgorithm != jwt.ES256 {
		t.Fatalf("unexpected public client: %+v", pub)
	}
	if len(pub.RedirectURIs) != 1 || pub.RedirectURIs[0] != "http://127.0.0.1/callback" {
		t.Fatalf("unexpected redirect URIs: %v", pub.RedirectURIs)
	}

	conf, err := sc.Client(context.Background(), "confidential-client")
	if err != nil || conf == nil {
		t.Fatalf("Client: %v, %v", conf, err)
	}
	if conf.Public || len(conf.Secrets) != 1 || conf.Secrets[0] != "secret" || conf.PrivateKeyJWT != nil {
		t.Fatalf("unexpected confidential client: %+v", conf)
	}
	if conf.ClaimsPolicy != "claims policy" || conf.AuthorizationPolicy != "authorization policy" || conf.GrantValidity != 2*time.Hour || conf.TokenValidity != 3*time.Hour || conf.RefreshValidity != 4*time.Hour || conf.DPoPRefreshValidity != 5*time.Hour {
		t.Fatalf("static policy or duration fields not mapped: %+v", conf)
	}
	conf.RedirectURIs[0] = "https://mutated.example/callback"
	conf.Secrets[0] = "mutated"
	conf.ClaimsPolicy = "mutated"
	conf.AuthorizationPolicy = "mutated"
	conf.GrantValidity = 0
	conf.TokenValidity = 0
	conf.RefreshValidity = 0
	conf.DPoPRefreshValidity = 0
	confAgain, err := sc.Client(context.Background(), "confidential-client")
	if err != nil || confAgain == nil {
		t.Fatalf("Client(confidential-client) after mutation = %v, %v", confAgain, err)
	}
	if confAgain.RedirectURIs[0] != "https://example.com/callback" || confAgain.Secrets[0] != "secret" || confAgain.ClaimsPolicy != "claims policy" || confAgain.AuthorizationPolicy != "authorization policy" || confAgain.GrantValidity != 2*time.Hour || confAgain.TokenValidity != 3*time.Hour || confAgain.RefreshValidity != 4*time.Hour || confAgain.DPoPRefreshValidity != 5*time.Hour {
		t.Fatalf("returned client mutation escaped into indexed client: %+v", confAgain)
	}

	missing, err := sc.Client(context.Background(), "missing")
	if err != nil || missing != nil {
		t.Fatalf("Client(missing) = %v, %v; want nil, nil", missing, err)
	}
}

func TestNewStaticClientsPrivateKeyJWT(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	pemKey := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
	for _, tc := range []struct {
		name string
		kid  string
	}{
		{name: "derived kid"},
		{name: "configured kid", kid: "partner-key"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sc, err := NewStaticClients([]config.Client{{
				ID: "jwt-client", RedirectURLs: []string{"https://client.example/callback"},
				ClientJWTPublicKeys: []config.ClientJWTKey{{PEM: pemKey, KeyID: tc.kid}},
			}})
			if err != nil {
				t.Fatalf("NewStaticClients: %v", err)
			}
			client, err := sc.Client(context.Background(), "jwt-client")
			if err != nil || client == nil || client.PrivateKeyJWT == nil || client.IDTokenSigningAlgorithm != jwt.ES256 {
				t.Fatalf("Client() = %+v, %v; want private_key_jwt client", client, err)
			}
			wantKey, err := jwt.NewVerificationKey(&key.PublicKey, "", tc.kid)
			if err != nil {
				t.Fatal(err)
			}
			jwks, err := client.PrivateKeyJWT.JWKS()
			if err != nil || !strings.Contains(string(jwks), `"kid":"`+wantKey.KeyID+`"`) {
				t.Fatalf("verification JWKS = %s, %v; expected kid %q", jwks, err, wantKey.KeyID)
			}
			if len(client.Secrets) != 0 || client.Public {
				t.Fatalf("Client() = %+v; want no secrets and not public", client)
			}
			again, err := sc.Client(context.Background(), "jwt-client")
			if err != nil || again == nil || again.PrivateKeyJWT != client.PrivateKeyJWT {
				t.Fatalf("client key handle was not preserved across lookups: %v, %v", again, err)
			}
		})
	}
}

func TestRemoteJWKSLoadsInBackground(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	verificationKey, err := jwt.NewVerificationKey(&key.PublicKey, "", "client-key")
	if err != nil {
		t.Fatal(err)
	}
	keySet, err := jwt.NewVerificationKeySet(verificationKey)
	if err != nil {
		t.Fatal(err)
	}
	body, err := keySet.JWKS()
	if err != nil {
		t.Fatal(err)
	}
	var unavailable atomic.Bool
	unavailable.Store(true)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if unavailable.Load() {
			http.Error(w, "unavailable", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/jwk-set+json")
		_, _ = w.Write(body)
	}))
	defer server.Close()
	ctx := context.WithValue(t.Context(), oauth2.HTTPClient, server.Client())

	// Construction succeeds while the key host is down, with no keys loaded.
	sc, err := NewStaticClients([]config.Client{{ID: "remote", JWKSURL: server.URL}})
	if err != nil {
		t.Fatalf("NewStaticClients with unreachable JWKS: %v", err)
	}
	client, err := sc.Client(ctx, "remote")
	if err != nil || client == nil || client.PrivateKeyJWT == nil {
		t.Fatalf("Client(remote) = %v, %v", client, err)
	}
	if hasKey(t, client.PrivateKeyJWT, "client-key") {
		t.Fatal("keys present before the JWKS was fetched")
	}

	loaders := sc.RemoteJWKS()
	if len(loaders) != 1 {
		t.Fatalf("RemoteJWKS() returned %d loaders, want 1", len(loaders))
	}
	loader := loaders[0]
	loader.retry = 10 * time.Millisecond
	runLoader := func() (stop func()) {
		runCtx, cancel := context.WithCancel(ctx)
		done := make(chan error, 1)
		go func() { done <- loader.Run(runCtx) }()
		return func() {
			cancel()
			select {
			case err := <-done:
				if err != nil {
					t.Errorf("Run returned %v after cancel, want nil", err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("Run did not stop after cancel")
			}
		}
	}

	// The loader retries until the host recovers, then fills the client's keys.
	stop := runLoader()
	time.Sleep(50 * time.Millisecond)
	unavailable.Store(false)
	waitFor(t, func() bool { return hasKey(t, client.PrivateKeyJWT, "client-key") })
	stop()

	// If the host goes down again, a new load attempt keeps the last good keys.
	unavailable.Store(true)
	stop = runLoader()
	time.Sleep(50 * time.Millisecond)
	stop()
	if !hasKey(t, client.PrivateKeyJWT, "client-key") {
		t.Fatal("failed load discarded the last good keys")
	}
}

func hasKey(t *testing.T, keys *jwt.VerificationKeySet, kid string) bool {
	t.Helper()
	encoded, err := keys.JWKS()
	if err != nil {
		t.Fatal(err)
	}
	return strings.Contains(string(encoded), `"`+kid+`"`)
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("condition not met within 5s")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestNewStaticClientsRequiresHTTPSJWKS(t *testing.T) {
	for _, jwksURL := range []string{"http://client.example/jwks", "/jwks", "https:///jwks"} {
		_, err := NewStaticClients([]config.Client{{ID: "remote", JWKSURL: jwksURL}})
		if err == nil || !strings.Contains(err.Error(), "absolute https URL") {
			t.Errorf("NewStaticClients(%q) error = %v, want https requirement", jwksURL, err)
		}
	}
}

func TestNewStaticClientsRejectsMalformedOrDuplicateKeys(t *testing.T) {
	_, err := NewStaticClients([]config.Client{{
		ID: "bad", ClientJWTPublicKeys: []config.ClientJWTKey{{PEM: "not PEM"}},
	}})
	if err == nil {
		t.Fatal("expected malformed PEM to be rejected")
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	pemKey := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
	_, err = NewStaticClients([]config.Client{{
		ID: "duplicate", ClientJWTPublicKeys: []config.ClientJWTKey{{PEM: pemKey}, {PEM: pemKey}},
	}})
	if err == nil {
		t.Fatal("expected duplicate keys to be rejected")
	}
}

func TestNewStaticClientsRejectsUnsupportedJWTAlgorithm(t *testing.T) {
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		t.Fatal(err)
	}
	_, err = NewStaticClients([]config.Client{{
		ID: "unsupported", ClientJWTPublicKeys: []config.ClientJWTKey{{
			PEM: string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})),
		}},
	}})
	if err == nil {
		t.Fatal("expected EdDSA private_key_jwt key to be rejected")
	}
}

func TestNewStaticClientsRejectsDuplicateClientIDs(t *testing.T) {
	_, err := NewStaticClients([]config.Client{{ID: "duplicate"}, {ID: "duplicate"}})
	if err == nil {
		t.Fatal("expected duplicate static client IDs to be rejected")
	}
}

func TestConfigValidatePublicSkipPKCE(t *testing.T) {
	cfg := &config.Config{
		Issuer: "https://idp.example.com",
		Clients: []config.Client{{
			ID:           "bad",
			RedirectURLs: []string{"http://127.0.0.1/callback"},
			Public:       true,
			SkipPKCE:     true,
		}},
	}
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected validation error for public client with skipPKCE")
	}
}

func TestStaticClientsAcceptRS256(t *testing.T) {
	sc, err := NewStaticClients([]config.Client{{ID: "rsa-client", UseRS256: true}})
	if err != nil {
		t.Fatal(err)
	}
	c, err := sc.Client(context.Background(), "rsa-client")
	if err != nil || c == nil || c.IDTokenSigningAlgorithm != jwt.RS256 {
		t.Fatalf("Client() = %+v, %v; want RS256 client", c, err)
	}
}
