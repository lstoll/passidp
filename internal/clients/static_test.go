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

func TestStaticClients_ClientOptsPublic(t *testing.T) {
	sc := &StaticClients{
		Clients: []config.Client{
			{
				ID:           "public-client",
				RedirectURLs: []string{"http://127.0.0.1/callback"},
				Public:       true,
			},
			{
				ID:           "confidential-client",
				RedirectURLs: []string{"https://example.com/callback"},
				Secrets:      []string{"secret"},
			},
		},
	}

	publicOpts, err := sc.ClientOpts(context.Background(), "public-client")
	if err != nil {
		t.Fatalf("ClientOpts: %v", err)
	}
	if len(publicOpts) != 2 {
		t.Fatalf("expected public + signing alg options, got %d", len(publicOpts))
	}

	confOpts, err := sc.ClientOpts(context.Background(), "confidential-client")
	if err != nil {
		t.Fatalf("ClientOpts: %v", err)
	}
	if len(confOpts) != 1 {
		t.Fatalf("expected signing alg option only, got %d", len(confOpts))
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
			opts, err := sc.ClientOpts(context.Background(), "jwt-client")
			if err != nil || len(opts) != 2 {
				t.Fatalf("ClientOpts() = %d options, %v; want signing algorithm and private_key_jwt", len(opts), err)
			}
			wantKey, err := jwt.NewVerificationKey(&key.PublicKey, "", tc.kid)
			if err != nil {
				t.Fatal(err)
			}
			jwks, err := sc.verificationKeys["jwt-client"].JWKS()
			if err != nil || !strings.Contains(string(jwks), `"kid":"`+wantKey.KeyID+`"`) {
				t.Fatalf("verification JWKS = %s, %v; expected kid %q", jwks, err, wantKey.KeyID)
			}
			secrets, err := sc.ClientSecrets(context.Background(), "jwt-client")
			if err != nil || len(secrets) != 0 {
				t.Fatalf("ClientSecrets() = %v, %v; want no secrets", secrets, err)
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
	keys := sc.verificationKeys["remote"]
	if keys == nil {
		t.Fatal("remote client has no key set")
	}
	if hasKey(t, keys, "client-key") {
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
	waitFor(t, func() bool { return hasKey(t, keys, "client-key") })
	stop()

	// If the host goes down again, a new load attempt keeps the last good keys.
	unavailable.Store(true)
	stop = runLoader()
	time.Sleep(50 * time.Millisecond)
	stop()
	if !hasKey(t, keys, "client-key") {
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
	sc := &StaticClients{Clients: []config.Client{{ID: "rsa-client", UseRS256: true}}}
	if _, err := sc.ClientOpts(context.Background(), "rsa-client"); err != nil {
		t.Fatalf("ClientOpts: %v", err)
	}
}
