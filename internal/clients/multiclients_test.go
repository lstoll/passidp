package clients

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"testing"

	"lds.li/passidp/internal/config"
)

func TestMultiClients_GetClient(t *testing.T) {
	// Test static client takes precedence
	staticClients := &StaticClients{
		Clients: []config.Client{
			{
				ID:           "static-client",
				RedirectURLs: []string{"https://example.com/callback"},
				Secrets:      []string{"secret1"},
				Public:       false,
			},
		},
	}

	db := setupTestDB(t)

	dynamicClients := &DynamicClients{DB: db}

	// Create a dynamic client with the same ID
	req := defaultTestClientRequest()
	req.RedirectURIs = []string{"https://dynamic.com/callback"}
	createTestDynamicClient(t, db, "static-client", req) // Same ID as static client

	multi := NewMultiClients(staticClients, dynamicClients)

	// Should get static client (takes precedence)
	client, found := multi.GetClient("static-client")
	if !found {
		t.Error("expected to find client")
	}
	if client.(*StaticClient).configClient.ID != "static-client" {
		t.Errorf("expected static client, got %s", client.(*StaticClient).configClient.ID)
	}
	if len(client.(*StaticClient).configClient.RedirectURLs) != 1 || client.(*StaticClient).configClient.RedirectURLs[0] != "https://example.com/callback" {
		t.Errorf("expected static client redirect URLs, got %v", client.(*StaticClient).configClient.RedirectURLs)
	}

	// Test dynamic client when static doesn't exist
	_, found = multi.GetClient("dc.dynamic-only")
	if found {
		t.Error("expected not to find dynamic client with dc. prefix")
	}

	// Test non-existent client
	_, found = multi.GetClient("nonexistent")
	if found {
		t.Error("expected not to find nonexistent client")
	}
}

func TestMultiClientsStaticJWTDoesNotFallBackToDynamicSecret(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	pemKey := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))

	db := setupTestDB(t)
	req := defaultTestClientRequest()
	createTestDynamicClient(t, db, "same-client", req)
	static, err := NewStaticClients([]config.Client{{
		ID:                  "same-client",
		RedirectURLs:        []string{"https://static.example/callback"},
		ClientJWTPublicKeys: []config.ClientJWTKey{{PEM: pemKey}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	multi := NewMultiClients(static, &DynamicClients{DB: db})

	client, err := multi.Client(context.Background(), "same-client")
	if err != nil || client == nil {
		t.Fatalf("Client: %v, %v", client, err)
	}
	if client.PrivateKeyJWT == nil {
		t.Fatal("static private_key_jwt client lost its keys")
	}
	if len(client.Secrets) != 0 {
		t.Fatalf("static JWT client inherited dynamic client secrets: %v", client.Secrets)
	}
	if len(client.RedirectURIs) != 1 || client.RedirectURIs[0] != "https://static.example/callback" {
		t.Fatalf("static JWT client inherited dynamic redirect URIs: %v", client.RedirectURIs)
	}
}

func TestMultiClients_Client(t *testing.T) {
	staticClients := &StaticClients{
		Clients: []config.Client{
			{
				ID:           "static-client",
				RedirectURLs: []string{"https://static.com/callback"},
				Secrets:      []string{"secret1"},
			},
		},
	}

	db := setupTestDB(t)
	dynamicClients := &DynamicClients{DB: db}

	req := defaultTestClientRequest()
	req.RedirectURIs = []string{"https://dynamic.com/callback"}
	createTestDynamicClient(t, db, "dc.dynamic-client", req)

	multi := NewMultiClients(staticClients, dynamicClients)

	// Static client
	client, err := multi.Client(context.Background(), "static-client")
	if err != nil || client == nil {
		t.Fatalf("static: %v, %v", client, err)
	}
	if len(client.RedirectURIs) != 1 || client.RedirectURIs[0] != "https://static.com/callback" {
		t.Errorf("expected static client redirect URIs, got %v", client.RedirectURIs)
	}
	if len(client.Secrets) != 1 || client.Secrets[0] != "secret1" {
		t.Errorf("expected static client secrets, got %v", client.Secrets)
	}

	// Dynamic client
	client, err = multi.Client(context.Background(), "dc.dynamic-client")
	if err != nil || client == nil {
		t.Fatalf("dynamic: %v, %v", client, err)
	}
	if len(client.RedirectURIs) != 1 || client.RedirectURIs[0] != "https://dynamic.com/callback" {
		t.Errorf("expected dynamic client redirect URIs, got %v", client.RedirectURIs)
	}

	// Non-existent client
	client, err = multi.Client(context.Background(), "nonexistent")
	if err != nil || client != nil {
		t.Errorf("expected (nil, nil) for nonexistent client, got %v, %v", client, err)
	}
}
