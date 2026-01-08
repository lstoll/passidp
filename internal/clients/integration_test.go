package clients

import (
	"testing"

	"lds.li/passidp/internal/config"
)

func TestMultiClientsIntegration(t *testing.T) {
	// This integration test focuses on scenarios that demonstrate how MultiClients
	// integrates both static and dynamic clients, particularly edge cases like
	// precedence and conflicts. Individual method behaviors are tested in unit tests.

	// Create static clients
	staticClients := &StaticClients{
		Clients: []config.Client{
			{
				ID:           "static-web-client",
				RedirectURLs: []string{"https://static.example.com/callback"},
				Secrets:      []string{"static-secret"},
				Public:       false,
				UseRS256:     true,
			},
			{
				ID:           "static-public-client",
				RedirectURLs: []string{"https://static.example.com/public-callback"},
				Secrets:      []string{},
				Public:       true,
			},
		},
	}

	// Create database and dynamic clients
	db, cleanup := setupTestDB(t)
	defer cleanup()

	dynamicClients := &DynamicClients{DB: db}

	// Create a dynamic client
	req := defaultTestClientRequest()
	req.RedirectURIs = []string{"https://dynamic.example.com/callback"}
	createTestDynamicClient(t, db, "dc.dynamic-web-client", req)

	// Create MultiClients
	multi := NewMultiClients(staticClients, dynamicClients)

	// Test: Static client takes precedence when a dynamic client with the same ID exists
	// This is an important integration scenario showing precedence behavior
	conflictReq := defaultTestClientRequest()
	conflictReq.RedirectURIs = []string{"https://conflict.example.com/callback"}
	createTestDynamicClient(t, db, "static-web-client", conflictReq) // Same ID as static client

	client, found := multi.GetClient("static-web-client")
	if !found {
		t.Fatal("expected to find static client")
	}
	if _, ok := client.(*StaticClient); !ok {
		t.Fatal("expected static client to take precedence over dynamic client")
	}
	if client.(*StaticClient).configClient.RedirectURLs[0] != "https://static.example.com/callback" {
		t.Error("expected static client redirect URI, not dynamic client URI")
	}

	// Test: Both client types work together
	client, found = multi.GetClient("dc.dynamic-web-client")
	if !found {
		t.Fatal("expected to find dynamic client")
	}
	if _, ok := client.(*DynamicClient); !ok {
		t.Fatal("expected dynamic client")
	}

	// Test: Public client handling (integration-specific scenario)
	client, found = multi.GetClient("static-public-client")
	if !found {
		t.Fatal("expected to find public static client")
	}
	if !client.(*StaticClient).configClient.Public {
		t.Error("expected client to be public")
	}
}
