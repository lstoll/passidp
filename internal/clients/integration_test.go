package clients

import (
	"context"
	"testing"

	"lds.li/passidp/internal/config"
)

func TestMultiClientsIntegration(t *testing.T) {
	// This integration test focuses on scenarios that demonstrate how MultiClients
	// integrates both static and dynamic clients, particularly edge cases like
	// precedence and conflicts. Individual method behaviors are tested in unit tests.

	// Create static clients
	staticClients, err := NewStaticClients([]config.Client{
		{
			ID:           "static-web-client",
			RedirectURLs: []string{"https://static.example.com/callback"},
			Secrets:      []string{"static-secret"},
			Public:       false,
		},
		{
			ID:           "static-public-client",
			RedirectURLs: []string{"https://static.example.com/public-callback"},
			Secrets:      []string{},
			Public:       true,
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	// Create database and dynamic clients
	db := setupTestDB(t)

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

	client, err := multi.Client(context.Background(), "static-web-client")
	if err != nil || client == nil {
		t.Fatalf("expected to find static client, got %v, %v", client, err)
	}
	if client.RedirectURIs[0] != "https://static.example.com/callback" {
		t.Error("expected static client redirect URI, not dynamic client URI")
	}

	// Test: Both client types work together
	client, err = multi.Client(context.Background(), "dc.dynamic-web-client")
	if err != nil || client == nil || client.ID != "dc.dynamic-web-client" {
		t.Fatalf("expected dynamic client, got %v, %v", client, err)
	}

	// Test: Public client handling (integration-specific scenario)
	client, err = multi.Client(context.Background(), "static-public-client")
	if err != nil || client == nil {
		t.Fatalf("expected to find public static client, got %v, %v", client, err)
	}
	if !client.Public {
		t.Error("expected client to be public")
	}
}
