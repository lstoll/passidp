package clients

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"testing"
	"time"

	"lds.li/oauth2ext/oidcclientreg"
	"lds.li/webauthn-oidc-idp/internal/storage"
)

// setupTestDB creates a temporary BoltDB database for testing
func setupTestDB(t *testing.T) (*storage.DynamicClientStore, func()) {
	// Create temporary file for BoltDB
	tmpfile, err := os.CreateTemp("", "test-dynamic-clients-*.db")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	tmpfile.Close()

	// Create State instance (which initializes buckets)
	state, err := storage.NewState(tmpfile.Name())
	if err != nil {
		os.Remove(tmpfile.Name())
		t.Fatalf("failed to create state: %v", err)
	}

	store := storage.NewDynamicClientStore(state)

	cleanup := func() {
		state.Close()
		os.Remove(tmpfile.Name())
	}

	return store, cleanup
}

// createTestDynamicClient creates a dynamic client in the database for testing
func createTestDynamicClient(t *testing.T, db *storage.DynamicClientStore, clientID string, req oidcclientreg.ClientRegistrationRequest) {
	reqBody, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("failed to marshal request: %v", err)
	}

	// Use clientID as part of hash to ensure uniqueness
	secretHash := fmt.Sprintf("test-hash-%s", clientID)

	if err := db.CreateDynamicClient(context.Background(), clientID, secretHash, string(reqBody), time.Now().AddDate(0, 0, 14)); err != nil {
		t.Fatalf("failed to create test client: %v", err)
	}
}

// defaultTestClientRequest returns a standard test client registration request
func defaultTestClientRequest() oidcclientreg.ClientRegistrationRequest {
	return oidcclientreg.ClientRegistrationRequest{
		RedirectURIs:    []string{"https://example.com/callback"},
		GrantTypes:      []string{"authorization_code"},
		ResponseTypes:   []string{"code"},
		ApplicationType: "web",
		ClientName:      "Test Client",
	}
}
