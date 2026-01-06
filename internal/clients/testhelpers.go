package clients

import (
	"context"
	"database/sql"
	"encoding/json"
	"testing"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"lds.li/oauth2ext/oidcclientreg"
	"lds.li/webauthn-oidc-idp/internal/queries"
)

// setupTestDB creates an in-memory SQLite database for testing
func setupTestDB(t *testing.T) (*queries.Queries, func()) {
	// Create in-memory SQLite database
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("failed to open database: %v", err)
	}

	// Create the dynamic_clients table
	_, err = db.Exec(`
		CREATE TABLE dynamic_clients (
			id TEXT PRIMARY KEY,
			client_secret_hash TEXT NOT NULL,
			registration_blob TEXT NOT NULL,
			created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			expires_at DATETIME NOT NULL,
			active BOOLEAN NOT NULL DEFAULT TRUE
		);
	`)
	if err != nil {
		t.Fatalf("failed to create table: %v", err)
	}

	// Create indexes
	_, err = db.Exec(`
		CREATE INDEX idx_dynamic_clients_active_expires ON dynamic_clients(active, expires_at);
		CREATE INDEX idx_dynamic_clients_id_active ON dynamic_clients(id, active);
	`)
	if err != nil {
		t.Fatalf("failed to create indexes: %v", err)
	}

	queriesDB := queries.New(db)

	cleanup := func() {
		db.Close()
	}

	return queriesDB, cleanup
}

// createTestDynamicClient creates a dynamic client in the database for testing
func createTestDynamicClient(t *testing.T, db *queries.Queries, clientID string, req oidcclientreg.ClientRegistrationRequest) {
	reqBody, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("failed to marshal request: %v", err)
	}

	params := queries.CreateDynamicClientParams{
		ID:               clientID,
		ClientSecretHash: "test-hash",
		RegistrationBlob: string(reqBody),
		ExpiresAt:        time.Now().AddDate(0, 0, 14),
	}

	if err := db.CreateDynamicClient(context.Background(), params); err != nil {
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
