package clients

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"lds.li/oauth2ext/oidcclientreg"
)


func TestDynamicClients_GetClient(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	dc := &DynamicClients{DB: db}

	// Test with non-dynamic client ID
	client, found := dc.GetClient("static-client")
	if found {
		t.Error("expected static client to not be found")
	}
	if client != nil {
		t.Error("expected static client to be nil")
	}

	// Test with dynamic client ID that doesn't exist
	client, found = dc.GetClient("dc.nonexistent")
	if found {
		t.Error("expected nonexistent dynamic client to not be found")
	}
	if client != nil {
		t.Error("expected nonexistent dynamic client to be nil")
	}
}


func TestDynamicClients_registerClient(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	dc := &DynamicClients{DB: db}

	// Test valid client registration
	req := defaultTestClientRequest()

	reqBody, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("failed to marshal request: %v", err)
	}

	httpReq := httptest.NewRequest("POST", "/registerClient", bytes.NewBuffer(reqBody))
	httpReq.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	dc.registerClient(w, httpReq)

	if w.Code != http.StatusCreated {
		t.Errorf("expected status 201, got %d", w.Code)
	}

	var response oidcclientreg.ClientRegistrationResponse
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}

	// Verify response fields
	if !strings.HasPrefix(response.ClientID, "dc.") {
		t.Errorf("expected client ID to start with 'dc.', got %s", response.ClientID)
	}

	if response.ClientSecret == "" {
		t.Error("expected client secret to be set")
	}

	// The response only contains basic client info, not the full registration details
	// The full details are stored in the database and can be verified there

	// Verify client was stored in database
	ctx := context.Background()
	dbClient, err := db.GetDynamicClient(ctx, response.ClientID)
	if err != nil {
		t.Fatalf("failed to get client from database: %v", err)
	}

	if dbClient.ID != response.ClientID {
		t.Errorf("expected client ID to match, got %s", dbClient.ID)
	}

	// Verify the registration blob contains the request data
	var storedReq oidcclientreg.ClientRegistrationRequest
	if err := json.Unmarshal([]byte(dbClient.RegistrationBlob), &storedReq); err != nil {
		t.Fatalf("failed to unmarshal stored registration: %v", err)
	}

	if storedReq.ClientName != "Test Client" {
		t.Errorf("expected stored client name to match, got %s", storedReq.ClientName)
	}

	// Verify expiration is set to 14 days from now
	expectedExpiry := time.Now().AddDate(0, 0, 14)
	if dbClient.ExpiresAt.Sub(expectedExpiry) > time.Hour {
		t.Errorf("expected expiry to be approximately 14 days from now, got %v", dbClient.ExpiresAt)
	}
}

func TestDynamicClients_validateClientRegistration(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	dc := &DynamicClients{DB: db}

	tests := []struct {
		name    string
		req     oidcclientreg.ClientRegistrationRequest
		wantErr bool
	}{
		{
			name: "valid request",
			req: oidcclientreg.ClientRegistrationRequest{
				RedirectURIs:    []string{"https://example.com/callback"},
				GrantTypes:      []string{"authorization_code"},
				ResponseTypes:   []string{"code"},
				ApplicationType: "web",
			},
			wantErr: false,
		},
		{
			name: "missing redirect URIs",
			req: oidcclientreg.ClientRegistrationRequest{
				GrantTypes:      []string{"authorization_code"},
				ResponseTypes:   []string{"code"},
				ApplicationType: "web",
			},
			wantErr: true,
		},
		{
			name: "empty redirect URIs",
			req: oidcclientreg.ClientRegistrationRequest{
				RedirectURIs:    []string{},
				GrantTypes:      []string{"authorization_code"},
				ResponseTypes:   []string{"code"},
				ApplicationType: "web",
			},
			wantErr: true,
		},
		{
			name: "missing grant types (should default to authorization_code)",
			req: oidcclientreg.ClientRegistrationRequest{
				RedirectURIs:    []string{"https://example.com/callback"},
				ResponseTypes:   []string{"code"},
				ApplicationType: "web",
			},
			wantErr: false,
		},
		{
			name: "missing response types (should default to code)",
			req: oidcclientreg.ClientRegistrationRequest{
				RedirectURIs:    []string{"https://example.com/callback"},
				GrantTypes:      []string{"authorization_code"},
				ApplicationType: "web",
			},
			wantErr: false,
		},
		{
			name: "missing application type (should default to web)",
			req: oidcclientreg.ClientRegistrationRequest{
				RedirectURIs:  []string{"https://example.com/callback"},
				GrantTypes:    []string{"authorization_code"},
				ResponseTypes: []string{"code"},
			},
			wantErr: false,
		},
		{
			name: "valid RS256 signing algorithm",
			req: oidcclientreg.ClientRegistrationRequest{
				RedirectURIs:             []string{"https://example.com/callback"},
				GrantTypes:               []string{"authorization_code"},
				ResponseTypes:            []string{"code"},
				ApplicationType:          "web",
				IDTokenSignedResponseAlg: "RS256",
			},
			wantErr: false,
		},
		{
			name: "valid ES256 signing algorithm",
			req: oidcclientreg.ClientRegistrationRequest{
				RedirectURIs:             []string{"https://example.com/callback"},
				GrantTypes:               []string{"authorization_code"},
				ResponseTypes:            []string{"code"},
				ApplicationType:          "web",
				IDTokenSignedResponseAlg: "ES256",
			},
			wantErr: false,
		},
		{
			name: "unsupported signing algorithm",
			req: oidcclientreg.ClientRegistrationRequest{
				RedirectURIs:             []string{"https://example.com/callback"},
				GrantTypes:               []string{"authorization_code"},
				ResponseTypes:            []string{"code"},
				ApplicationType:          "web",
				IDTokenSignedResponseAlg: "PS256",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := dc.validateClientRegistration(&tt.req)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateClientRegistration() error = %v, wantErr %v", err, tt.wantErr)
			}

			if !tt.wantErr {
				// Check that defaults were set
				if len(tt.req.GrantTypes) == 0 {
					t.Error("expected grant types to be set")
				}
				if len(tt.req.ResponseTypes) == 0 {
					t.Error("expected response types to be set")
				}
				if tt.req.ApplicationType == "" {
					t.Error("expected application type to be set")
				}
			}
		})
	}
}

func TestDynamicClients_shouldEnforcePKCE(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	dc := &DynamicClients{DB: db}

	tests := []struct {
		name            string
		applicationType string
		redirectURIs    []string
		want            bool
	}{
		{
			name:            "native client should enforce PKCE",
			applicationType: "native",
			redirectURIs:    []string{"https://example.com/callback"},
			want:            true,
		},
		{
			name:            "spa client should enforce PKCE",
			applicationType: "spa",
			redirectURIs:    []string{"https://example.com/callback"},
			want:            true,
		},
		{
			name:            "web client with localhost should enforce PKCE",
			applicationType: "web",
			redirectURIs:    []string{"http://localhost:3000/callback"},
			want:            true,
		},
		{
			name:            "web client with 127.0.0.1 should enforce PKCE",
			applicationType: "web",
			redirectURIs:    []string{"http://127.0.0.1:3000/callback"},
			want:            true,
		},
		{
			name:            "web client with 127.1.2.3 should enforce PKCE",
			applicationType: "web",
			redirectURIs:    []string{"http://127.1.2.3:3000/callback"},
			want:            true,
		},
		{
			name:            "web client with external URL should not enforce PKCE",
			applicationType: "web",
			redirectURIs:    []string{"https://example.com/callback"},
			want:            false,
		},
		{
			name:            "web client with mixed URLs should enforce PKCE if any are localhost",
			applicationType: "web",
			redirectURIs:    []string{"https://example.com/callback", "http://localhost:3000/callback"},
			want:            true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			redirectURIsStr := strings.Join(tt.redirectURIs, ",")
			got := dc.shouldEnforcePKCE(tt.applicationType, redirectURIsStr)
			if got != tt.want {
				t.Errorf("shouldEnforcePKCE() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestDynamicClients_GetClientMetadata(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	dc := &DynamicClients{DB: db}

	// Test with non-dynamic client ID
	_, err := dc.GetClientMetadata(context.Background(), "static-client")
	if err == nil {
		t.Error("expected error for non-dynamic client ID")
	}
	if !strings.Contains(err.Error(), "is not a dynamic client") {
		t.Errorf("expected error about non-dynamic client, got: %v", err)
	}

	// Test with dynamic client ID that doesn't exist
	_, err = dc.GetClientMetadata(context.Background(), "dc.nonexistent")
	if err == nil {
		t.Error("expected error for nonexistent dynamic client")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("expected error about client not found, got: %v", err)
	}

	// Test with valid dynamic client
	req := defaultTestClientRequest()
	clientID := "dc.test-metadata"
	createTestDynamicClient(t, db, clientID, req)

	// Test getting metadata
	metadata, err := dc.GetClientMetadata(context.Background(), clientID)
	if err != nil {
		t.Fatalf("failed to get client metadata: %v", err)
	}

	if metadata.ClientName != "Test Client" {
		t.Errorf("expected client name 'Test Client', got %s", metadata.ClientName)
	}

	if metadata.ApplicationType != "web" {
		t.Errorf("expected application type 'web', got %s", metadata.ApplicationType)
	}

	if len(metadata.RedirectURIs) != 1 || metadata.RedirectURIs[0] != "https://example.com/callback" {
		t.Errorf("expected redirect URI 'https://example.com/callback', got %v", metadata.RedirectURIs)
	}
}

func TestDynamicClients_ClientOpts(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	dc := &DynamicClients{DB: db}

	// Test with non-dynamic client ID
	opts, err := dc.ClientOpts(context.Background(), "static-client")
	if err != nil {
		t.Errorf("expected no error for non-dynamic client, got: %v", err)
	}
	if len(opts) != 0 {
		t.Errorf("expected no options for non-dynamic client, got %d options", len(opts))
	}

	// Test with dynamic client ID that doesn't exist
	opts, err = dc.ClientOpts(context.Background(), "dc.nonexistent")
	if err != nil {
		t.Errorf("expected no error for nonexistent dynamic client, got: %v", err)
	}
	if len(opts) != 0 {
		t.Errorf("expected no options for nonexistent dynamic client, got %d options", len(opts))
	}

	// Test with valid dynamic client - default algorithm (RS256)
	req := defaultTestClientRequest()
	req.ClientName = "" // Remove ClientName for this test
	clientID := "dc.test-opts-default"
	createTestDynamicClient(t, db, clientID, req)

	opts, err = dc.ClientOpts(context.Background(), clientID)
	if err != nil {
		t.Fatalf("failed to get client options: %v", err)
	}

	// Should have 2 options: signing algorithm and PKCE skip
	if len(opts) != 2 {
		t.Errorf("expected 2 options (signing alg + PKCE skip), got %d", len(opts))
	}

	// Test with valid dynamic client - explicit RS256 algorithm
	reqRS256 := defaultTestClientRequest()
	reqRS256.IDTokenSignedResponseAlg = "RS256"
	clientIDRS256 := "dc.test-opts-rs256"
	createTestDynamicClient(t, db, clientIDRS256, reqRS256)

	optsRS256, err := dc.ClientOpts(context.Background(), clientIDRS256)
	if err != nil {
		t.Fatalf("failed to get RS256 client options: %v", err)
	}

	// Should have 2 options: signing algorithm and PKCE skip
	if len(optsRS256) != 2 {
		t.Errorf("expected 2 options for RS256 client, got %d", len(optsRS256))
	}

	// Test with valid dynamic client - explicit ES256 algorithm
	reqES256 := defaultTestClientRequest()
	reqES256.IDTokenSignedResponseAlg = "ES256"
	clientIDES256 := "dc.test-opts-es256"
	createTestDynamicClient(t, db, clientIDES256, reqES256)

	optsES256, err := dc.ClientOpts(context.Background(), clientIDES256)
	if err != nil {
		t.Fatalf("failed to get ES256 client options: %v", err)
	}

	// Should have 2 options: signing algorithm and PKCE skip
	if len(optsES256) != 2 {
		t.Errorf("expected 2 options for ES256 client, got %d", len(optsES256))
	}

	// Test with valid dynamic client - unsupported algorithm (should default to RS256)
	reqUnsupported := defaultTestClientRequest()
	reqUnsupported.IDTokenSignedResponseAlg = "PS256" // Unsupported algorithm
	clientIDUnsupported := "dc.test-opts-unsupported"
	createTestDynamicClient(t, db, clientIDUnsupported, reqUnsupported)

	optsUnsupported, err := dc.ClientOpts(context.Background(), clientIDUnsupported)
	if err != nil {
		t.Fatalf("failed to get unsupported algorithm client options: %v", err)
	}

	// Should have 2 options: signing algorithm and PKCE skip
	if len(optsUnsupported) != 2 {
		t.Errorf("expected 2 options for unsupported algorithm client, got %d", len(optsUnsupported))
	}
}
