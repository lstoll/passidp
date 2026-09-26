package config

import (
	"strings"
	"testing"
)

func TestClientAuthenticationConfigValidation(t *testing.T) {
	tests := []struct {
		name    string
		client  Client
		wantErr string
	}{
		{name: "secret", client: Client{Secrets: []string{"secret"}}},
		{name: "public", client: Client{Public: true}},
		{name: "pem JWT", client: Client{ClientJWTPublicKeys: []ClientJWTKey{{PEM: "pem"}}}},
		{name: "remote JWKS", client: Client{JWKSURL: "https://client.example/jwks"}},
		{name: "JWT and secret", client: Client{Secrets: []string{"secret"}, JWKSURL: "https://client.example/jwks"}, wantErr: "cannot combine private_key_jwt with client secrets"},
		{name: "JWT and public", client: Client{Public: true, JWKSURL: "https://client.example/jwks"}, wantErr: "cannot combine private_key_jwt with public"},
		{name: "PEM and URL", client: Client{ClientJWTPublicKeys: []ClientJWTKey{{PEM: "pem"}}, JWKSURL: "https://client.example/jwks"}, wantErr: "cannot configure both clientJWTPublicKeys and jwksURL"},
		{name: "http JWKS", client: Client{JWKSURL: "http://client.example/jwks"}, wantErr: "jwksURL must be an absolute https URL"},
		{name: "relative JWKS", client: Client{JWKSURL: "/jwks"}, wantErr: "jwksURL must be an absolute https URL"},
		{name: "public and secret", client: Client{Public: true, Secrets: []string{"secret"}}, wantErr: "cannot combine public client authentication with client secrets"},
		{name: "duplicate ID", client: Client{Secrets: []string{"secret"}}, wantErr: "duplicate client ID"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.client.ID = "test"
			tt.client.RedirectURLs = []string{"https://client.example/callback"}
			clients := []Client{tt.client}
			if tt.name == "duplicate ID" {
				clients = append(clients, tt.client)
			}
			err := (&Config{Issuer: "https://issuer.example", Clients: clients}).Validate()
			if tt.wantErr == "" && err != nil {
				t.Fatalf("Validate() error = %v", err)
			}
			if tt.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tt.wantErr)) {
				t.Fatalf("Validate() error = %v, want substring %q", err, tt.wantErr)
			}
		})
	}
}
