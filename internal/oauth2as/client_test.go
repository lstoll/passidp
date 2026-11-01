package oauth2as

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"lds.li/oauth2ext/jwt"
)

func TestIsValidRedirectURI(t *testing.T) {
	registeredURIs := []string{
		"https://client.example.com/cb",
		"https://client.example.com/cb?login=true",
		"http://127.0.0.1:8080/cb4",      // Registered IPv4 loopback
		"http://localhost:9000/callback", // Registered localhost loopback
		"http://[::1]:9090/cb6",          // Registered IPv6 loopback
	}

	testCases := []struct {
		name        string
		redirectURI string
		expected    bool
		description string
	}{
		{
			name:        "Exact Match Simple",
			redirectURI: "https://client.example.com/cb",
			expected:    true,
			description: "A standard, exact match should be valid.",
		},
		{
			name:        "Exact Match With Query",
			redirectURI: "https://client.example.com/cb?login=true",
			expected:    true,
			description: "An exact match including query parameters should be valid.",
		},

		{
			name:        "Invalid Scheme",
			redirectURI: "http://client.example.com/cb",
			expected:    false,
			description: "A mismatch in scheme (http vs https) should be invalid.",
		},
		{
			name:        "Invalid Host",
			redirectURI: "https://attacker.example.com/cb",
			expected:    false,
			description: "A mismatch in hostname should be invalid.",
		},
		{
			name:        "Invalid Path",
			redirectURI: "https://client.example.com/callback",
			expected:    false,
			description: "A mismatch in path should be invalid.",
		},
		{
			name:        "Invalid Query",
			redirectURI: "https://client.example.com/cb?login=false",
			expected:    false,
			description: "A mismatch in query parameters should be invalid.",
		},
		{
			name:        "Port Mismatch on Non-Loopback",
			redirectURI: "https://client.example.com:8443/cb",
			expected:    false,
			description: "Specifying a port on a non-loopback URI when not registered should be invalid.",
		},

		{
			name:        "Valid Loopback IPv4 - Different Port",
			redirectURI: "http://127.0.0.1:51004/cb4",
			expected:    true,
			description: "A different port on a registered IPv4 loopback URI should be valid.",
		},
		{
			name:        "Valid Loopback IPv6 - Different Port",
			redirectURI: "http://[::1]:61023/cb6",
			expected:    true,
			description: "A different port on a registered IPv6 loopback URI should be valid.",
		},
		{
			name:        "Invalid Loopback, mixed IPv4 and IPv6",
			redirectURI: "http://127.0.0.1:51004/cb6",
			expected:    false,
			description: "The loopback exception permits a variable port, not a different address literal.",
		},

		{
			name:        "Invalid Loopback - Path Mismatch",
			redirectURI: "http://127.0.0.1:51004/callback",
			expected:    false,
			description: "A path mismatch on a loopback URI should be invalid.",
		},
		{
			name:        "Invalid Loopback - Scheme Mismatch",
			redirectURI: "https://127.0.0.1:8080/cb",
			expected:    false,
			description: "Using https on a registered http loopback URI should be invalid.",
		},
		{
			name:        "Bypass Attempt - Embedded Credentials",
			redirectURI: "https://client.example.com/cb@attacker.com/",
			expected:    false,
			description: "Should not be tricked by credentials in the user info part of the URI.",
		},
		{
			name:        "Bypass Attempt - Loopback with Credentials",
			redirectURI: "http://user:pass@127.0.0.1:8080/cb",
			expected:    false,
			description: "Loopback URIs with user info should not match if not registered that way.",
		},
		{
			name:        "Bypass Attempt - Different Loopback IP",
			redirectURI: "http://127.0.0.2:8080/cb",
			expected:    false,
			description: "Only exactly registered loopback IPs (127.0.0.1, localhost, [::1]) should be treated as special.",
		},
		{
			name:        "Bypass Attempt - 0.0.0.0 Host",
			redirectURI: "http://0.0.0.0:8080/cb",
			expected:    false,
			description: "0.0.0.0 should not be treated as a loopback address for this validation.",
		},
		{
			name:        "Bypass Attempt - Path Traversal",
			redirectURI: "https://client.example.com/cb/../",
			expected:    false,
			description: "Path traversal should fail simple string comparison.",
		},
		{
			name:        "Bypass Attempt - Case Mismatch Host",
			redirectURI: "http://LocalHost:9000/callback",
			expected:    false,
			description: "Hostname comparison is case-insensitive, but our simple check is not. This should fail simple string comparison and the parsed check.",
		},
		{
			name:        "Malformed URI",
			redirectURI: "https://client.example.com/%",
			expected:    false,
			description: "A URI that fails to parse should never be valid.",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Execute the function under test.
			actual := isValidRedirectURI(tc.redirectURI, registeredURIs)

			// Assert the result.
			if actual != tc.expected {
				t.Errorf("Test: '%s'\nDescription: %s\nRedirect URI: '%s'\nExpected: %t, but got: %t",
					tc.name, tc.description, tc.redirectURI, tc.expected, actual)
			}
		})
	}
}

func TestClientValidate(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keys, err := jwt.NewVerificationKeySet(jwt.VerificationKey{Key: &key.PublicKey, Algorithm: jwt.ES256, KeyID: "key"})
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name    string
		client  Client
		wantErr bool
	}{
		{"public with skip PKCE", Client{Public: true, SkipPKCE: true}, true},
		{"public alone", Client{Public: true}, false},
		{"public with private key jwt", Client{Public: true, PrivateKeyJWT: keys}, true},
		{"public with secrets", Client{Public: true, Secrets: []string{"s"}}, true},
		{"private key jwt with secrets", Client{PrivateKeyJWT: keys, Secrets: []string{"s"}}, true},
		{"private key jwt alone", Client{PrivateKeyJWT: keys, SkipPKCE: true}, false},
		{"secrets alone", Client{Secrets: []string{"s"}}, false},
		{"no authentication configured", Client{}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.client.validate()
			if (err != nil) != tc.wantErr {
				t.Fatalf("validate() = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}
