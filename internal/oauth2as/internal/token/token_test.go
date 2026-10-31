package token

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"
)

var (
	testUsage  = Usage{Name: "refresh_token", Prefix: "r"}
	otherUsage = Usage{Name: "authorization_code", Prefix: "c"}
)

func TestTokenRoundTrip(t *testing.T) {
	original := mustToken(t, testUsage, "token-id")
	userToken := original.UserToken()
	parts := strings.Split(userToken, ".")
	if len(parts) != 5 || parts[0] != "o2as" || parts[1] != "r" || parts[2] != "1" {
		t.Fatalf("unexpected token envelope: %q", userToken)
	}
	if strings.Contains(userToken, "token-id") {
		t.Fatal("token ID should use canonical base64url encoding")
	}

	parsed, err := ParseUserToken(userToken, testUsage)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.ID() != "token-id" {
		t.Fatalf("want token-id, got %q", parsed.ID())
	}
	verified, err := parsed.Verify(original.Stored(), "grant-id", "subject")
	if err != nil {
		t.Fatal(err)
	}
	if verified.UserToken() != userToken || verified.ID() != original.ID() {
		t.Fatal("verified token does not reproduce the original envelope")
	}
	if !bytes.Equal(verified.Stored(), original.Stored()) {
		t.Fatal("verified token derived a different stored verifier")
	}

	stored := original.Stored()
	stored[0] ^= 0xff
	if bytes.Equal(stored, original.Stored()) {
		t.Fatal("Stored returned mutable internal state")
	}
}

func TestTokenCompatibilityVector(t *testing.T) {
	// Generated with the previous implementation using this fixed secret and
	// binding. The opaque envelope and verifier must remain byte-for-byte stable.
	var secret [secretSize]byte
	for i := range secret {
		secret[i] = byte(i)
	}
	usage := Usage{Name: "refresh_token", Prefix: "r"}
	stored, err := deriveStoredVerifier(secret, usage, "vector-id", "vector-grant", "vector-subject")
	if err != nil {
		t.Fatal(err)
	}
	const wantUserToken = "o2as.r.1.dmVjdG9yLWlk.AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"
	const wantStored = "72b6b4dcd3767abbcc588becc30f985d2a4bf03dd9510f5f61f94f4ac5c86dd5"
	token := Token{usage: usage, id: "vector-id", secret: secret, stored: stored}
	if got := token.UserToken(); got != wantUserToken {
		t.Fatalf("user token = %q, want %q", got, wantUserToken)
	}
	wantStoredBytes, err := hex.DecodeString(wantStored)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(stored[:], wantStoredBytes) {
		t.Fatalf("stored verifier = %x, want %x", stored, wantStoredBytes)
	}
	parsed, err := ParseUserToken(wantUserToken, usage)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := parsed.Verify(wantStoredBytes, "vector-grant", "vector-subject"); err != nil {
		t.Fatalf("verify compatibility vector: %v", err)
	}
}

func TestTokenBinding(t *testing.T) {
	original := mustToken(t, testUsage, "token-id")
	parsed, err := ParseUserToken(original.UserToken(), testUsage)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name    string
		stored  []byte
		grantID string
		subject string
	}{
		{name: "wrong verifier", stored: bytes.Repeat([]byte{0xff}, 32), grantID: "grant-id", subject: "subject"},
		{name: "wrong grant", stored: original.Stored(), grantID: "other-grant", subject: "subject"},
		{name: "wrong subject", stored: original.Stored(), grantID: "grant-id", subject: "other-subject"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := parsed.Verify(test.stored, test.grantID, test.subject); err == nil {
				t.Fatal("verification succeeded")
			}
		})
	}
	if _, err := ParseUserToken(original.UserToken(), otherUsage); err == nil {
		t.Fatal("token parsed under a different usage")
	}
	samePrefixUsage := Usage{Name: "different_usage", Prefix: testUsage.Prefix}
	parsedForOtherUsage, err := ParseUserToken(original.UserToken(), samePrefixUsage)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := parsedForOtherUsage.Verify(original.Stored(), "grant-id", "subject"); err == nil {
		t.Fatal("token verified under a different usage name")
	}

	parts := strings.Split(original.UserToken(), ".")
	parts[3] = tokenEncoding.EncodeToString([]byte("other-token-id"))
	parsedWithOtherID, err := ParseUserToken(strings.Join(parts, "."), testUsage)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := parsedWithOtherID.Verify(original.Stored(), "grant-id", "subject"); err == nil {
		t.Fatal("token verified under a different storage record ID")
	}
	other := mustToken(t, testUsage, "token-id")
	if original.UserToken() == other.UserToken() || bytes.Equal(original.Stored(), other.Stored()) {
		t.Fatal("independently generated tokens reused cryptographic material")
	}
}

func TestParseUserTokenRejectsMalformedInput(t *testing.T) {
	token := mustToken(t, testUsage, "token-id")
	valid := token.UserToken()
	parts := strings.Split(valid, ".")
	tests := map[string]string{
		"empty":             "",
		"legacy protobuf":   "o2asr_CgJpZBIgc2VjcmV0",
		"missing part":      strings.Join(parts[:4], "."),
		"extra part":        valid + ".extra",
		"wrong namespace":   "other." + strings.Join(parts[1:], "."),
		"wrong version":     strings.Join([]string{parts[0], parts[1], "2", parts[3], parts[4]}, "."),
		"empty ID":          strings.Join([]string{parts[0], parts[1], parts[2], "", parts[4]}, "."),
		"invalid ID base64": strings.Join([]string{parts[0], parts[1], parts[2], "!", parts[4]}, "."),
		"short secret":      strings.Join([]string{parts[0], parts[1], parts[2], parts[3], "AA"}, "."),
		"padded secret":     valid + "=",
		"too long":          strings.Repeat("x", maxTokenLength+1),
	}
	for name, candidate := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseUserToken(candidate, testUsage); err == nil {
				t.Fatalf("parsed malformed token %q", candidate)
			}
		})
	}
}

func TestNewRejectsInvalidEnvelopeInputs(t *testing.T) {
	tests := []struct {
		name  string
		usage Usage
		id    string
	}{
		{name: "empty usage", usage: Usage{}, id: "id"},
		{name: "dot in prefix", usage: Usage{Name: "name", Prefix: "bad.prefix"}, id: "id"},
		{name: "empty ID", usage: testUsage},
		{name: "oversized ID", usage: testUsage, id: strings.Repeat("x", maxTokenIDSize+1)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := New(test.usage, test.id, "grant", "subject"); err == nil {
				t.Fatal("New succeeded")
			}
		})
	}
}

func mustToken(t testing.TB, usage Usage, tokenID string) Token {
	t.Helper()
	token, err := New(usage, tokenID, "grant-id", "subject")
	if err != nil {
		t.Fatal(err)
	}
	return token
}
