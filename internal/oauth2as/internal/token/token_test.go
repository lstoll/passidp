package token

import (
	"bytes"
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

func TestGrantKeyWorkflowAndRotation(t *testing.T) {
	grantKey, err := GenerateGrantKey()
	if err != nil {
		t.Fatal(err)
	}
	first := mustToken(t, testUsage, "token-1")
	second := mustToken(t, testUsage, "token-2")

	metadata := []byte("sensitive metadata")
	ciphertext, err := grantKey.EncryptMetadata(metadata, "grant-id")
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(ciphertext, metadata) || !bytes.HasPrefix(ciphertext, metadataEnvelopeHeader) {
		t.Fatalf("unexpected metadata envelope: %x", ciphertext)
	}

	firstWrapped, err := grantKey.WrapForToken(&first)
	if err != nil {
		t.Fatal(err)
	}
	firstParsed, err := ParseUserToken(first.UserToken(), testUsage)
	if err != nil {
		t.Fatal(err)
	}
	firstVerified, err := firstParsed.Verify(first.Stored(), "grant-id", "subject")
	if err != nil {
		t.Fatal(err)
	}
	unwrapped, err := firstVerified.UnwrapGrantKey(firstWrapped)
	if err != nil {
		t.Fatal(err)
	}
	plaintext, err := unwrapped.DecryptMetadata(ciphertext, "grant-id")
	if err != nil || !bytes.Equal(plaintext, metadata) {
		t.Fatalf("metadata round trip: got %q, err %v", plaintext, err)
	}

	// Rotation keeps the grant key and metadata ciphertext, but wraps the key
	// under independently derived material for the replacement token.
	secondWrapped, err := unwrapped.WrapForToken(&second)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(firstWrapped, secondWrapped) {
		t.Fatal("rotation produced an identical wrapped grant key")
	}
	if _, err := second.UnwrapGrantKey(firstWrapped); err == nil {
		t.Fatal("replacement token unwrapped the previous token's grant key")
	}
	if _, err := second.UnwrapGrantKey(ciphertext); err == nil {
		t.Fatal("metadata envelope was accepted as a wrapped grant key")
	}
	secondKey, err := second.UnwrapGrantKey(secondWrapped)
	if err != nil {
		t.Fatal(err)
	}
	plaintext, err = secondKey.DecryptMetadata(ciphertext, "grant-id")
	if err != nil || !bytes.Equal(plaintext, metadata) {
		t.Fatalf("rotated metadata round trip: got %q, err %v", plaintext, err)
	}
}

func TestAEADBindingsAndTampering(t *testing.T) {
	key, err := GenerateGrantKey()
	if err != nil {
		t.Fatal(err)
	}
	ciphertext, err := key.EncryptMetadata([]byte("plaintext"), "grant-id")
	if err != nil {
		t.Fatal(err)
	}
	tampered := bytes.Clone(ciphertext)
	tampered[len(tampered)-1] ^= 1
	if _, err := key.DecryptMetadata(tampered, "grant-id"); err == nil {
		t.Fatal("accepted tampered ciphertext")
	}
	if _, err := key.DecryptMetadata(ciphertext, "other-grant"); err == nil {
		t.Fatal("accepted ciphertext under a different grant")
	}
	wrongVersion := bytes.Clone(ciphertext)
	wrongVersion[3]++
	if _, err := key.DecryptMetadata(wrongVersion, "grant-id"); err == nil {
		t.Fatal("accepted an unknown envelope version")
	}
	if _, err := key.DecryptMetadata([]byte("short"), "grant-id"); err == nil {
		t.Fatal("accepted a truncated envelope")
	}
	second, err := GenerateGrantKey()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := second.DecryptMetadata(ciphertext, "grant-id"); err == nil {
		t.Fatal("a different grant key decrypted the metadata")
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
