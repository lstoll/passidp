package idp

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"lds.li/keyset/insecurecleartext"
	"lds.li/keyset/memstore"
	"lds.li/oauth2ext/jwt"
)

func TestKeysetSignerRoundTrip(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)

	store := memstore.New(insecurecleartext.Keeper)
	signer, keys, authenticator, err := initKeysets(ctx, store)
	if err != nil {
		t.Fatal(err)
	}
	algorithms := signer.Algorithms()
	if len(algorithms) != 2 || algorithms[0] != jwt.ES256 || algorithms[1] != jwt.RS256 {
		t.Fatalf("algorithms = %v", algorithms)
	}

	for _, algorithm := range algorithms {
		t.Run(string(algorithm), func(t *testing.T) {
			now := time.Now()
			compact, err := signer.Sign(ctx, map[string]any{
				"sub": "test",
				"iat": now.Unix(),
				"exp": now.Add(time.Hour).Unix(),
			}, jwt.SignOptions{Algorithms: []jwt.Algorithm{algorithm}})
			if err != nil {
				t.Fatal(err)
			}
			verified, err := keys.VerifyJWT(compact, jwt.ValidationPolicy{
				IgnoreIssuer:      true,
				IgnoreAudiences:   true,
				AllowedAlgorithms: []jwt.Algorithm{algorithm},
				RequireIssuedAt:   true,
			})
			if err != nil {
				t.Fatal(err)
			}
			if subject, err := verified.Subject(); err != nil || subject != "test" {
				t.Fatalf("subject = %q, %v", subject, err)
			}
		})
	}

	tag, err := authenticator.Authenticate([]byte("session-id"))
	if err != nil {
		t.Fatal(err)
	}
	if err := authenticator.Verify([]byte("session-id"), tag); err != nil {
		t.Fatal(err)
	}
	if err := authenticator.Verify([]byte("other"), tag); err == nil {
		t.Fatal("authenticator accepted the wrong message")
	}
}

func TestOIDCHandlesReplaceAfterRotation(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)

	store := memstore.New(insecurecleartext.Keeper)
	signer, keys, _, err := initKeysets(ctx, store)
	if err != nil {
		t.Fatal(err)
	}

	now := time.Now()
	claims := map[string]any{
		"sub": "test",
		"iat": now.Unix(),
		"exp": now.Add(time.Hour).Unix(),
	}
	policy := jwt.ValidationPolicy{
		IgnoreIssuer:      true,
		IgnoreAudiences:   true,
		AllowedAlgorithms: []jwt.Algorithm{jwt.ES256},
		RequireIssuedAt:   true,
	}
	oldCompact, err := signer.Sign(ctx, claims, jwt.SignOptions{Algorithms: []jwt.Algorithm{jwt.ES256}})
	if err != nil {
		t.Fatal(err)
	}
	oldKID := jwtHeaderKID(t, oldCompact)

	ks, rev, err := store.Read(ctx, keysetIDOIDCES256)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ks.Rotate(now.Add(25 * time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := store.Write(ctx, keysetIDOIDCES256, ks, rev); err != nil {
		t.Fatal(err)
	}

	nextSigner, nextKeys, err := loadOIDCHandles(ctx, store)
	if err != nil {
		t.Fatal(err)
	}
	if err := keys.Replace(nextKeys); err != nil {
		t.Fatal(err)
	}
	if err := signer.Replace(nextSigner); err != nil {
		t.Fatal(err)
	}

	if _, err := keys.VerifyJWT(oldCompact, policy); err != nil {
		t.Fatalf("old token should still verify after rotation: %v", err)
	}

	newCompact, err := signer.Sign(ctx, claims, jwt.SignOptions{Algorithms: []jwt.Algorithm{jwt.ES256}})
	if err != nil {
		t.Fatal(err)
	}
	if got := jwtHeaderKID(t, newCompact); got == oldKID {
		t.Fatal("expected a new signing kid after rotation")
	}
	if _, err := keys.VerifyJWT(newCompact, policy); err != nil {
		t.Fatalf("new token should verify: %v", err)
	}
}

func jwtHeaderKID(t *testing.T, compact string) string {
	t.Helper()
	parts := strings.Split(compact, ".")
	if len(parts) != 3 {
		t.Fatalf("JWT should have 3 parts, got %d", len(parts))
	}
	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatal(err)
	}
	var header map[string]any
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		t.Fatal(err)
	}
	kid, _ := header["kid"].(string)
	if kid == "" {
		t.Fatal("missing kid")
	}
	return kid
}
