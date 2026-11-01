package token

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

func TestNewAndDigest(t *testing.T) {
	for _, tc := range []struct {
		kind   Kind
		prefix string
	}{
		{kind: AuthorizationCode, prefix: "pc1_"},
		{kind: RefreshToken, prefix: "pr1_"},
	} {
		t.Run(tc.prefix, func(t *testing.T) {
			raw, id := New(tc.kind)
			if !strings.HasPrefix(raw, tc.prefix) {
				t.Fatalf("token %q does not have prefix %q", raw, tc.prefix)
			}
			suffix := strings.TrimPrefix(raw, tc.prefix)
			if suffix == "" {
				t.Fatal("token suffix is empty")
			}
			if len(suffix) > maxTokenSuffixLength {
				t.Fatalf("token suffix has unreasonable length %d", len(suffix))
			}
			sum := sha256.Sum256([]byte(raw))
			if want := hex.EncodeToString(sum[:]); id != want {
				t.Fatalf("ID = %q, want %q", id, want)
			}
			got, err := Digest(raw, tc.kind)
			if err != nil || got != id {
				t.Fatalf("Digest = %q, %v; want %q", got, err, id)
			}
		})
	}
}

func TestDigestStableVector(t *testing.T) {
	const raw = "pc1_test-secret"
	const want = "9b10987f15f849b2e7a504ca350af08d2549a4a8ca04c4f197247b8c94b6b323"
	got, err := Digest(raw, AuthorizationCode)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("Digest = %q, want %q", got, want)
	}
}

func TestDigestKindSeparationAndChanges(t *testing.T) {
	raw := "pc1_same-token"
	first, err := Digest(raw, AuthorizationCode)
	if err != nil {
		t.Fatal(err)
	}
	changed, err := Digest(raw+"x", AuthorizationCode)
	if err != nil {
		t.Fatal(err)
	}
	if first == changed {
		t.Fatal("changing the token did not change its digest")
	}
	refresh, err := Digest("pr1_same-token", RefreshToken)
	if err != nil || refresh == first {
		t.Fatalf("token prefix did not separate digests: %v", err)
	}
	if _, err := Digest(raw, RefreshToken); err == nil {
		t.Fatal("accepted authorization code as a refresh token")
	}
	if _, err := Digest("pr1_same-token", AuthorizationCode); err == nil {
		t.Fatal("accepted refresh token as an authorization code")
	}
}

func TestDigestRejectsMalformedTokens(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		kind Kind
	}{
		{name: "empty", raw: "", kind: AuthorizationCode},
		{name: "prefix only", raw: "pc1_", kind: AuthorizationCode},
		{name: "old format", raw: "o2as.c.1.a.b", kind: AuthorizationCode},
		{name: "wrong prefix", raw: "px1_secret", kind: AuthorizationCode},
		{name: "unknown expected kind", raw: "pc1_secret", kind: Kind(99)},
		{name: "oversized suffix", raw: "pc1_" + strings.Repeat("x", maxTokenSuffixLength+1), kind: AuthorizationCode},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Digest(tc.raw, tc.kind); err == nil {
				t.Fatalf("Digest(%q, %d) succeeded", tc.raw, tc.kind)
			}
		})
	}
}
