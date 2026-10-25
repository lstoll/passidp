package internal

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"lds.li/oauth2ext/jwt"
)

func NewTestSigner(t testing.TB, algorithms ...jwt.Algorithm) jwt.Signer {
	t.Helper()
	if len(algorithms) == 0 {
		algorithms = []jwt.Algorithm{jwt.ES256}
	}
	identities := make([]*jwt.SigningIdentity, 0, len(algorithms))
	for _, algorithm := range algorithms {
		switch algorithm {
		case jwt.ES256:
			key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			identity, err := jwt.NewSigningIdentity(key, algorithm, "")
			if err != nil {
				t.Fatal(err)
			}
			identities = append(identities, identity)
		case jwt.RS256:
			key, err := rsa.GenerateKey(rand.Reader, 2048)
			if err != nil {
				t.Fatal(err)
			}
			identity, err := jwt.NewSigningIdentity(key, algorithm, "")
			if err != nil {
				t.Fatal(err)
			}
			identities = append(identities, identity)
		default:
			t.Fatalf("unsupported test algorithm %q", algorithm)
		}
	}
	signer, err := jwt.NewSigningKeySet(identities...)
	if err != nil {
		t.Fatal(err)
	}
	return signer
}
