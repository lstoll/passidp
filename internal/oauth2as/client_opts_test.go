package oauth2as

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"lds.li/oauth2ext/jwt"
)

func TestApplyClientOpts(t *testing.T) {
	t.Run("rejects public client with skip PKCE", func(t *testing.T) {
		_, err := applyClientOpts([]ClientOpt{ClientOptPublic(), ClientOptSkipPKCE()})
		if err == nil {
			t.Fatal("expected error")
		}
	})

	t.Run("allows public client alone", func(t *testing.T) {
		co, err := applyClientOpts([]ClientOpt{ClientOptPublic()})
		if err != nil {
			t.Fatal(err)
		}
		if !co.public || co.skipPKCE {
			t.Fatalf("unexpected opts: %+v", co)
		}
	})

	t.Run("requires keys for private key jwt", func(t *testing.T) {
		_, err := applyClientOpts([]ClientOpt{ClientOptPrivateKeyJWT(nil)})
		if err == nil {
			t.Fatal("expected error")
		}
	})

	t.Run("rejects private key jwt public client", func(t *testing.T) {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		keys, err := jwt.NewVerificationKeySet(jwt.VerificationKey{Key: &key.PublicKey, Algorithm: jwt.ES256, KeyID: "key"})
		if err != nil {
			t.Fatal(err)
		}
		_, err = applyClientOpts([]ClientOpt{ClientOptPublic(), ClientOptPrivateKeyJWT(keys)})
		if err == nil {
			t.Fatal("expected error")
		}
	})
}
