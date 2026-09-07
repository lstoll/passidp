package idp

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"log/slog"
	"time"

	"lds.li/keyset"
	"lds.li/oauth2ext/jwt"
	"lds.li/session"
)

const (
	keysetIDOIDCRS256  = "oidc-rs256"
	keysetIDOIDCES256  = "oidc-es256"
	keysetIDSessionMAC = "session-mac"

	typeOIDCRS256  = keysetIDOIDCRS256
	typeOIDCES256  = keysetIDOIDCES256
	typeSessionMAC = keysetIDSessionMAC

	oidcKeyRefreshInterval = time.Minute
)

var (
	oidcPolicy = keyset.Policy{
		Primary:   24 * time.Hour,
		Propagate: 6 * time.Hour,
		PhaseOut:  24 * time.Hour,
	}
	sessionMACPolicy = keyset.Policy{
		Primary:   24 * time.Hour,
		Propagate: 6 * time.Hour,
		PhaseOut:  24 * time.Hour,
	}
	oidcSigningKeysets = []struct {
		id  string
		alg jwt.Algorithm
	}{
		{id: keysetIDOIDCES256, alg: jwt.ES256},
		{id: keysetIDOIDCRS256, alg: jwt.RS256},
	}
)

func initKeysets(ctx context.Context, store keyset.AdminStore) (*jwt.SigningKeySet, *jwt.VerificationKeySet, session.Authenticator, error) {
	registry, err := newKeysetRegistry()
	if err != nil {
		return nil, nil, nil, err
	}
	rotator, err := keyset.NewRotator(store, registry,
		keyset.WithInterval(10*time.Minute),
		keyset.WithEnsure(map[string]string{
			keysetIDOIDCRS256:  typeOIDCRS256,
			keysetIDOIDCES256:  typeOIDCES256,
			keysetIDSessionMAC: typeSessionMAC,
		}),
	)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("create keyset rotator: %w", err)
	}
	if err := rotator.Once(ctx); err != nil {
		return nil, nil, nil, fmt.Errorf("provision keysets: %w", err)
	}
	if err := rotator.Run(ctx); err != nil {
		return nil, nil, nil, fmt.Errorf("start keyset rotator: %w", err)
	}

	client, err := keyset.NewClient(store, keyset.WithTTL(5*time.Minute))
	if err != nil {
		return nil, nil, nil, fmt.Errorf("create keyset client: %w", err)
	}

	signer, keys, err := loadOIDCHandles(ctx, store)
	if err != nil {
		return nil, nil, nil, err
	}
	go refreshOIDCHandles(ctx, store, signer, keys)

	return signer, keys, &keysetSessionAuthenticator{client: client}, nil
}

func newKeysetRegistry() (*keyset.Registry, error) {
	registry, err := keyset.NewRegistry(map[string]keyset.Type{
		typeOIDCES256:  {Policy: oidcPolicy, New: newES256Material},
		typeOIDCRS256:  {Policy: oidcPolicy, New: newRS256Material},
		typeSessionMAC: {Policy: sessionMACPolicy, New: newHMACSHA256Material},
	})
	if err != nil {
		return nil, fmt.Errorf("create keyset registry: %w", err)
	}
	return registry, nil
}

func newES256Material(context.Context) (keyset.Material, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return keyset.Material{}, err
	}
	return marshalSigningMaterial(key, &key.PublicKey)
}

func newRS256Material(context.Context) (keyset.Material, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return keyset.Material{}, err
	}
	return marshalSigningMaterial(key, &key.PublicKey)
}

func newHMACSHA256Material(context.Context) (keyset.Material, error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return keyset.Material{}, err
	}
	return keyset.Material{Private: key}, nil
}

func marshalSigningMaterial(private any, public crypto.PublicKey) (keyset.Material, error) {
	privBytes, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		return keyset.Material{}, fmt.Errorf("marshal private key: %w", err)
	}
	pubBytes, err := x509.MarshalPKIXPublicKey(public)
	if err != nil {
		return keyset.Material{}, fmt.Errorf("marshal public key: %w", err)
	}
	return keyset.Material{Private: privBytes, Public: pubBytes}, nil
}

func loadOIDCHandles(ctx context.Context, store keyset.Store) (*jwt.SigningKeySet, *jwt.VerificationKeySet, error) {
	identities := make([]*jwt.SigningIdentity, 0, len(oidcSigningKeysets))
	verificationKeys := make([]jwt.VerificationKey, 0, len(oidcSigningKeysets)*2)
	for _, spec := range oidcSigningKeysets {
		ks, err := store.Get(ctx, spec.id)
		if err != nil {
			return nil, nil, fmt.Errorf("load signing keyset %q: %w", spec.id, err)
		}
		primary, ok := ks.Primary()
		if !ok {
			return nil, nil, fmt.Errorf("signing keyset %q has no primary", spec.id)
		}
		signer, err := signerFromPKCS8(primary.Private)
		if err != nil {
			return nil, nil, fmt.Errorf("parse primary signer for %q: %w", spec.id, err)
		}
		identity, err := jwt.NewSigningIdentity(signer, spec.alg, primary.ID)
		if err != nil {
			return nil, nil, fmt.Errorf("create signing identity for %q: %w", spec.id, err)
		}
		identities = append(identities, identity)

		for _, source := range ks.Public().Keys {
			if !source.State.IsUsable() {
				continue
			}
			key, err := verificationKeyFromPublic(spec.alg, source.ID, source.PublicKey)
			if err != nil {
				return nil, nil, fmt.Errorf("public key %s from keyset %q: %w", source.ID, spec.id, err)
			}
			verificationKeys = append(verificationKeys, key)
		}
	}

	signer, err := jwt.NewSigningKeySet(identities...)
	if err != nil {
		return nil, nil, fmt.Errorf("create JWT signing key set: %w", err)
	}
	keys, err := jwt.NewVerificationKeySet(verificationKeys...)
	if err != nil {
		return nil, nil, fmt.Errorf("create verification key set: %w", err)
	}
	return signer, keys, nil
}

func refreshOIDCHandles(ctx context.Context, store keyset.Store, signer *jwt.SigningKeySet, keys *jwt.VerificationKeySet) {
	ticker := time.NewTicker(oidcKeyRefreshInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			nextSigner, nextKeys, err := loadOIDCHandles(ctx, store)
			if err != nil {
				slog.ErrorContext(ctx, "refresh oauth signing keys", slog.String("error", err.Error()))
				continue
			}
			if err := keys.Replace(nextKeys); err != nil {
				slog.ErrorContext(ctx, "replace oauth verification keys", slog.String("error", err.Error()))
				continue
			}
			if err := signer.Replace(nextSigner); err != nil {
				slog.ErrorContext(ctx, "replace oauth signer", slog.String("error", err.Error()))
			}
		}
	}
}

func verificationKeyFromPublic(alg jwt.Algorithm, id string, der []byte) (jwt.VerificationKey, error) {
	publicKey, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return jwt.VerificationKey{}, fmt.Errorf("parse public key: %w", err)
	}
	return jwt.VerificationKey{Key: publicKey, Algorithm: alg, KeyID: id}, nil
}

func signerFromPKCS8(der []byte) (crypto.Signer, error) {
	key, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, err
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("PKCS#8 key is not a signer")
	}
	return signer, nil
}

type keysetSessionAuthenticator struct {
	client *keyset.Client
}

func (a *keysetSessionAuthenticator) Authenticate(message []byte) ([]byte, error) {
	mac, err := a.sessionMAC()
	if err != nil {
		return nil, err
	}
	return mac.Authenticate(message)
}

func (a *keysetSessionAuthenticator) Verify(message, authenticator []byte) error {
	mac, err := a.sessionMAC()
	if err != nil {
		return err
	}
	return mac.Verify(message, authenticator)
}

func (a *keysetSessionAuthenticator) sessionMAC() (session.Authenticator, error) {
	ks, err := a.client.Get(context.Background(), keysetIDSessionMAC)
	if err != nil {
		return nil, err
	}
	primary, ok := ks.Primary()
	if !ok {
		return nil, fmt.Errorf("session keyset has no primary")
	}
	var previous [][]byte
	for _, key := range ks.Keys() {
		if key.ID == primary.ID || !key.State.IsUsable() {
			continue
		}
		previous = append(previous, key.Private)
	}
	return session.NewHMACSHA256Authenticator(primary.Private, previous...)
}
