package idp

import (
	"context"
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

func initKeysets(ctx context.Context, store keyset.AdminStore) (*jwt.Signer, *jwt.VerificationKeySet, session.Authenticator, error) {
	rotator, err := keyset.NewRotator(store,
		keyset.WithInterval(10*time.Minute),
		keyset.WithEnsure(map[string]keyset.Spec{
			keysetIDOIDCRS256:  {Algorithm: keyset.RSAPKCS1v15_2048_SHA256, Policy: oidcPolicy},
			keysetIDOIDCES256:  {Algorithm: keyset.ECDSAP256SHA256, Policy: oidcPolicy},
			keysetIDSessionMAC: {Algorithm: keyset.HMACSHA256, Policy: sessionMACPolicy},
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

func loadOIDCHandles(ctx context.Context, store keyset.Store) (*jwt.Signer, *jwt.VerificationKeySet, error) {
	signingKeys := make([]jwt.SigningKey, 0, len(oidcSigningKeysets))
	verificationKeys := make([]jwt.VerificationKey, 0, len(oidcSigningKeysets)*2)
	for _, spec := range oidcSigningKeysets {
		ks, err := store.Get(ctx, spec.id)
		if err != nil {
			return nil, nil, fmt.Errorf("load signing keyset %q: %w", spec.id, err)
		}
		primary, err := ks.Signer()
		if err != nil {
			return nil, nil, fmt.Errorf("load primary signer for %q: %w", spec.id, err)
		}

		signingKeys = append(signingKeys, jwt.SigningKey{
			Signer:    primary,
			Algorithm: spec.alg,
			KeyID:     fmt.Sprintf("%d", primary.KeyID()),
		})

		for _, source := range ks.Public().Keys {
			if source.State == "disabled" {
				continue
			}
			key, err := verificationKeyFromPublic(spec.alg, source.ID, source.PublicKey)
			if err != nil {
				return nil, nil, fmt.Errorf("public key %d from keyset %q: %w", source.ID, spec.id, err)
			}
			verificationKeys = append(verificationKeys, key)
		}
	}

	signer, err := jwt.NewSignerFromKeys(jwt.SignerConfig{
		Keys:                signingKeys,
		PreferredAlgorithms: []jwt.Algorithm{jwt.ES256, jwt.RS256},
	})
	if err != nil {
		return nil, nil, fmt.Errorf("create JWT signer: %w", err)
	}
	keys, err := jwt.NewVerificationKeySet(verificationKeys...)
	if err != nil {
		return nil, nil, fmt.Errorf("create verification key set: %w", err)
	}
	return signer, keys, nil
}

func refreshOIDCHandles(ctx context.Context, store keyset.Store, signer *jwt.Signer, keys *jwt.VerificationKeySet) {
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

func verificationKeyFromPublic(alg jwt.Algorithm, id uint32, der []byte) (jwt.VerificationKey, error) {
	publicKey, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return jwt.VerificationKey{}, fmt.Errorf("parse public key: %w", err)
	}
	return jwt.VerificationKey{Key: publicKey, Algorithm: alg, KeyID: fmt.Sprintf("%d", id)}, nil
}

type keysetSessionAuthenticator struct {
	client *keyset.Client
}

func (a *keysetSessionAuthenticator) Authenticate(message []byte) ([]byte, error) {
	mac, err := a.client.MAC(context.Background(), keysetIDSessionMAC)
	if err != nil {
		return nil, err
	}
	return mac.Compute(message)
}

func (a *keysetSessionAuthenticator) Verify(message, authenticator []byte) error {
	mac, err := a.client.MAC(context.Background(), keysetIDSessionMAC)
	if err != nil {
		return err
	}
	return mac.Verify(authenticator, message)
}
