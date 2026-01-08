package idp

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/tink-crypto/tink-go/v2/jwt"
	"github.com/tink-crypto/tink-go/v2/keyset"
	"github.com/tink-crypto/tink-go/v2/proto/tink_go_proto"
	"google.golang.org/protobuf/types/known/durationpb"
	"lds.li/oauth2ext/oauth2as"
	"lds.li/passidp/internal/storage"
	"lds.li/tinkrotate"
	tinkrotatev1 "lds.li/tinkrotate/proto/tinkrotate/v1"
)

type Keyset struct {
	// Name of the keyset, used to refer to it in the store
	Name string
	// Template for new keys in this set
	Template *tink_go_proto.KeyTemplate
	// RotateEvery indicates how often we should rotate a new key in.
	RotateEvery time.Duration
}

const (
	keysetIDOIDC      = "oidc"
	keysetIDOIDCES256 = "oidc-es256"
)

var (
	oidcRotatePolicy = &tinkrotatev1.RotationPolicy{
		KeyTemplate:         jwt.RS256_2048_F4_Key_Template(),
		PrimaryDuration:     durationpb.New(24 * time.Hour),
		PropagationTime:     durationpb.New(6 * time.Hour),
		PhaseOutDuration:    durationpb.New(24 * time.Hour),
		DeletionGracePeriod: durationpb.New(0),
	}
	oidcES256RotatePolicy = &tinkrotatev1.RotationPolicy{
		KeyTemplate:         jwt.ES256Template(),
		PrimaryDuration:     durationpb.New(24 * time.Hour),
		PropagationTime:     durationpb.New(6 * time.Hour),
		PhaseOutDuration:    durationpb.New(24 * time.Hour),
		DeletionGracePeriod: durationpb.New(0),
	}
)

func initKeysets(ctx context.Context, state *storage.State) (oidcKeyset *KeysetSigner, _ error) {
	store := storage.NewKeysetStore(state)

	autoRotator, err := tinkrotate.NewAutoRotator(store, 10*time.Minute, &tinkrotate.AutoRotatorOpts{
		ProvisionPolicies: map[string]*tinkrotatev1.RotationPolicy{
			keysetIDOIDC:      oidcRotatePolicy,
			keysetIDOIDCES256: oidcES256RotatePolicy,
		},
	}) // Create the Rotator instance using the proto policy
	if err != nil {
		return nil, fmt.Errorf("failed to create autoRotator: %w", err)
	}

	// need an initial run to provision keysets
	if err := autoRotator.RunOnce(ctx); err != nil {
		return nil, fmt.Errorf("failed to run autoRotator: %w", err)
	}

	autoRotator.Start(ctx)

	pf := tinkrotate.NewPrimitiveSource(store, 0)

	return &KeysetSigner{
		defaultAlg: "RS256",
		algKeysets: map[string]string{
			"RS256": keysetIDOIDC,
			"ES256": keysetIDOIDCES256,
		},
		primitiveSource: pf,
		// TODO - should the primitive factory be able to return handles?
		store: store,
	}, nil
}

var (
	_ oauth2as.AlgorithmSigner = (*KeysetSigner)(nil)
	_ jwt.Verifier             = (*KeysetSigner)(nil)
)

// KeysetSigner can retrieve handles for the given keyset from the DB.
type KeysetSigner struct {
	// defaultAlg is the default algorithm to use for signing, when no algorithm is specified.
	defaultAlg string
	// algKeysets maps an algorithm to the keyset ID for that algorithm.
	algKeysets map[string]string
	// store is the store for the keysets.
	store tinkrotate.Store
	// primitiveSource is used to create signing primitives. Verification is
	// done manually due to the need to merge verification handles.
	primitiveSource *tinkrotate.PrimitiveSource
}

func (k *KeysetSigner) SignAndEncode(rawJWT *jwt.RawJWT) (string, error) {
	return k.SignAndEncodeForAlgorithm(k.defaultAlg, rawJWT)
}

func (k *KeysetSigner) SignAndEncodeForAlgorithm(alg string, rawJWT *jwt.RawJWT) (string, error) {
	ksid, ok := k.algKeysets[alg]
	if !ok {
		return "", fmt.Errorf("no keyset for algorithm %s", alg)
	}
	signer, err := k.primitiveSource.GetSigner(ksid)
	if err != nil {
		return "", fmt.Errorf("get signer: %w", err)
	}
	return signer.SignAndEncode(rawJWT)
}

func (k *KeysetSigner) VerifyAndDecode(compact string, validator *jwt.Validator) (*jwt.VerifiedJWT, error) {
	h, err := k.mergedVerificationHandle()
	if err != nil {
		return nil, fmt.Errorf("getting merged verification handle: %w", err)
	}
	verifier, err := jwt.NewVerifier(h)
	if err != nil {
		return nil, fmt.Errorf("new verifier: %w", err)
	}
	return verifier.VerifyAndDecode(compact, validator)
}

func (k *KeysetSigner) mergedVerificationHandle() (*keyset.Handle, error) {
	mgr := keyset.NewManager()
	var lastKid uint32
	for _, id := range k.algKeysets {
		h, err := k.store.GetPublicHandle(context.Background(), id)
		if err != nil {
			return nil, fmt.Errorf("get current handle: %w", err)
		}
		for i := range h.Len() {
			e, err := h.Entry(i)
			if err != nil {
				return nil, fmt.Errorf("get entry: %w", err)
			}
			if _, err := mgr.AddKey(e.Key()); err != nil {
				return nil, fmt.Errorf("add key: %w", err)
			}
			lastKid = e.KeyID()
		}
	}
	// only using for verification so the kid isn't important, but we need one
	// so just use the last we saw.
	if err := mgr.SetPrimary(lastKid); err != nil {
		return nil, fmt.Errorf("set primary: %w", err)
	}
	h, err := mgr.Handle()
	if err != nil {
		return nil, fmt.Errorf("getting merged handle: %w", err)
	}
	return h, nil
}

func (k *KeysetSigner) SignerForAlgorithm(ctx context.Context, alg string) (jwt.Signer, error) {
	id, ok := k.algKeysets[alg]
	if !ok {
		return nil, fmt.Errorf("no keyset for algorithm %s", alg)
	}
	h, err := k.store.GetHandle(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("get current handle: %w", err)
	}

	signer, err := jwt.NewSigner(h)
	if err != nil {
		return nil, fmt.Errorf("new signer: %w", err)
	}

	return signer, nil
}

// SupportedAlgorithms returns the list of algorithms supported by this
// signer.
func (k *KeysetSigner) SupportedAlgorithms() []string {
	var algs []string
	for alg := range k.algKeysets {
		algs = append(algs, string(alg))
	}
	return algs
}

func (k *KeysetSigner) JWKS(ctx context.Context) ([]byte, error) {
	mergejwksm := map[string]any{
		"keys": []any{},
	}

	for alg, id := range k.algKeysets {
		h, err := k.store.GetPublicHandle(ctx, id)
		if err != nil {
			return nil, fmt.Errorf("getting handle for %s: %w", alg, err)
		}

		jwks, err := jwt.JWKSetFromPublicKeysetHandle(h)
		if err != nil {
			return nil, fmt.Errorf("getting JWKS for %s: %w", alg, err)
		}

		jwksm := make(map[string]any)
		if err := json.Unmarshal(jwks, &jwksm); err != nil {
			return nil, fmt.Errorf("unmarshalling JWKS for %s: %w", alg, err)
		}

		for _, k := range jwksm["keys"].([]any) {
			mergejwksm["keys"] = append(mergejwksm["keys"].([]any), k)
		}
	}

	mergejwks, err := json.Marshal(mergejwksm)
	if err != nil {
		return nil, fmt.Errorf("marshalling merged JWKS: %w", err)
	}

	return mergejwks, nil
}
