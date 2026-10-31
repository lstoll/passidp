package oauth2as

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"lds.li/oauth2ext/dpop"
	"lds.li/oauth2ext/jwt"
	"lds.li/passidp/internal/oauth2as/oauth2proto"
)

func TestRefreshReuseRequiresAuthentication(t *testing.T) {
	for _, grace := range []time.Duration{0, time.Minute} {
		for _, bound := range []bool{false, true} {
			t.Run(fmt.Sprintf("grace=%s/dpop=%t", grace, bound), func(t *testing.T) {
				store := newTestStorage(t)
				signer, keys := testSignerVerifier(t)
				proofKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				if err != nil {
					t.Fatal(err)
				}
				proofSigner, err := jwt.NewSigningIdentity(proofKey, "", "")
				if err != nil {
					t.Fatal(err)
				}
				now := time.Now().UTC().Truncate(time.Microsecond)
				var grantID string
				server, err := NewServer(Config{
					Issuer: "https://issuer", Storage: store, Signer: signer, VerificationKeys: keys,
					Clients:              staticClientSource{{ID: "client", Secrets: []string{"secret"}, RedirectURIs: []string{"https://client/callback"}, SkipPKCE: true}},
					RefreshTokenValidity: time.Hour, GrantValidity: time.Hour, RefreshTokenRotationGracePeriod: grace,
					DPoPVerifier: &dpop.Verifier{},
					TokenHandler: func(_ context.Context, req *TokenRequest) (*TokenResponse, error) {
						grantID = req.GrantID
						return &TokenResponse{}, nil
					},
					UserinfoHandler: func(context.Context, *UserinfoRequest) (*UserinfoResponse, error) { return &UserinfoResponse{}, nil },
				})
				if err != nil {
					t.Fatal(err)
				}
				server.now = func() time.Time { return now }
				request := func(withProof bool) *http.Request {
					r := httptest.NewRequest(http.MethodPost, "https://issuer/token", nil)
					if withProof {
						proof, err := dpop.Sign(t.Context(), proofSigner, dpop.ProofOptions{HTTPMethod: http.MethodPost, HTTPURI: "https://issuer/token"})
						if err != nil {
							t.Fatal(err)
						}
						r.Header.Set("DPoP", proof)
					}
					return r
				}
				redirect, err := server.GrantAuth(t.Context(), &AuthGrant{Request: &AuthRequest{ClientID: "client", RedirectURI: "https://client/callback"}, UserID: "user", GrantedScopes: []string{"offline_access"}})
				if err != nil {
					t.Fatal(err)
				}
				u, err := url.Parse(redirect)
				if err != nil {
					t.Fatal(err)
				}
				issued, err := server.codeToken(t.Context(), request(bound), &oauth2proto.TokenRequest{Code: u.Query().Get("code"), RedirectURI: "https://client/callback", ClientID: "client", ClientSecret: "secret"})
				if err != nil {
					t.Fatal(err)
				}
				refresh := func(token, secret string, proof bool) (*oauth2proto.TokenResponse, error) {
					return server.refreshToken(t.Context(), request(proof), &oauth2proto.TokenRequest{RefreshToken: token, ClientID: "client", ClientSecret: secret})
				}
				replacement, err := refresh(issued.RefreshToken, "secret", bound)
				if err != nil {
					t.Fatal(err)
				}
				now = now.Add(grace + time.Second)
				if _, err := refresh(issued.RefreshToken, "wrong", false); err == nil {
					t.Fatal("wrong client secret accepted")
				}
				if _, err := store.getGrant(t.Context(), grantID); err != nil {
					t.Fatalf("unauthenticated reuse revoked grant: %v", err)
				}
				if bound {
					if _, err := refresh(issued.RefreshToken, "secret", false); err == nil {
						t.Fatal("missing DPoP proof accepted")
					}
					if _, err := store.getGrant(t.Context(), grantID); err != nil {
						t.Fatalf("reuse without DPoP revoked grant: %v", err)
					}
				}
				successor, err := refresh(replacement.RefreshToken, "secret", bound)
				if err != nil {
					t.Fatalf("successor unusable after unauthenticated reuse: %v", err)
				}
				if _, err := refresh(issued.RefreshToken, "secret", bound); err == nil {
					t.Fatal("authenticated reuse accepted")
				}
				if _, err := store.getGrant(t.Context(), grantID); !errors.Is(err, ErrNotFound) {
					t.Fatalf("authenticated reuse did not revoke grant: %v", err)
				}
				if _, err := refresh(successor.RefreshToken, "secret", bound); err == nil {
					t.Fatal("successor survived authenticated reuse")
				}
			})
		}
	}
}
