package oauth2as

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"lds.li/oauth2ext/dpop"
	"lds.li/passidp/internal/oauth2as/internal/token"
	"lds.li/passidp/internal/oauth2as/oauth2proto"
)

func newCodeExchangeServer(t *testing.T) *Server {
	t.Helper()
	signer, verifier := testSignerVerifier(t)
	return &Server{
		config: Config{
			Issuer:           "https://issuer",
			Storage:          newTestStorage(t),
			Signer:           signer,
			VerificationKeys: verifier,
			DPoPVerifier:     &dpop.Verifier{},
			TokenHandler: func(context.Context, *TokenRequest) (*TokenResponse, error) {
				return &TokenResponse{}, nil
			},
			RefreshTokenValidity: time.Hour,
			Clients: staticClientSource{{
				ID:           "client-id",
				Secrets:      []string{"client-secret"},
				RedirectURIs: []string{"https://redirect"},
				SkipPKCE:     true,
			}},
		},
		now: time.Now,
	}
}

func codeExchangeRequest(code string) *oauth2proto.TokenRequest {
	return &oauth2proto.TokenRequest{
		GrantType:    oauth2proto.GrantTypeAuthorizationCode,
		Code:         code,
		RedirectURI:  "https://redirect",
		ClientID:     "client-id",
		ClientSecret: "client-secret",
	}
}

func tokenRequest() *http.Request {
	return httptest.NewRequest(http.MethodPost, "/token", nil)
}

func grantIDForCode(t *testing.T, s *Storage, code string) string {
	t.Helper()
	codeID, err := token.Digest(code, token.AuthorizationCode)
	if err != nil {
		t.Fatal(err)
	}
	stored, err := s.getAuthCode(t.Context(), codeID)
	if err != nil {
		t.Fatal(err)
	}
	return stored.GrantID
}

func wantTokenError(t *testing.T, err error, code oauth2proto.TokenErrorCode) {
	t.Helper()
	var tokenErr *oauth2proto.TokenError
	if !errors.As(err, &tokenErr) || tokenErr.ErrorCode != code {
		t.Fatalf("error = %v, want %s", err, code)
	}
}

func TestAuthorizationCodeReuseRevokesGrant(t *testing.T) {
	for _, tc := range []struct {
		name string
		// afterFirstUse runs between the first and second exchange.
		afterFirstUse func(t *testing.T, s *Server, code string)
	}{
		{name: "within code lifetime"},
		{name: "after code lifetime", afterFirstUse: func(t *testing.T, s *Server, code string) {
			codeID, err := token.Digest(code, token.AuthorizationCode)
			if err != nil {
				t.Fatal(err)
			}
			stored, err := s.config.Storage.getAuthCode(t.Context(), codeID)
			if err != nil {
				t.Fatal(err)
			}
			stored.ValidUntil = time.Now().Add(-time.Second)
			if err := s.config.Storage.seed(t.Context(), storageFixtures{AuthCodes: []storedAuthCode{*stored}}); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newCodeExchangeServer(t)
			code := newCodeGrant(t, s.config.Storage)
			grantID := grantIDForCode(t, s.config.Storage, code)

			first, err := s.codeToken(t.Context(), tokenRequest(), codeExchangeRequest(code))
			if err != nil {
				t.Fatalf("first exchange: %v", err)
			}
			if first.RefreshToken == "" {
				t.Fatal("first exchange issued no refresh token")
			}
			if tc.afterFirstUse != nil {
				tc.afterFirstUse(t, s, code)
			}

			_, err = s.codeToken(t.Context(), tokenRequest(), codeExchangeRequest(code))
			wantTokenError(t, err, oauth2proto.TokenErrorCodeInvalidGrant)

			if _, err := s.config.Storage.getGrant(t.Context(), grantID); !errors.Is(err, ErrNotFound) {
				t.Fatalf("grant after code reuse: err = %v, want ErrNotFound", err)
			}
			_, err = s.refreshToken(t.Context(), tokenRequest(), &oauth2proto.TokenRequest{
				GrantType:    oauth2proto.GrantTypeRefreshToken,
				RefreshToken: first.RefreshToken,
				ClientID:     "client-id",
				ClientSecret: "client-secret",
			})
			wantTokenError(t, err, oauth2proto.TokenErrorCodeInvalidGrant)
		})
	}
}

func TestAuthorizationCodeReuseRequiresClientAuthentication(t *testing.T) {
	s := newCodeExchangeServer(t)
	code := newCodeGrant(t, s.config.Storage)
	grantID := grantIDForCode(t, s.config.Storage, code)
	if _, err := s.codeToken(t.Context(), tokenRequest(), codeExchangeRequest(code)); err != nil {
		t.Fatalf("first exchange: %v", err)
	}

	replay := codeExchangeRequest(code)
	replay.ClientSecret = "wrong-secret"
	_, err := s.codeToken(t.Context(), tokenRequest(), replay)
	wantTokenError(t, err, oauth2proto.TokenErrorCodeInvalidClient)

	if _, err := s.config.Storage.getGrant(t.Context(), grantID); err != nil {
		t.Fatalf("unauthenticated replay revoked grant: %v", err)
	}
}

func TestCodeExchangeRequiresVerifierWhenChallengeWasSent(t *testing.T) {
	s := newCodeExchangeServer(t) // client has SkipPKCE set
	code := newCodeGrant(t, s.config.Storage)
	grant, err := s.config.Storage.getGrant(t.Context(), grantIDForCode(t, s.config.Storage, code))
	if err != nil {
		t.Fatal(err)
	}
	const verifier = "a-code-verifier-that-is-long-enough-for-pkce-0123456789"
	sum := sha256.Sum256([]byte(verifier))
	grant.CodeChallenge = base64.RawURLEncoding.EncodeToString(sum[:])
	if err := s.config.Storage.seed(t.Context(), storageFixtures{Grants: []storedGrant{*grant}}); err != nil {
		t.Fatal(err)
	}

	_, err = s.codeToken(t.Context(), tokenRequest(), codeExchangeRequest(code))
	wantTokenError(t, err, oauth2proto.TokenErrorCodeUnauthorizedClient)

	withVerifier := codeExchangeRequest(code)
	withVerifier.CodeVerifier = verifier
	if _, err := s.codeToken(t.Context(), tokenRequest(), withVerifier); err != nil {
		t.Fatalf("exchange with verifier: %v", err)
	}
}

func TestCodeExchangeRejectsMalformedDPoPProof(t *testing.T) {
	for _, tc := range []struct {
		name     string
		verifier *dpop.Verifier
	}{
		{name: "malformed proof", verifier: &dpop.Verifier{}},
		{name: "DPoP not configured"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newCodeExchangeServer(t)
			s.config.DPoPVerifier = tc.verifier
			code := newCodeGrant(t, s.config.Storage)

			req := tokenRequest()
			req.Header.Set("DPoP", "not-a-jwt")
			_, err := s.codeToken(t.Context(), req, codeExchangeRequest(code))
			wantTokenError(t, err, oauth2proto.TokenErrorCodeInvalidDPoPProof)

			rec := httptest.NewRecorder()
			_ = oauth2proto.WriteError(rec, req, err)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want %d", rec.Code, http.StatusBadRequest)
			}
		})
	}
}
