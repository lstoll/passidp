package oauth2as

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
	"uuid"

	"lds.li/oauth2ext/clientjwt"
	"lds.li/oauth2ext/jwt"
	"lds.li/oauth2ext/oidc"
	"lds.li/passidp/internal/oauth2as/internal/token"
	"lds.li/passidp/internal/oauth2as/oauth2proto"
)

func TestJWTClientTokenAuth(t *testing.T) {
	const (
		issuer   = "https://issuer.example"
		tokenURL = "https://issuer.example/token"
		clientID = "jwt-client"
	)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	clientSigner, err := jwt.NewSigningIdentity(key, jwt.ES256, "client-key")
	if err != nil {
		t.Fatal(err)
	}
	keys, err := jwt.NewVerificationKeySetFromSigner(clientSigner)
	if err != nil {
		t.Fatal(err)
	}

	signer, verifier := testSignerVerifier(t)
	server := &Server{
		config: Config{
			Issuer:               issuer,
			TokenURL:             tokenURL,
			Storage:              newTestStorage(t),
			Signer:               signer,
			VerificationKeys:     verifier,
			RefreshTokenValidity: time.Hour,
			TokenHandler: func(context.Context, *TokenRequest) (*TokenResponse, error) {
				return &TokenResponse{}, nil
			},
			Clients: staticClientSource{
				{
					ID:           clientID,
					RedirectURLs: []string{"https://redirect"},
					Opts:         []ClientOpt{ClientOptSkipPKCE(), ClientOptPrivateKeyJWT(keys)},
				},
				{
					ID:           "client-id",
					Secrets:      []string{"client-secret"},
					RedirectURLs: []string{"https://redirect"},
					Opts:         []ClientOpt{ClientOptSkipPKCE()},
				},
			},
		},
		now:                   time.Now,
		clientAssertionReplay: newMemoryClientAssertionReplayStore(),
	}

	t.Run("code exchange", func(t *testing.T) {
		code := jwtClientCodeGrant(t, server.config.Storage)
		assertion, err := clientjwt.Sign(t.Context(), clientSigner, clientjwt.SignOptions{ClientID: clientID, Audience: tokenURL, Algorithm: jwt.ES256})
		if err != nil {
			t.Fatal(err)
		}
		resp, err := server.codeToken(t.Context(), httptest.NewRequest(http.MethodPost, "/token", nil), &oauth2proto.TokenRequest{
			GrantType:           oauth2proto.GrantTypeAuthorizationCode,
			Code:                code,
			RedirectURI:         "https://redirect",
			ClientID:            clientID,
			ClientAssertionType: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
			ClientAssertion:     assertion,
		})
		if err != nil {
			t.Fatal(err)
		}
		if resp.AccessToken == "" {
			t.Fatal("missing access token")
		}
	})

	t.Run("refresh", func(t *testing.T) {
		refresh := jwtClientRefreshGrant(t, server.config.Storage, clientID)
		assertion, err := clientjwt.Sign(t.Context(), clientSigner, clientjwt.SignOptions{ClientID: clientID, Audience: tokenURL, Algorithm: jwt.ES256})
		if err != nil {
			t.Fatal(err)
		}
		resp, err := server.refreshToken(t.Context(), httptest.NewRequest(http.MethodPost, "/token", nil), &oauth2proto.TokenRequest{
			GrantType:           oauth2proto.GrantTypeRefreshToken,
			RefreshToken:        refresh,
			ClientID:            clientID,
			ClientAssertionType: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
			ClientAssertion:     assertion,
		})
		if err != nil {
			t.Fatal(err)
		}
		if resp.AccessToken == "" {
			t.Fatal("missing access token")
		}
	})

	t.Run("client id may be omitted", func(t *testing.T) {
		code := jwtClientCodeGrant(t, server.config.Storage)
		assertion, err := clientjwt.Sign(t.Context(), clientSigner, clientjwt.SignOptions{ClientID: clientID, Audience: tokenURL, Algorithm: jwt.ES256})
		if err != nil {
			t.Fatal(err)
		}
		resp, err := server.codeToken(t.Context(), httptest.NewRequest(http.MethodPost, "/token", nil), &oauth2proto.TokenRequest{
			GrantType:           oauth2proto.GrantTypeAuthorizationCode,
			Code:                code,
			RedirectURI:         "https://redirect",
			ClientAssertionType: clientjwt.AssertionType,
			ClientAssertion:     assertion,
		})
		if err != nil {
			t.Fatal(err)
		}
		if resp.AccessToken == "" {
			t.Fatal("missing access token")
		}
	})

	t.Run("assertion replay is rejected", func(t *testing.T) {
		assertion, err := clientjwt.Sign(t.Context(), clientSigner, clientjwt.SignOptions{
			ClientID:  clientID,
			Audience:  tokenURL,
			Algorithm: jwt.ES256,
			JWTID:     "replayed-assertion",
		})
		if err != nil {
			t.Fatal(err)
		}
		req := &oauth2proto.TokenRequest{
			ClientID:            clientID,
			ClientAssertionType: clientjwt.AssertionType,
			ClientAssertion:     assertion,
		}
		if err := server.validateTokenClient(t.Context(), req, clientID); err != nil {
			t.Fatal(err)
		}
		err = server.validateTokenClient(t.Context(), req, clientID)
		tokenErr, ok := err.(*oauth2proto.TokenError)
		if !ok || tokenErr.ErrorCode != oauth2proto.TokenErrorCodeInvalidClient {
			t.Fatalf("error: got %v", err)
		}
	})

	t.Run("assertion lifetime is bounded", func(t *testing.T) {
		assertion, err := clientjwt.Sign(t.Context(), clientSigner, clientjwt.SignOptions{
			ClientID:  clientID,
			Audience:  tokenURL,
			Algorithm: jwt.ES256,
			IssuedAt:  time.Now(),
			Expiry:    time.Now().Add(6 * time.Minute),
		})
		if err != nil {
			t.Fatal(err)
		}
		err = server.validateTokenClient(t.Context(), &oauth2proto.TokenRequest{
			ClientID:            clientID,
			ClientAssertionType: clientjwt.AssertionType,
			ClientAssertion:     assertion,
		}, clientID)
		tokenErr, ok := err.(*oauth2proto.TokenError)
		if !ok || tokenErr.ErrorCode != oauth2proto.TokenErrorCodeInvalidClient {
			t.Fatalf("error: got %v", err)
		}
	})

	t.Run("secret only rejected", func(t *testing.T) {
		code := jwtClientCodeGrant(t, server.config.Storage)
		_, err := server.codeToken(t.Context(), httptest.NewRequest(http.MethodPost, "/token", nil), &oauth2proto.TokenRequest{
			GrantType:    oauth2proto.GrantTypeAuthorizationCode,
			Code:         code,
			RedirectURI:  "https://redirect",
			ClientID:     clientID,
			ClientSecret: "not-a-secret",
		})
		tokenErr, ok := err.(*oauth2proto.TokenError)
		if !ok || tokenErr.ErrorCode != oauth2proto.TokenErrorCodeInvalidClient {
			t.Fatalf("error: got %v", err)
		}
	})

	t.Run("assertion with secret rejected", func(t *testing.T) {
		code := jwtClientCodeGrant(t, server.config.Storage)
		assertion, err := clientjwt.Sign(t.Context(), clientSigner, clientjwt.SignOptions{ClientID: clientID, Audience: tokenURL, Algorithm: jwt.ES256})
		if err != nil {
			t.Fatal(err)
		}
		_, err = server.codeToken(t.Context(), httptest.NewRequest(http.MethodPost, "/token", nil), &oauth2proto.TokenRequest{
			GrantType:           oauth2proto.GrantTypeAuthorizationCode,
			Code:                code,
			RedirectURI:         "https://redirect",
			ClientID:            clientID,
			ClientSecret:        "also-secret",
			ClientAssertionType: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
			ClientAssertion:     assertion,
		})
		tokenErr, ok := err.(*oauth2proto.TokenError)
		if !ok || tokenErr.ErrorCode != oauth2proto.TokenErrorCodeInvalidRequest {
			t.Fatalf("error: got %v", err)
		}
	})

	t.Run("secret client still works", func(t *testing.T) {
		code := newCodeGrant(t, server.config.Storage)
		resp, err := server.codeToken(t.Context(), httptest.NewRequest(http.MethodPost, "/token", nil), &oauth2proto.TokenRequest{
			GrantType:    oauth2proto.GrantTypeAuthorizationCode,
			Code:         code,
			RedirectURI:  "https://redirect",
			ClientID:     "client-id",
			ClientSecret: "client-secret",
		})
		if err != nil {
			t.Fatal(err)
		}
		if resp.AccessToken == "" {
			t.Fatal("missing access token")
		}
	})
}

func jwtClientCodeGrant(t *testing.T, store *Storage) string {
	t.Helper()
	grant := &storedGrant{
		UserID:        "testsub",
		ClientID:      "jwt-client",
		GrantedScopes: []string{oidc.ScopeOfflineAccess},
		GrantedAt:     time.Now(),
		ExpiresAt:     time.Now().Add(time.Minute),
		Request: &AuthRequest{
			ClientID:    "jwt-client",
			RedirectURI: "https://redirect",
			Scopes:      []string{oidc.ScopeOfflineAccess},
		},
	}
	grantID, err := store.createGrant(t.Context(), grant)
	if err != nil {
		t.Fatal(err)
	}
	authCodeID := uuid.NewV4().String()
	tok, err := token.New(tokenUsageAuthCode, authCodeID, grantID, grant.UserID)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.createAuthCode(t.Context(), authCodeID, &storedAuthCode{
		Code:             tok.Stored(),
		GrantID:          grantID,
		ValidUntil:       time.Now().Add(time.Minute),
		StorageExpiresAt: time.Now().Add(time.Minute),
	}); err != nil {
		t.Fatal(err)
	}
	return tok.UserToken()
}

func jwtClientRefreshGrant(t *testing.T, store *Storage, clientID string) string {
	t.Helper()
	grant := &storedGrant{
		UserID:        "testsub",
		ClientID:      clientID,
		GrantedScopes: []string{oidc.ScopeOfflineAccess},
		GrantedAt:     time.Now(),
		ExpiresAt:     time.Now().Add(time.Hour),
	}
	grantID, err := store.createGrant(t.Context(), grant)
	if err != nil {
		t.Fatal(err)
	}
	refreshID := uuid.NewV4().String()
	tok, err := token.New(tokenUsageRefresh, refreshID, grantID, grant.UserID)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.createRefreshToken(t.Context(), refreshID, &storedRefreshToken{
		Token:            tok.Stored(),
		GrantID:          grantID,
		ValidUntil:       time.Now().Add(time.Hour),
		StorageExpiresAt: time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
	return tok.UserToken()
}
