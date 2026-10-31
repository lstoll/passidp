package oauth2as

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"maps"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"lds.li/oauth2ext/jwt"
	"lds.li/oauth2ext/oidc"
	"lds.li/passidp/internal/oauth2as/internal/token"
	"lds.li/passidp/internal/oauth2as/oauth2proto"
)

type unauthorizedErrImpl struct{ error }

func (u *unauthorizedErrImpl) Unauthorized() bool { return true }

func TestCodeToken(t *testing.T) {
	const (
		issuer = "https://issuer"

		clientID     = "client-id"
		clientSecret = "client-secret"
		redirectURI  = "https://redirect"

		otherClientID       = "other-client"
		otherClientSecret   = "other-secret"
		otherClientRedirect = "https://other"

		rs256ClientID       = "rs256-client"
		rs256ClientSecret   = "rs256-secret"
		rs256ClientRedirect = "https://rs256"
	)

	newOIDC := func() *Server {
		s := newTestStorage(t)

		signer, verifier := testSignerVerifier(t)

		return &Server{
			config: Config{
				Issuer: issuer,

				Storage:          s,
				Signer:           signer,
				VerificationKeys: verifier,

				TokenHandler: func(_ context.Context, req *TokenRequest) (*TokenResponse, error) {
					return &TokenResponse{}, nil
				},

				Clients: staticClientSource{
					{
						ID:           clientID,
						Secrets:      []string{clientSecret},
						RedirectURIs: []string{redirectURI},
						SkipPKCE:     true,
					},
					{
						ID:           otherClientID,
						Secrets:      []string{otherClientSecret},
						RedirectURIs: []string{otherClientRedirect},
						SkipPKCE:     true,
					},
					{
						ID:           rs256ClientID,
						Secrets:      []string{rs256ClientSecret},
						RedirectURIs: []string{rs256ClientRedirect},
						SkipPKCE:     true, IDTokenSigningAlgorithm: jwt.RS256,
					},
				},
			},

			now: time.Now,
		}
	}

	t.Run("Happy path", func(t *testing.T) {
		o := newOIDC()
		codeToken := newCodeGrant(t, o.config.Storage)

		treq := &oauth2proto.TokenRequest{
			GrantType:    oauth2proto.GrantTypeAuthorizationCode,
			Code:         codeToken,
			RedirectURI:  redirectURI,
			ClientID:     clientID,
			ClientSecret: clientSecret,
		}

		tresp, err := o.codeToken(context.TODO(), httptest.NewRequest(http.MethodPost, "/token", nil), treq)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if tresp.AccessToken == "" {
			t.Error("token request should have returned an access token, but got none")
		}
		if _, ok := tresp.ExtraParams["id_token"]; ok {
			t.Error("token response included an ID token without the openid scope")
		}
		if !slices.Equal(tresp.Scopes, []string{oidc.ScopeOfflineAccess}) {
			t.Errorf("token response scopes: got %v", tresp.Scopes)
		}
	})

	t.Run("Redeeming an already redeemed code should fail", func(t *testing.T) {
		o := newOIDC()
		codeToken := newCodeGrant(t, o.config.Storage)

		treq := &oauth2proto.TokenRequest{
			GrantType:    oauth2proto.GrantTypeAuthorizationCode,
			Code:         codeToken,
			RedirectURI:  redirectURI,
			ClientID:     clientID,
			ClientSecret: clientSecret,
		}

		_, err := o.codeToken(context.Background(), httptest.NewRequest(http.MethodPost, "/token", nil), treq)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// replay fails
		_, err = o.codeToken(context.Background(), httptest.NewRequest(http.MethodPost, "/token", nil), treq)
		if err, ok := err.(*oauth2proto.TokenError); !ok || err.ErrorCode != oauth2proto.TokenErrorCodeInvalidGrant {
			t.Errorf("want invalid token grant error, got: %v", err)
		}
	})

	t.Run("Expired authorization code should fail", func(t *testing.T) {
		o := newOIDC()
		codeToken := newCodeGrant(t, o.config.Storage)
		codeID, err := token.Digest(codeToken, token.AuthorizationCode)
		if err != nil {
			t.Fatal(err)
		}
		code, err := o.config.Storage.getAuthCode(t.Context(), codeID)
		if err != nil {
			t.Fatal(err)
		}
		code.ValidUntil = time.Now().Add(-time.Second)
		if err := o.config.Storage.commit(t.Context(), storageCommit{
			Checks:    []storageCheck{{Kind: storageKindAuthCode, ID: code.ID, Version: code.storageVersion}},
			AuthCodes: []storedAuthCode{*code},
		}); err != nil {
			t.Fatal(err)
		}

		_, err = o.codeToken(t.Context(), httptest.NewRequest(http.MethodPost, "/token", nil), &oauth2proto.TokenRequest{
			GrantType:    oauth2proto.GrantTypeAuthorizationCode,
			Code:         codeToken,
			RedirectURI:  redirectURI,
			ClientID:     clientID,
			ClientSecret: clientSecret,
		})
		if tokenErr, ok := err.(*oauth2proto.TokenError); !ok || tokenErr.ErrorCode != oauth2proto.TokenErrorCodeInvalidGrant {
			t.Fatalf("expired code error = %v, want invalid_grant", err)
		}
	})

	t.Run("Invalid client secret should fail", func(t *testing.T) {
		o := newOIDC()
		codeToken := newCodeGrant(t, o.config.Storage)

		treq := &oauth2proto.TokenRequest{
			GrantType:    oauth2proto.GrantTypeAuthorizationCode,
			Code:         codeToken,
			RedirectURI:  redirectURI,
			ClientID:     clientID,
			ClientSecret: "invalid-secret",
		}

		_, err := o.codeToken(context.Background(), httptest.NewRequest(http.MethodPost, "/token", nil), treq)
		if err, ok := err.(*oauth2proto.TokenError); !ok || err.ErrorCode != oauth2proto.TokenErrorCodeInvalidClient {
			t.Errorf("want invalid client error, got: %v", err)
		}
	})

	t.Run("Client secret that differs from the original client should fail", func(t *testing.T) {
		o := newOIDC()
		codeToken := newCodeGrant(t, o.config.Storage)

		treq := &oauth2proto.TokenRequest{
			GrantType:   oauth2proto.GrantTypeAuthorizationCode,
			Code:        codeToken,
			RedirectURI: redirectURI,
			// This is not the credentials the code should be tracking, but are
			// otherwise valid
			ClientID:     otherClientID,
			ClientSecret: otherClientSecret,
		}

		_, err := o.codeToken(context.Background(), httptest.NewRequest(http.MethodPost, "/token", nil), treq)
		if err, ok := err.(*oauth2proto.TokenError); !ok || err.ErrorCode != oauth2proto.TokenErrorCodeInvalidClient {
			t.Errorf("want invalid client error, got: %v", err)
		}
	})

	t.Run("Response access token validity time honoured", func(t *testing.T) {
		o := newOIDC()
		codeToken := newCodeGrant(t, o.config.Storage)

		treq := &oauth2proto.TokenRequest{
			GrantType:    oauth2proto.GrantTypeAuthorizationCode,
			Code:         codeToken,
			RedirectURI:  redirectURI,
			ClientID:     clientID,
			ClientSecret: clientSecret,
		}

		o.config.TokenHandler = func(_ context.Context, req *TokenRequest) (*TokenResponse, error) {
			return &TokenResponse{
				IDTokenExpiry:     time.Now().Add(5 * time.Minute),
				AccessTokenExpiry: time.Now().Add(5 * time.Minute),
			}, nil
		}

		tresp, err := o.codeToken(context.Background(), httptest.NewRequest(http.MethodPost, "/token", nil), treq)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if tresp.AccessToken == "" {
			t.Error("token request should have returned an access token, but got none")
		}

		// compare whole seconds, we calculate this based on a expiresAt - now
		// delta so the function run time is factored in.
		if tresp.ExpiresIn > 5*time.Minute+2*time.Second || tresp.ExpiresIn < 5*time.Minute-2*time.Second {
			t.Errorf("want token exp within 2s of %f, got: %f", 5*time.Minute.Seconds(), tresp.ExpiresIn.Seconds())
		}
	})

	t.Run("Should issue different tokens for different algorithms", func(t *testing.T) {
		o := newOIDC()

		// Create a storedGrant with the auth code
		grant := &storedGrant{
			UserID:        "testsub",
			ClientID:      rs256ClientID,
			GrantedScopes: []string{oidc.ScopeOpenID, oidc.ScopeOfflineAccess},
			GrantedAt:     time.Now(),
			ExpiresAt:     time.Now().Add(1 * time.Minute),
			RedirectURI:   rs256ClientRedirect,
		}

		grantID, err := o.config.Storage.createGrant(context.Background(), grant)
		if err != nil {
			t.Fatal(err)
		}

		authCodeStr, authCodeID := token.New(token.AuthorizationCode)

		// Create token entry for the auth code
		err = o.config.Storage.createAuthCode(context.Background(), authCodeID, &storedAuthCode{
			GrantID:          grantID,
			ValidUntil:       time.Now().Add(1 * time.Minute),
			StorageExpiresAt: time.Now().Add(1 * time.Minute),
		})
		if err != nil {
			t.Fatal(err)
		}
		treq := &oauth2proto.TokenRequest{
			GrantType:    oauth2proto.GrantTypeAuthorizationCode,
			Code:         authCodeStr,
			RedirectURI:  rs256ClientRedirect,
			ClientID:     rs256ClientID,
			ClientSecret: rs256ClientSecret,
		}

		tresp, err := o.codeToken(context.TODO(), httptest.NewRequest(http.MethodPost, "/token", nil), treq)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		idt, ok := tresp.ExtraParams["id_token"].(string)
		if !ok {
			t.Fatalf("id_token not found in extra params")
		}

		parts := strings.Split(idt, ".")
		if len(parts) != 3 {
			t.Fatalf("id_token should have 3 parts, got: %v", parts)
		}

		header, err := base64.RawURLEncoding.DecodeString(parts[0])
		if err != nil {
			t.Fatalf("failed to decode id_token header: %v", err)
		}

		var headerMap map[string]any
		if err := json.Unmarshal(header, &headerMap); err != nil {
			t.Fatalf("failed to unmarshal id_token header: %v", err)
		}

		alg, ok := headerMap["alg"].(string)
		if !ok {
			t.Fatalf("alg not found in id_token header")
		}

		if alg != "RS256" {
			t.Fatalf("want ID token alg to be RS256, got: %s", alg)
		}

		parts = strings.Split(tresp.AccessToken, ".")
		if len(parts) != 3 {
			t.Fatalf("access token should have 3 parts, got: %v", parts)
		}
		header, err = base64.RawURLEncoding.DecodeString(parts[0])
		if err != nil {
			t.Fatalf("failed to decode access token header: %v", err)
		}
		if err := json.Unmarshal(header, &headerMap); err != nil {
			t.Fatalf("failed to unmarshal access token header: %v", err)
		}
		if alg, _ := headerMap["alg"].(string); alg != "ES256" {
			t.Fatalf("want access token alg to remain ES256, got: %q", alg)
		}
	})

}

func TestRefreshToken(t *testing.T) {
	const (
		issuer = "https://issuer"

		clientID     = "client-id"
		clientSecret = "client-secret"
		redirectURI  = "https://redirect"

		otherClientID       = "other-client"
		otherClientSecret   = "other-secret"
		otherClientRedirect = "https://other"
	)

	newOIDC := func() *Server {
		s := newTestStorage(t)

		signer, verifier := testSignerVerifier(t)

		return &Server{

			config: Config{
				Issuer: issuer,

				Storage:          s,
				Signer:           signer,
				VerificationKeys: verifier,

				TokenHandler: func(_ context.Context, req *TokenRequest) (*TokenResponse, error) {
					return &TokenResponse{}, nil
				},
				Clients: staticClientSource{
					{
						ID:           clientID,
						Secrets:      []string{clientSecret},
						RedirectURIs: []string{redirectURI},
						SkipPKCE:     true,
					},
					{
						ID:           otherClientID,
						Secrets:      []string{otherClientSecret},
						RedirectURIs: []string{otherClientRedirect},
						SkipPKCE:     true,
					},
				},

				CodeValidityTime:     1 * time.Minute,
				RefreshTokenValidity: 6 * time.Hour,
				GrantValidity:        6 * time.Hour,
			},

			now: time.Now,
		}
	}

	t.Run("Refresh token happy path", func(t *testing.T) {
		o := newOIDC()
		refreshToken := newRefreshGrant(t, o.config.Storage)

		o.config.TokenHandler = func(_ context.Context, req *TokenRequest) (*TokenResponse, error) {
			return &TokenResponse{}, nil
		}

		// keep trying to refresh
		for i := 1; i <= 5; i++ {
			treq := &oauth2proto.TokenRequest{
				GrantType:    oauth2proto.GrantTypeRefreshToken,
				RefreshToken: refreshToken,
				ClientID:     clientID,
				ClientSecret: clientSecret,
			}

			tresp, err := o.refreshToken(context.Background(), httptest.NewRequest(http.MethodPost, "/token", nil), treq)
			if err != nil {
				t.Fatalf("iter %d: unexpected error calling token with refresh token: %v", i, err)
			}

			if tresp.AccessToken == "" {
				t.Errorf("iter %d: refresh request should have returned an access token, but got none", i)
			}

			if tresp.RefreshToken == "" {
				t.Errorf("iter %d: refresh request should have returned a refresh token, but got none", i)
			}

			refreshToken = tresp.RefreshToken
		}

		// try again while we still should be within the expiry period.
		o.now = func() time.Time { return time.Now().Add(5 * time.Hour) }

		treq := &oauth2proto.TokenRequest{
			GrantType:    oauth2proto.GrantTypeRefreshToken,
			RefreshToken: refreshToken,
			ClientID:     clientID,
			ClientSecret: clientSecret,
		}

		tresp, err := o.refreshToken(context.Background(), httptest.NewRequest(http.MethodPost, "/token", nil), treq)
		if err != nil {
			t.Fatalf("failed to refresh token while still in validity period: %v", err)
		}
		refreshToken = tresp.RefreshToken
		if refreshToken == "" {
			t.Fatal("refresh request should have returned a refresh token, but got none")
		}

		// march to the future, when we should be expired
		o.now = func() time.Time { return time.Now().Add(7 * time.Hour) }

		treq = &oauth2proto.TokenRequest{
			GrantType:    oauth2proto.GrantTypeRefreshToken,
			RefreshToken: refreshToken,
			ClientID:     clientID,
			ClientSecret: clientSecret,
		}

		_, err = o.refreshToken(context.Background(), httptest.NewRequest(http.MethodPost, "/token", nil), treq)
		if te, ok := err.(*oauth2proto.TokenError); !ok || te.ErrorCode != oauth2proto.TokenErrorCodeInvalidGrant {
			t.Errorf("expired session should have given invalid_grant, got: %v", te)
		}
	})

	t.Run("Invalid client secret should fail", func(t *testing.T) {
		o := newOIDC()
		refreshToken := newRefreshGrant(t, o.config.Storage)

		treq := &oauth2proto.TokenRequest{
			GrantType:    oauth2proto.GrantTypeRefreshToken,
			RefreshToken: refreshToken,
			ClientID:     clientID,
			ClientSecret: "invalid-secret",
		}

		_, err := o.refreshToken(context.Background(), httptest.NewRequest(http.MethodPost, "/token", nil), treq)
		if err, ok := err.(*oauth2proto.TokenError); !ok || err.ErrorCode != oauth2proto.TokenErrorCodeInvalidClient {
			t.Errorf("want invalid_client error, got: %v", err)
		}
	})

	t.Run("Refresh token with handler errors", func(t *testing.T) {
		o := newOIDC()
		refreshToken := newRefreshGrant(t, o.config.Storage)

		var returnErr error
		const errDesc = "Refresh unauthorized"

		o.config.TokenHandler = func(_ context.Context, req *TokenRequest) (*TokenResponse, error) {
			if returnErr != nil {
				return nil, returnErr
			}
			return &TokenResponse{
				// OverrideRefreshTokenExpiry: o.now().Add(10 * time.Minute),
			}, nil
		}

		// try and refresh, and observe intentional unauth error
		returnErr = &unauthorizedErrImpl{error: errors.New(errDesc)}

		treq := &oauth2proto.TokenRequest{
			GrantType:    oauth2proto.GrantTypeRefreshToken,
			RefreshToken: refreshToken,
			ClientID:     clientID,
			ClientSecret: clientSecret,
		}

		_, err := o.refreshToken(context.Background(), httptest.NewRequest(http.MethodPost, "/token", nil), treq)

		if err == nil {
			t.Fatal("want error refreshing, got none")
		}
		terr, ok := err.(*oauth2proto.TokenError)
		if !ok {
			t.Fatalf("want token error, got: %T", err)
		}
		if terr.ErrorCode != oauth2proto.TokenErrorCodeInvalidGrant || terr.Description != errDesc {
			t.Fatalf("unexpected code %q (want %q) or description %q (want %q)", terr.ErrorCode, oauth2proto.TokenErrorCodeInvalidGrant, terr.Description, errDesc)
		}

		// refresh with generic err
		refreshToken = newRefreshGrant(t, o.config.Storage)

		returnErr = errors.New("boomtown")

		treq = &oauth2proto.TokenRequest{
			GrantType:    oauth2proto.GrantTypeRefreshToken,
			RefreshToken: refreshToken,
			ClientID:     clientID,
			ClientSecret: clientSecret,
		}

		_, err = o.refreshToken(context.Background(), httptest.NewRequest(http.MethodPost, "/token", nil), treq)

		if err == nil {
			t.Fatal("want error refreshing, got none")
		}
		if _, ok = err.(*oauth2proto.HTTPError); !ok {
			t.Fatalf("want http error, got %T (%v)", err, err)
		}
	})

}

func TestUserinfo(t *testing.T) {
	echoHandler := func(w io.Writer, uireq *UserinfoRequest) error {
		o := map[string]any{
			"gotsub": uireq.Subject,
		}

		if err := json.NewEncoder(w).Encode(o); err != nil {
			t.Fatal(err)
		}

		return nil
	}

	signAccessToken := func(tokenIssuer string, expiresAt time.Time, additional map[string]any) string {
		signer, _ := testSignerVerifier(t)
		claims := map[string]any{
			"iss": tokenIssuer,
			"sub": "sub",
			"iat": time.Now().Unix(),
			"exp": expiresAt.Unix(),
		}
		maps.Copy(claims, additional)
		compact, err := signer.Sign(t.Context(), claims, jwt.SignOptions{Type: "at+jwt", Algorithm: jwt.ES256})
		if err != nil {
			t.Fatal(err)
		}

		return compact
	}

	issuer := "http://iss"

	for _, tc := range []struct {
		Name string
		// Setup should return both a session to be persisted, and an access
		// token
		Setup   func(t *testing.T, storage *Storage) (accessToken string)
		Handler func(w io.Writer, uireq *UserinfoRequest) error
		// WantErr signifies that we expect an error
		WantErr bool
		// WantJSON is what we want the endpoint to return
		WantJSON map[string]any
	}{
		{
			Name: "Simple output, valid session",
			Setup: func(t *testing.T, storage *Storage) (accessToken string) {
				grantID, err := storage.createGrant(t.Context(), &storedGrant{
					UserID: "sub", ClientID: "client-id", GrantedScopes: []string{oidc.ScopeOpenID},
					GrantedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour),
				})
				if err != nil {
					t.Fatal(err)
				}
				return signAccessToken(issuer, time.Now().Add(time.Minute), map[string]any{claimGrantID: grantID, "client_id": "client-id"})
			},
			Handler: echoHandler,
			WantJSON: map[string]any{
				"gotsub": "sub",
			},
		},
		{
			Name: "Token for other issuer",
			Setup: func(t *testing.T, _ *Storage) (accessToken string) {
				return signAccessToken("http://other", time.Now().Add(time.Minute), nil)
			},
			Handler: echoHandler,
			WantErr: true,
		},
		{
			Name: "Expired access token",
			Setup: func(t *testing.T, _ *Storage) (accessToken string) {
				return signAccessToken(issuer, time.Now().Add(-time.Minute), nil)
			},
			Handler: echoHandler,
			WantErr: true,
		},
		{
			Name: "No access token",
			Setup: func(t *testing.T, _ *Storage) (accessToken string) {
				return ""
			},
			Handler: echoHandler,
			WantErr: true,
		},
	} {
		t.Run(tc.Name, func(t *testing.T) {
			s := newTestStorage(t)

			signer, verifier := testSignerVerifier(t)

			config := Config{
				Issuer:           issuer,
				Storage:          s,
				Signer:           signer,
				VerificationKeys: verifier,
				UserinfoHandler: func(_ context.Context, uireq *UserinfoRequest) (*UserinfoResponse, error) {
					return &UserinfoResponse{
						Identity: map[string]any{
							"iss": issuer,
							"sub": uireq.Subject,
							"exp": time.Now().Add(1 * time.Minute).Unix(),
						},
					}, nil
				},
				TokenHandler: func(_ context.Context, req *TokenRequest) (*TokenResponse, error) {
					return &TokenResponse{}, nil
				},
				Clients: staticClientSource{},
				Logger:  slog.New(slog.NewTextHandler(os.Stderr, nil)),
			}

			oidc, err := NewServer(config)
			if err != nil {
				t.Fatal(err)
			}

			at := tc.Setup(t, s)

			rec := httptest.NewRecorder()
			req := httptest.NewRequest("GET", "/userinfo", nil)

			if at != "" {
				req.Header.Set("authorization", "Bearer "+at)
			}

			oidc.UserinfoHandler(rec, req)
			if tc.WantErr && rec.Result().StatusCode == http.StatusOK {
				t.Error("want error, but got none")
			}
			if !tc.WantErr && rec.Result().StatusCode != http.StatusOK {
				t.Errorf("want no error, got status: %d", rec.Result().StatusCode)
			}
		})
	}
}

func TestUserinfoGrantContext(t *testing.T) {
	const issuer = "http://iss"

	s := newTestStorage(t)
	grant := &storedGrant{
		UserID:        "sub",
		ClientID:      "client-id",
		GrantedScopes: []string{"openid", "profile"},
		GrantedAt:     time.Now(),
		ExpiresAt:     time.Now().Add(time.Hour),
		ACR:           "urn:mace:incommon:iap:silver",
		AMR:           []string{"pwd"},
	}
	grantID, err := s.createGrant(context.Background(), grant)
	if err != nil {
		t.Fatal(err)
	}

	signer, verifier := testSignerVerifier(t)
	accessToken := signTestAccessToken(t, signer, issuer, grantID, "client-id")

	var gotReq *UserinfoRequest
	oidc, err := NewServer(Config{
		Issuer:           issuer,
		Storage:          s,
		Signer:           signer,
		VerificationKeys: verifier,
		UserinfoHandler: func(_ context.Context, uireq *UserinfoRequest) (*UserinfoResponse, error) {
			gotReq = uireq
			return &UserinfoResponse{Identity: map[string]any{"sub": uireq.Subject}}, nil
		},
		TokenHandler: func(_ context.Context, req *TokenRequest) (*TokenResponse, error) {
			return &TokenResponse{}, nil
		},
		Clients: staticClientSource{},
	})
	if err != nil {
		t.Fatal(err)
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/userinfo", nil)
	req.Header.Set("authorization", "Bearer "+accessToken)
	oidc.UserinfoHandler(rec, req)

	if rec.Result().StatusCode != http.StatusOK {
		t.Fatalf("want status 200, got %d", rec.Result().StatusCode)
	}
	if gotReq == nil {
		t.Fatal("userinfo handler was not called")
	}
	if gotReq.GrantID != grantID {
		t.Errorf("GrantID: want %q, got %q", grantID, gotReq.GrantID)
	}
	if !slices.Equal(gotReq.GrantedScopes, []string{"openid", "profile"}) {
		t.Errorf("GrantedScopes: got %v", gotReq.GrantedScopes)
	}
	if gotReq.ACR != "urn:mace:incommon:iap:silver" {
		t.Errorf("ACR: got %q", gotReq.ACR)
	}
	if !slices.Equal(gotReq.AMR, []string{"pwd"}) {
		t.Errorf("AMR: got %v", gotReq.AMR)
	}

	gotReq.GrantedScopes[0] = "changed"
	gotReq.AMR[0] = "changed"
	stored, err := s.getGrant(t.Context(), grantID)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(stored.GrantedScopes, []string{"openid", "profile"}) || !slices.Equal(stored.AMR, []string{"pwd"}) {
		t.Fatalf("userinfo handler mutated stored grant: %#v", stored)
	}
}

func TestUserinfoRequiresOpenIDScope(t *testing.T) {
	const issuer = "http://iss"
	storage := newTestStorage(t)
	grantID, err := storage.createGrant(t.Context(), &storedGrant{
		UserID:        "sub",
		ClientID:      "client-id",
		GrantedScopes: []string{"profile"},
		GrantedAt:     time.Now(),
		ExpiresAt:     time.Now().Add(time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	signer, verifier := testSignerVerifier(t)
	server, err := NewServer(Config{
		Issuer: issuer, Storage: storage, Signer: signer, VerificationKeys: verifier,
		UserinfoHandler: func(context.Context, *UserinfoRequest) (*UserinfoResponse, error) {
			t.Fatal("userinfo handler called without openid scope")
			return nil, nil
		},
		TokenHandler: func(context.Context, *TokenRequest) (*TokenResponse, error) { return &TokenResponse{}, nil },
		Clients:      staticClientSource{},
	})
	if err != nil {
		t.Fatal(err)
	}
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/userinfo", nil)
	request.Header.Set("authorization", "Bearer "+signTestAccessToken(t, signer, issuer, grantID, "client-id"))
	server.UserinfoHandler(recorder, request)
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("status: got %d, want %d", recorder.Code, http.StatusForbidden)
	}
}

func TestUserinfoFailsClosedOnGrantContext(t *testing.T) {
	const issuer = "http://iss"
	storage := newTestStorage(t)
	grantID, err := storage.createGrant(t.Context(), &storedGrant{
		UserID: "sub", ClientID: "client-id", GrantedScopes: []string{oidc.ScopeOpenID},
		GrantedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	signer, verifier := testSignerVerifier(t)
	server, err := NewServer(Config{
		Issuer: issuer, Storage: storage, Signer: signer, VerificationKeys: verifier,
		UserinfoHandler: func(context.Context, *UserinfoRequest) (*UserinfoResponse, error) {
			t.Fatal("userinfo handler called with invalid grant context")
			return nil, nil
		},
		TokenHandler: func(context.Context, *TokenRequest) (*TokenResponse, error) { return &TokenResponse{}, nil },
		Clients:      staticClientSource{},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name, grantID, clientID string
	}{
		{name: "missing grant claim", clientID: "client-id"},
		{name: "unknown grant", grantID: "unknown", clientID: "client-id"},
		{name: "wrong client", grantID: grantID, clientID: "other-client"},
	} {
		t.Run(test.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			request := httptest.NewRequest(http.MethodGet, "/userinfo", nil)
			request.Header.Set("authorization", "Bearer "+signTestAccessToken(t, signer, issuer, test.grantID, test.clientID))
			server.UserinfoHandler(recorder, request)
			if recorder.Code != http.StatusUnauthorized {
				t.Fatalf("status: got %d, want %d", recorder.Code, http.StatusUnauthorized)
			}
		})
	}
}

func signTestAccessToken(t *testing.T, signer jwt.Signer, issuer, grantID, clientID string) string {
	t.Helper()
	claims := map[string]any{
		"iss": issuer, "sub": "sub", "client_id": clientID,
		"iat": time.Now().Unix(), "exp": time.Now().Add(time.Minute).Unix(),
	}
	if grantID != "" {
		claims[claimGrantID] = grantID
	}
	input := signingInput{Type: "at+jwt", Claims: claims}
	compact, err := signer.Sign(t.Context(), input.Claims, jwt.SignOptions{Type: input.Type, Algorithm: jwt.ES256})
	if err != nil {
		t.Fatal(err)
	}
	return compact
}

func TestValidateTokenClientAllowsPublicClientWithoutSecret(t *testing.T) {
	server := &Server{config: Config{Clients: staticClientSource{{ID: "public", Public: true}}}}
	_, err := server.validateTokenClient(t.Context(), &oauth2proto.TokenRequest{ClientID: "public"}, "public")
	if err != nil {
		t.Fatal(err)
	}
}

var (
	signer     jwt.Signer
	verifier   *jwt.VerificationKeySet
	signerOnce sync.Once
)

func testSignerVerifier(t *testing.T) (jwt.Signer, *jwt.VerificationKeySet) {
	signerOnce.Do(func() {
		ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		ecIdentity, e := jwt.NewSigningIdentity(ecKey, jwt.ES256, "")
		if e != nil {
			t.Fatal(e)
		}
		rsaIdentity, e := jwt.NewSigningIdentity(rsaKey, jwt.RS256, "")
		if e != nil {
			t.Fatal(e)
		}
		signer, err = jwt.NewSigningKeySet(ecIdentity, rsaIdentity)
		if err != nil {
			t.Fatal(err)
		}
		verifier, err = jwt.NewVerificationKeySetFromSigner(signer)
		if err != nil {
			t.Fatal(err)
		}
	})
	return signer, verifier
}

func newRefreshGrant(t *testing.T, smgr *Storage) (refreshToken string) {
	// Create a storedGrant with the refresh token
	grant := &storedGrant{
		UserID:        "testsub",
		ClientID:      "client-id",
		GrantedScopes: []string{oidc.ScopeOfflineAccess},
		GrantedAt:     time.Now(),
		ExpiresAt:     time.Now().Add(6 * time.Hour),
	}

	grantID, err := smgr.createGrant(context.Background(), grant)
	if err != nil {
		t.Fatal(err)
	}

	refreshToken, refreshTokenID := token.New(token.RefreshToken)

	// Create token entry for the refresh token
	err = smgr.createRefreshToken(context.Background(), refreshTokenID, &storedRefreshToken{
		GrantID:          grantID,
		ValidUntil:       time.Now().Add(6 * time.Hour),
		StorageExpiresAt: time.Now().Add(6 * time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}

	return refreshToken
}

func newCodeGrant(t *testing.T, smgr *Storage) (authCode string) {
	// Create a storedGrant with the auth code
	grant := &storedGrant{
		UserID:        "testsub",
		ClientID:      "client-id",
		GrantedScopes: []string{oidc.ScopeOfflineAccess},
		GrantedAt:     time.Now(),
		ExpiresAt:     time.Now().Add(1 * time.Minute),
		RedirectURI:   "https://redirect",
	}

	grantID, err := smgr.createGrant(context.Background(), grant)
	if err != nil {
		t.Fatal(err)
	}

	authCode, authCodeID := token.New(token.AuthorizationCode)

	// Create token entry for the auth code
	err = smgr.createAuthCode(context.Background(), authCodeID, &storedAuthCode{
		GrantID:          grantID,
		ValidUntil:       time.Now().Add(1 * time.Minute),
		StorageExpiresAt: time.Now().Add(1 * time.Minute),
	})
	if err != nil {
		t.Fatal(err)
	}

	return authCode
}

// staticClientSource is a test ClientSource over a fixed list of clients.
type staticClientSource []Client

func (c staticClientSource) Client(ctx context.Context, clientID string) (*Client, error) {
	for _, sc := range c {
		if sc.ID == clientID {
			return &sc, nil
		}
	}
	return nil, nil
}
