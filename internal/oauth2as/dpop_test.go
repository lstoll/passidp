package oauth2as

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
	"uuid"

	"lds.li/oauth2ext/dpop"
	"lds.li/oauth2ext/jwt"
	"lds.li/oauth2ext/oidc"
	"lds.li/passidp/internal/oauth2as/internal/token"
	"lds.li/passidp/internal/oauth2as/oauth2proto"
)

func TestDPoPTokenFlow(t *testing.T) {
	const (
		issuer       = "https://issuer"
		clientID     = "client-id"
		clientSecret = "client-secret"
		redirectURI  = "https://redirect"
		userID       = "test-user"
	)

	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	dpopSigner, err := jwt.NewSigningIdentity(privKey, "", "")
	if err != nil {
		t.Fatalf("failed to create signer: %v", err)
	}

	s := NewMemoryStorage()
	signer, verifier := testSignerVerifier(t)

	var capturedTokenRequest *TokenRequest

	server := &Server{
		config: Config{
			Issuer:           issuer,
			Storage:          s,
			Signer:           signer,
			VerificationKeys: verifier,
			DPoPVerifier:     &dpop.Verifier{},
			TokenHandler: func(_ context.Context, req *TokenRequest) (*TokenResponse, error) {
				capturedTokenRequest = req
				return &TokenResponse{}, nil
			},
			Clients: staticClientSource{
				{
					ID:           clientID,
					Secrets:      []string{clientSecret},
					RedirectURLs: []string{redirectURI},
					Opts:         []ClientOpt{ClientOptSkipPKCE()},
				},
			},
		},
		now: time.Now,
	}

	t.Run("Initial token exchange with DPoP", func(t *testing.T) {
		codeToken := newCodeGrant(t, server.config.Storage)

		dpopProof, err := dpop.Sign(t.Context(), dpopSigner, dpop.ProofOptions{
			HTTPMethod: http.MethodPost,
			HTTPURI:    issuer + "/token",
		})
		if err != nil {
			t.Fatalf("failed to create DPoP proof: %v", err)
		}

		req := httptest.NewRequest(http.MethodPost, "/token", nil)
		req.Host = "localhost"
		req.Header.Set("DPoP", dpopProof)

		treq := &oauth2proto.TokenRequest{
			GrantType:    oauth2proto.GrantTypeAuthorizationCode,
			Code:         codeToken,
			RedirectURI:  redirectURI,
			ClientID:     clientID,
			ClientSecret: clientSecret,
		}

		_, err = server.codeToken(context.Background(), req, treq)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// Verify DPoP info was passed to token handler
		if !capturedTokenRequest.DPoPBound {
			t.Error("expected DPoPBound to be true")
		}

		// Verify grant was updated with thumbprint
		grant, err := server.config.Storage.getGrant(context.Background(), capturedTokenRequest.GrantID)
		if err != nil {
			t.Fatalf("failed to get grant: %v", err)
		}

		var addState storedAdditionalState
		if len(grant.AdditionalState) > 0 {
			if err := json.Unmarshal(grant.AdditionalState, &addState); err != nil {
				t.Fatalf("failed to unmarshal additional state: %v", err)
			}
		}

		dpopThumbprintFromMetadata := ""
		if addState.DPoPThumbprint != nil {
			dpopThumbprintFromMetadata = *addState.DPoPThumbprint
		}

		t.Logf("Grant DPoP thumbprint from metadata: %s", dpopThumbprintFromMetadata)
		if dpopThumbprintFromMetadata == "" {
			t.Error("expected grant to have DPoP thumbprint in metadata")
		}

		// A new authorization code avoids the one-time-code check and exercises
		// the token endpoint's DPoP replay classification.
		replayed := *treq
		replayed.Code = newCodeGrant(t, server.config.Storage)
		_, err = server.codeToken(context.Background(), req, &replayed)
		var tokenErr *oauth2proto.TokenError
		if !errors.As(err, &tokenErr) || tokenErr.ErrorCode != oauth2proto.TokenErrorCodeInvalidDPoPProof {
			t.Fatalf("replayed proof error = %v, want invalid_dpop_proof", err)
		}
	})

	t.Run("Refresh with DPoP enforcement", func(t *testing.T) {
		// Create a DPoP-bound grant with refresh token
		dpopThumbprint := "test-thumbprint-123"

		addState := storedAdditionalState{
			DPoPThumbprint: &dpopThumbprint,
		}
		addStateBytes, _ := json.Marshal(addState)

		grant := &storedGrant{
			UserID:          userID,
			ClientID:        clientID,
			GrantedScopes:   []string{oidc.ScopeOpenID, oidc.ScopeOfflineAccess},
			GrantedAt:       time.Now(),
			ExpiresAt:       time.Now().Add(24 * time.Hour),
			AdditionalState: addStateBytes,
		}

		grantID, err := server.config.Storage.createGrant(context.Background(), grant)
		if err != nil {
			t.Fatalf("failed to create grant: %v", err)
		}

		refreshTokenID := uuid.NewV4().String()
		refreshToken, err := token.New(tokenUsageRefresh, refreshTokenID, grantID, userID)
		if err != nil {
			t.Fatalf("failed to generate refresh token: %v", err)
		}

		// Create token entry for the refresh token
		err = server.config.Storage.createRefreshToken(context.Background(), refreshTokenID, &storedRefreshToken{
			Token:            refreshToken.Stored(),
			GrantID:          grantID,
			ValidUntil:       time.Now().Add(24 * time.Hour),
			StorageExpiresAt: time.Now().Add(24 * time.Hour),
		})
		if err != nil {
			t.Fatalf("failed to create refresh token: %v", err)
		}
		refreshTokenStr := refreshToken.UserToken()

		dpopProof, err := dpop.Sign(t.Context(), dpopSigner, dpop.ProofOptions{
			HTTPMethod: http.MethodPost,
			HTTPURI:    issuer + "/token",
		})
		if err != nil {
			t.Fatalf("failed to create DPoP proof: %v", err)
		}

		// Derive the key thumbprint directly. Verifying this proof here would
		// consume it before the request under test.
		expectedThumbprint := dpopSigner.Thumbprint()

		// Update grant with correct thumbprint in metadata
		addState.DPoPThumbprint = &expectedThumbprint
		addStateBytes, _ = json.Marshal(addState)
		grant.AdditionalState = addStateBytes

		if err := server.config.Storage.updateGrant(context.Background(), grantID, grant); err != nil {
			t.Fatalf("failed to update grant: %v", err)
		}

		t.Run("Refresh succeeds with valid DPoP proof", func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/token", nil)
			req.Host = "localhost"
			req.Header.Set("DPoP", dpopProof)

			treq := &oauth2proto.TokenRequest{
				GrantType:    oauth2proto.GrantTypeRefreshToken,
				RefreshToken: refreshTokenStr,
				ClientID:     clientID,
				ClientSecret: clientSecret,
			}

			capturedTokenRequest = nil
			_, err = server.refreshToken(context.Background(), req, treq)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			// Verify DPoP info was passed to token handler
			if !capturedTokenRequest.DPoPBound {
				t.Error("expected DPoPBound to be true")
			}
		})

		t.Run("Refresh fails without DPoP proof", func(t *testing.T) {
			// Recreate grant since previous test consumed it
			addState := storedAdditionalState{
				DPoPThumbprint: &expectedThumbprint,
			}
			addStateBytes, _ := json.Marshal(addState)

			grant2 := &storedGrant{
				UserID:          userID,
				ClientID:        clientID,
				GrantedScopes:   []string{oidc.ScopeOpenID, oidc.ScopeOfflineAccess},
				GrantedAt:       time.Now(),
				ExpiresAt:       time.Now().Add(24 * time.Hour),
				AdditionalState: addStateBytes,
			}
			grantID2, err := server.config.Storage.createGrant(context.Background(), grant2)
			if err != nil {
				t.Fatalf("failed to create grant: %v", err)
			}

			refreshTokenID2 := uuid.NewV4().String()
			refreshToken2, err := token.New(tokenUsageRefresh, refreshTokenID2, grantID2, userID)
			if err != nil {
				t.Fatalf("failed to generate refresh token: %v", err)
			}

			// Create token entry for the refresh token
			err = server.config.Storage.createRefreshToken(context.Background(), refreshTokenID2, &storedRefreshToken{
				Token:            refreshToken2.Stored(),
				GrantID:          grantID2,
				ValidUntil:       time.Now().Add(24 * time.Hour),
				StorageExpiresAt: time.Now().Add(24 * time.Hour),
			})
			if err != nil {
				t.Fatalf("failed to create refresh token: %v", err)
			}
			refreshTokenStr2 := refreshToken2.UserToken()

			// Request without DPoP header
			req := httptest.NewRequest(http.MethodPost, "/token", nil)

			treq := &oauth2proto.TokenRequest{
				GrantType:    oauth2proto.GrantTypeRefreshToken,
				RefreshToken: refreshTokenStr2,
				ClientID:     clientID,
				ClientSecret: clientSecret,
			}

			_, err = server.refreshToken(context.Background(), req, treq)
			if err == nil {
				t.Fatal("expected error when DPoP proof is missing")
			}

			tokenErr, ok := err.(*oauth2proto.TokenError)
			if !ok {
				t.Fatalf("expected TokenError, got %T", err)
			}
			if tokenErr.ErrorCode != oauth2proto.TokenErrorCodeInvalidGrant {
				t.Errorf("expected invalid_grant error, got %s", tokenErr.ErrorCode)
			}
		})

		t.Run("Refresh fails with wrong DPoP key", func(t *testing.T) {
			wrongKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				t.Fatalf("failed to generate key: %v", err)
			}
			wrongSigner, err := jwt.NewSigningIdentity(wrongKey, "", "")
			if err != nil {
				t.Fatalf("failed to create signer: %v", err)
			}

			addState := storedAdditionalState{
				DPoPThumbprint: &expectedThumbprint,
			}
			addStateBytes, _ := json.Marshal(addState)

			grant3 := &storedGrant{
				UserID:          userID,
				ClientID:        clientID,
				GrantedScopes:   []string{oidc.ScopeOpenID, oidc.ScopeOfflineAccess},
				GrantedAt:       time.Now(),
				ExpiresAt:       time.Now().Add(24 * time.Hour),
				AdditionalState: addStateBytes,
			}
			grantID3, err := server.config.Storage.createGrant(context.Background(), grant3)
			if err != nil {
				t.Fatalf("failed to create grant: %v", err)
			}

			refreshTokenID3 := uuid.NewV4().String()
			refreshToken3, err := token.New(tokenUsageRefresh, refreshTokenID3, grantID3, userID)
			if err != nil {
				t.Fatalf("failed to generate refresh token: %v", err)
			}

			// Create token entry for the refresh token
			err = server.config.Storage.createRefreshToken(context.Background(), refreshTokenID3, &storedRefreshToken{
				Token:            refreshToken3.Stored(),
				GrantID:          grantID3,
				ValidUntil:       time.Now().Add(24 * time.Hour),
				StorageExpiresAt: time.Now().Add(24 * time.Hour),
			})
			if err != nil {
				t.Fatalf("failed to create refresh token: %v", err)
			}
			refreshTokenStr3 := refreshToken3.UserToken()

			// Create DPoP proof with wrong key
			wrongProof, err := dpop.Sign(t.Context(), wrongSigner, dpop.ProofOptions{
				HTTPMethod: http.MethodPost,
				HTTPURI:    issuer + "/token",
			})
			if err != nil {
				t.Fatalf("failed to create DPoP proof: %v", err)
			}

			req := httptest.NewRequest(http.MethodPost, "/token", nil)
			req.Host = "localhost"
			req.Header.Set("DPoP", wrongProof)

			treq := &oauth2proto.TokenRequest{
				GrantType:    oauth2proto.GrantTypeRefreshToken,
				RefreshToken: refreshTokenStr3,
				ClientID:     clientID,
				ClientSecret: clientSecret,
			}

			_, err = server.refreshToken(context.Background(), req, treq)
			if err == nil {
				t.Fatal("expected error when DPoP key doesn't match")
			}

			tokenErr, ok := err.(*oauth2proto.TokenError)
			if !ok {
				t.Fatalf("expected TokenError, got %T", err)
			}
			if tokenErr.ErrorCode != oauth2proto.TokenErrorCodeInvalidGrant {
				t.Errorf("expected invalid_grant error, got %s", tokenErr.ErrorCode)
			}
		})
	})
}

func TestInvalidAuthorizationCodeDoesNotConsumeDPoPProof(t *testing.T) {
	const issuer = "https://issuer"
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	proofSigner, err := jwt.NewSigningIdentity(key, "", "")
	if err != nil {
		t.Fatal(err)
	}
	proof, err := dpop.Sign(t.Context(), proofSigner, dpop.ProofOptions{HTTPMethod: http.MethodPost, HTTPURI: issuer + "/token"})
	if err != nil {
		t.Fatal(err)
	}
	dpopVerifier := &dpop.Verifier{ReplayCacheMaxEntries: 1}
	server := &Server{config: Config{Issuer: issuer, Storage: NewMemoryStorage(), DPoPVerifier: dpopVerifier}}
	req := httptest.NewRequest(http.MethodPost, "/token", nil)
	req.Header.Set("DPoP", proof)
	if _, err := server.codeToken(t.Context(), req, &oauth2proto.TokenRequest{Code: "not-an-auth-code"}); err == nil {
		t.Fatal("invalid authorization code accepted")
	}
	validator, err := dpop.NewValidator(&dpop.ValidatorOpts{
		IgnoreThumbprint: true, ExpectedHTM: new(http.MethodPost), ExpectedHTU: new(issuer + "/token"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := dpopVerifier.VerifyAndDecode(proof, validator); err != nil {
		t.Fatalf("invalid-code request consumed DPoP proof: %v", err)
	}
}

func TestVerifyDPoPProofPreservesEscapedRequestPath(t *testing.T) {
	const issuer = "https://issuer.example"
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	proofSigner, err := jwt.NewSigningIdentity(key, "", "")
	if err != nil {
		t.Fatal(err)
	}
	proof, err := dpop.Sign(t.Context(), proofSigner, dpop.ProofOptions{
		HTTPMethod: http.MethodPost,
		HTTPURI:    issuer + "/token%2Fsubresource",
	})
	if err != nil {
		t.Fatal(err)
	}

	server := &Server{config: Config{DPoPVerifier: &dpop.Verifier{}}}
	req := httptest.NewRequest(http.MethodPost, "https://internal/token%2Fsubresource", nil)
	req.Header.Set("DPoP", proof)
	if _, err := server.verifyDPoPProof(issuer, req, nil, ""); err != nil {
		t.Fatalf("verification failed: %v", err)
	}
}

func TestUserinfoDPoPSenderConstraint(t *testing.T) {
	const issuer = "https://issuer.example"
	storage := NewMemoryStorage()
	grantID, err := storage.createGrant(t.Context(), &storedGrant{
		UserID: "sub", ClientID: "client", GrantedScopes: []string{oidc.ScopeOpenID},
		GrantedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	issuerSigner, verifier := testSignerVerifier(t)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	proofSigner, err := jwt.NewSigningIdentity(key, "", "")
	if err != nil {
		t.Fatal(err)
	}
	thumbprint := proofSigner.Thumbprint()
	accessToken := signDPoPAccessToken(t, issuerSigner, issuer, grantID, "client", thumbprint)
	server, err := NewServer(Config{
		Issuer: issuer, Storage: storage, Signer: issuerSigner, VerificationKeys: verifier, DPoPVerifier: &dpop.Verifier{}, Clients: staticClientSource{},
		TokenHandler: func(context.Context, *TokenRequest) (*TokenResponse, error) { return &TokenResponse{}, nil },
		UserinfoHandler: func(context.Context, *UserinfoRequest) (*UserinfoResponse, error) {
			return &UserinfoResponse{Identity: map[string]string{"sub": "sub"}}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	request := func(scheme string, proof string) *httptest.ResponseRecorder {
		t.Helper()
		recorder := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/userinfo", nil)
		req.Header.Set("Authorization", scheme+" "+accessToken)
		if proof != "" {
			req.Header.Set("DPoP", proof)
		}
		server.UserinfoHandler(recorder, req)
		return recorder
	}
	if recorder := request("Bearer", ""); recorder.Code != http.StatusUnauthorized {
		t.Fatalf("bound token with Bearer: got %d, want %d", recorder.Code, http.StatusUnauthorized)
	}
	proof, err := dpop.Sign(t.Context(), proofSigner, dpop.ProofOptions{HTTPMethod: http.MethodGet, HTTPURI: issuer + "/userinfo", AccessToken: accessToken})
	if err != nil {
		t.Fatal(err)
	}
	if recorder := request("DPoP", proof); recorder.Code != http.StatusOK {
		t.Fatalf("valid DPoP: got %d, want %d: %s", recorder.Code, http.StatusOK, recorder.Body.String())
	}
	if recorder := request("DPoP", proof); recorder.Code != http.StatusUnauthorized {
		t.Fatalf("replayed DPoP proof: got %d, want %d", recorder.Code, http.StatusUnauthorized)
	}
	missingATH, err := dpop.Sign(t.Context(), proofSigner, dpop.ProofOptions{HTTPMethod: http.MethodGet, HTTPURI: issuer + "/userinfo"})
	if err != nil {
		t.Fatal(err)
	}
	if recorder := request("DPoP", missingATH); recorder.Code != http.StatusUnauthorized {
		t.Fatalf("missing ath: got %d, want %d", recorder.Code, http.StatusUnauthorized)
	}
	wrongATH, err := dpop.Sign(t.Context(), proofSigner, dpop.ProofOptions{HTTPMethod: http.MethodGet, HTTPURI: issuer + "/userinfo", AccessToken: "different-access-token"})
	if err != nil {
		t.Fatal(err)
	}
	if recorder := request("DPoP", wrongATH); recorder.Code != http.StatusUnauthorized {
		t.Fatalf("wrong ath: got %d, want %d", recorder.Code, http.StatusUnauthorized)
	}
	wrongKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	wrongSigner, err := jwt.NewSigningIdentity(wrongKey, "", "")
	if err != nil {
		t.Fatal(err)
	}
	wrongProof, err := dpop.Sign(t.Context(), wrongSigner, dpop.ProofOptions{HTTPMethod: http.MethodGet, HTTPURI: issuer + "/userinfo", AccessToken: accessToken})
	if err != nil {
		t.Fatal(err)
	}
	if recorder := request("DPoP", wrongProof); recorder.Code != http.StatusUnauthorized {
		t.Fatalf("wrong DPoP key: got %d, want %d", recorder.Code, http.StatusUnauthorized)
	}
	server.config.DPoPVerifier = nil
	if recorder := request("DPoP", proof); recorder.Code != http.StatusUnauthorized {
		t.Fatalf("bound token without configured verifier: got %d, want %d", recorder.Code, http.StatusUnauthorized)
	}
}

func signDPoPAccessToken(t *testing.T, signer jwt.Signer, issuer, grantID, clientID, thumbprint string) string {
	t.Helper()
	input := signingInput{Type: "at+jwt", Claims: map[string]any{
		"iss": issuer, "sub": "sub", "client_id": clientID, claimGrantID: grantID,
		"iat": time.Now().Unix(), "exp": time.Now().Add(time.Minute).Unix(), "cnf": map[string]any{"jkt": thumbprint},
	}}
	compact, err := signer.Sign(t.Context(), input.Claims, jwt.SignOptions{Type: input.Type, Algorithm: jwt.ES256})
	if err != nil {
		t.Fatal(err)
	}
	return compact
}
