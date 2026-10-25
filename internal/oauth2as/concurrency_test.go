package oauth2as

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"lds.li/passidp/internal/oauth2as/internal/token"
)

func TestRefreshTokenConcurrency(t *testing.T) {
	s := newTestStorage(t)
	signer, verifier := testSignerVerifier(t)
	const concurrency = 10
	ready := make(chan struct{})
	var arrived atomic.Int32

	srv := &Server{
		config: Config{
			Issuer:               "https://issuer",
			Storage:              s,
			Signer:               signer,
			VerificationKeys:     verifier,
			RefreshTokenValidity: time.Hour,
			TokenHandler: func(_ context.Context, req *TokenRequest) (*TokenResponse, error) {
				if arrived.Add(1) == concurrency {
					close(ready)
				}
				<-ready
				return &TokenResponse{}, nil
			},
			Clients: staticClientSource{
				{
					ID:           "test-client",
					Secrets:      []string{"test-secret"},
					RedirectURIs: []string{"https://redirect"},
				},
			},
		},
		now:    time.Now,
		logger: slog.New(slog.DiscardHandler),
	}

	userID := "test-user"
	grant := &storedGrant{
		UserID:        userID,
		ClientID:      "test-client",
		GrantedScopes: []string{"openid", "offline_access"},
		GrantedAt:     time.Now(),
		ExpiresAt:     time.Now().Add(1 * time.Hour),
	}
	gid, err := srv.config.Storage.createGrant(context.Background(), grant)
	if err != nil {
		t.Fatalf("failed to create grant: %v", err)
	}

	rtID := "rt-1"
	tok, err := token.New(tokenUsageRefresh, rtID, gid, userID)
	if err != nil {
		t.Fatalf("failed to generate refresh token: %v", err)
	}
	rt := &storedRefreshToken{
		GrantID:          gid,
		Token:            tok.Stored(),
		ValidUntil:       time.Now().Add(1 * time.Hour),
		StorageExpiresAt: time.Now().Add(1 * time.Hour),
	}
	if err := srv.config.Storage.createRefreshToken(context.Background(), rtID, rt); err != nil {
		t.Fatalf("failed to create refresh token: %v", err)
	}

	rtString := tok.UserToken()

	// Fire concurrent requests
	var wg sync.WaitGroup
	results := make(chan int, concurrency)

	for range concurrency {
		wg.Go(func() {
			v := url.Values{}
			v.Set("grant_type", "refresh_token")
			v.Set("refresh_token", rtString)
			v.Set("client_id", "test-client")
			v.Set("client_secret", "test-secret")

			req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(v.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

			w := httptest.NewRecorder()
			srv.TokenHandler(w, req)

			results <- w.Code
		})
	}

	wg.Wait()
	close(results)

	successCount := 0
	failureCount := 0

	for code := range results {
		if code == http.StatusOK {
			successCount++
		} else {
			failureCount++
		}
	}

	if successCount != 1 {
		t.Errorf("successful exchanges = %d, want exactly one", successCount)
	}
	if failureCount != concurrency-1 {
		t.Errorf("failed exchanges = %d, want %d", failureCount, concurrency-1)
	}

	// A failed compare-and-swap cannot fork the token family and does not revoke
	// the one successful exchange.
	postGrant, err := s.getGrant(t.Context(), gid)
	if err != nil || postGrant == nil {
		t.Errorf("grant was unexpectedly revoked: %v", err)
	}
	if count := refreshTokenCount(t, s); count != 1 {
		t.Fatalf("refresh token records = %d, want one active replacement", count)
	}
}
