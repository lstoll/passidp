package oauth2as

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"lds.li/passidp/internal/oauth2as/internal/token"
	"lds.li/passidp/internal/oauth2as/oauth2proto"
)

func TestTokenCommitFailuresAreAtomic(t *testing.T) {
	store := newTestStorage(t)
	authCode := newCodeGrant(t, store)
	var failCommits atomic.Bool
	store.commitHook = func(storageCommit) error {
		if failCommits.Load() {
			return errors.New("injected commit failure")
		}
		return nil
	}
	failCommits.Store(true)
	signer, verifier := testSignerVerifier(t)
	server := &Server{
		config: Config{
			Issuer:               "https://issuer",
			Storage:              store,
			Signer:               signer,
			VerificationKeys:     verifier,
			AccessTokenValidity:  time.Hour,
			IDTokenValidity:      time.Hour,
			RefreshTokenValidity: time.Hour,
			Clients: staticClientSource{{
				ID:           "client-id",
				Secrets:      []string{"test-secret"},
				RedirectURIs: []string{"https://redirect"},
				SkipPKCE:     true,
			}},
			TokenHandler: func(context.Context, *TokenRequest) (*TokenResponse, error) {
				return &TokenResponse{}, nil
			},
		},
		now:    time.Now,
		logger: slog.New(slog.DiscardHandler),
	}
	_, err := server.codeToken(t.Context(), httptest.NewRequest(http.MethodPost, "/token", nil), &oauth2proto.TokenRequest{
		GrantType:    oauth2proto.GrantTypeAuthorizationCode,
		Code:         authCode,
		RedirectURI:  "https://redirect",
		ClientID:     "client-id",
		ClientSecret: "test-secret",
	})
	if err == nil {
		t.Fatal("code exchange unexpectedly succeeded")
	}

	parsed, err := token.ParseUserToken(authCode, tokenUsageAuthCode)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.getAuthCode(t.Context(), parsed.ID()); err != nil {
		t.Fatalf("authorization code was consumed by failed commit: %v", err)
	}
	if count := refreshTokenCount(t, store); count != 0 {
		t.Fatalf("failed commit created %d refresh token records", count)
	}
	sessions, err := store.listRefreshSessions(t.Context(), storageRefreshSessionQuery{UserID: "testsub", ActiveAt: time.Now().Add(-time.Minute), Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(sessions) != 0 {
		t.Fatalf("failed commit created %d session index records", len(sessions))
	}

	failCommits.Store(false)
	issued, err := server.codeToken(t.Context(), httptest.NewRequest(http.MethodPost, "/token", nil), &oauth2proto.TokenRequest{
		GrantType:    oauth2proto.GrantTypeAuthorizationCode,
		Code:         authCode,
		RedirectURI:  "https://redirect",
		ClientID:     "client-id",
		ClientSecret: "test-secret",
	})
	if err != nil {
		t.Fatal(err)
	}
	refreshRequest := &oauth2proto.TokenRequest{
		GrantType:    oauth2proto.GrantTypeRefreshToken,
		RefreshToken: issued.RefreshToken,
		ClientID:     "client-id",
		ClientSecret: "test-secret",
	}
	failCommits.Store(true)
	if _, err := server.refreshToken(t.Context(), httptest.NewRequest(http.MethodPost, "/token", nil), refreshRequest); err == nil {
		t.Fatal("refresh unexpectedly succeeded with a failed commit")
	}
	failCommits.Store(false)
	if _, err := server.refreshToken(t.Context(), httptest.NewRequest(http.MethodPost, "/token", nil), refreshRequest); err != nil {
		t.Fatalf("failed refresh commit consumed the presented token: %v", err)
	}
}
