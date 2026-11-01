package oauth2as

import (
	"context"
	"errors"
	"log/slog"
	"net/http/httptest"
	"testing"
	"time"

	"lds.li/passidp/internal/oauth2as/oauth2proto"
)

func TestSQLiteRefreshPreparedBeforeSessionRevocationCannotCommit(t *testing.T) {
	store := newTestStorage(t)
	signer, verifier := testSignerVerifier(t)
	server := &Server{
		config: Config{
			Issuer:               "https://issuer.example",
			Storage:              store,
			Signer:               signer,
			VerificationKeys:     verifier,
			AccessTokenValidity:  time.Hour,
			IDTokenValidity:      time.Hour,
			RefreshTokenValidity: time.Hour,
			Clients: staticClientSource{{
				ID: "client-id", Secrets: []string{"test-secret"},
				RedirectURIs: []string{"https://redirect"}, SkipPKCE: true,
			}},
			TokenHandler: func(context.Context, *TokenRequest) (*TokenResponse, error) {
				return &TokenResponse{}, nil
			},
		},
		now:    time.Now,
		logger: slog.New(slog.DiscardHandler),
	}

	authCode := newCodeGrant(t, store)
	issued, err := server.codeToken(t.Context(), httptest.NewRequest("POST", "/token", nil), &oauth2proto.TokenRequest{
		GrantType: oauth2proto.GrantTypeAuthorizationCode,
		Code:      authCode, RedirectURI: "https://redirect",
		ClientID: "client-id", ClientSecret: "test-secret",
	})
	if err != nil {
		t.Fatalf("exchange authorization code: %v", err)
	}
	if issued.RefreshToken == "" {
		t.Fatal("authorization code exchange returned no refresh token")
	}
	page, err := server.ListRefreshSessions(t.Context(), RefreshSessionQuery{UserID: "testsub"})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Sessions) != 1 {
		t.Fatalf("initial session count = %d, want 1", len(page.Sessions))
	}
	grantID := page.Sessions[0].GrantID

	prepared := make(chan struct{})
	release := make(chan struct{})
	server.config.TokenHandler = func(ctx context.Context, request *TokenRequest) (*TokenResponse, error) {
		if request.IsRefresh {
			close(prepared)
			select {
			case <-release:
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		return &TokenResponse{}, nil
	}
	type refreshResult struct {
		response *oauth2proto.TokenResponse
		err      error
	}
	result := make(chan refreshResult, 1)
	go func() {
		response, err := server.refreshToken(t.Context(), httptest.NewRequest("POST", "/token", nil), &oauth2proto.TokenRequest{
			GrantType:    oauth2proto.GrantTypeRefreshToken,
			RefreshToken: issued.RefreshToken,
			ClientID:     "client-id", ClientSecret: "test-secret",
		})
		result <- refreshResult{response: response, err: err}
	}()

	select {
	case <-prepared:
	case <-time.After(5 * time.Second):
		t.Fatal("refresh response was not prepared")
	}
	if err := server.RevokeRefreshSession(t.Context(), "testsub", grantID); err != nil {
		t.Fatalf("revoke refresh session while response prepared: %v", err)
	}
	close(release)
	refreshed := <-result
	var tokenErr *oauth2proto.TokenError
	if refreshed.response != nil || !errors.As(refreshed.err, &tokenErr) || tokenErr.ErrorCode != oauth2proto.TokenErrorCodeInvalidGrant {
		t.Fatalf("stale refresh result = (%v, %v), want invalid_grant", refreshed.response, refreshed.err)
	}

	if _, err := store.getGrant(t.Context(), grantID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("revoked grant lookup error = %v, want ErrNotFound", err)
	}
	if count := refreshTokenCount(t, store); count != 0 {
		t.Fatalf("revoked session has %d refresh tokens, want 0", count)
	}
	page, err = server.ListRefreshSessions(t.Context(), RefreshSessionQuery{UserID: "testsub"})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Sessions) != 0 {
		t.Fatalf("revoked session was resurrected: %#v", page.Sessions)
	}
	if _, err := server.refreshToken(t.Context(), httptest.NewRequest("POST", "/token", nil), &oauth2proto.TokenRequest{
		GrantType:    oauth2proto.GrantTypeRefreshToken,
		RefreshToken: issued.RefreshToken,
		ClientID:     "client-id", ClientSecret: "test-secret",
	}); !errors.As(err, &tokenErr) || tokenErr.ErrorCode != oauth2proto.TokenErrorCodeInvalidGrant {
		t.Fatalf("refresh after revoke = %v, want invalid_grant", err)
	}
}
