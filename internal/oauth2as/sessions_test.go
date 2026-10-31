package oauth2as

import (
	"context"
	"log/slog"
	"maps"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
	"time"

	"lds.li/passidp/internal/oauth2as/oauth2proto"
)

func TestListRefreshSessions(t *testing.T) {
	now := time.Date(2026, 8, 14, 12, 0, 0, 0, time.UTC)
	store := newTestStorage(t)
	server := &Server{config: Config{Storage: store}, now: func() time.Time { return now }}

	putGrantAndSession := func(session storedRefreshSession) {
		t.Helper()
		if err := store.commit(t.Context(), storageCommit{
			Checks: []storageCheck{
				{Kind: storageKindGrant, ID: session.GrantID},
				{Kind: storageKindSession, ID: session.GrantID},
			},
			Grants: []storedGrant{{
				ID:            session.GrantID,
				UserID:        session.UserID,
				ClientID:      session.ClientID,
				GrantedScopes: session.GrantedScopes,
				GrantedAt:     session.CreatedAt,
				ExpiresAt:     session.ExpiresAt,
			}},
			Sessions: []storedRefreshSession{session},
		}); err != nil {
			t.Fatal(err)
		}
	}
	// These differ below SQL storage's microsecond precision. Pagination must
	// still use the grant ID tie-breaker and never repeat either session.
	putGrantAndSession(storedRefreshSession{GrantID: "g1", UserID: "user", ClientID: "client-a", GrantedScopes: []string{"offline_access"}, ExpiresAt: now.Add(time.Hour), LastUsedAt: now.Add(100 * time.Nanosecond)})
	putGrantAndSession(storedRefreshSession{GrantID: "g2", UserID: "user", ClientID: "client-b", GrantedScopes: []string{"openid", "offline_access"}, ExpiresAt: now.Add(2 * time.Hour), LastUsedAt: now.Add(200 * time.Nanosecond)})
	putGrantAndSession(storedRefreshSession{GrantID: "expired", UserID: "user", ClientID: "client-c", ExpiresAt: now})
	putGrantAndSession(storedRefreshSession{GrantID: "other", UserID: "other", ClientID: "client-a", ExpiresAt: now.Add(time.Hour)})
	first, err := server.ListRefreshSessions(t.Context(), RefreshSessionQuery{UserID: "user", Limit: 1})
	if err != nil {
		t.Fatal(err)
	}
	if len(first.Sessions) != 1 || first.NextCursor == "" {
		t.Fatalf("unexpected first page: %#v", first)
	}
	first.Sessions[0].GrantedScopes[0] = "changed"
	second, err := server.ListRefreshSessions(t.Context(), RefreshSessionQuery{UserID: "user", Limit: 1, Cursor: first.NextCursor})
	if err != nil {
		t.Fatal(err)
	}
	if len(second.Sessions) != 1 {
		t.Fatalf("unexpected second page: %#v", second)
	}
	if first.Sessions[0].GrantID == second.Sessions[0].GrantID {
		t.Fatal("pagination returned the same session twice")
	}
	if second.NextCursor != "" {
		last, err := server.ListRefreshSessions(t.Context(), RefreshSessionQuery{UserID: "user", Limit: 1, Cursor: second.NextCursor})
		if err != nil {
			t.Fatal(err)
		}
		if len(last.Sessions) != 0 || last.NextCursor != "" {
			t.Fatalf("unexpected final filtered page: %#v", last)
		}
	}

	filtered, err := server.ListRefreshSessions(t.Context(), RefreshSessionQuery{UserID: "user", ClientID: "client-b"})
	if err != nil {
		t.Fatal(err)
	}
	if len(filtered.Sessions) != 1 || filtered.Sessions[0].GrantID != "g2" || !slices.Equal(filtered.Sessions[0].GrantedScopes, []string{"openid", "offline_access"}) {
		t.Fatalf("unexpected client-filtered sessions: %#v", filtered)
	}
	if _, err := server.ListRefreshSessions(t.Context(), RefreshSessionQuery{UserID: "user", ClientID: "client-b", Cursor: first.NextCursor}); err == nil {
		t.Fatal("cursor from a different query was accepted")
	}
}

func TestCodeExchangeCreatesRefreshSession(t *testing.T) {
	store := newTestStorage(t)
	signer, verifier := testSignerVerifier(t)
	currentTime := time.Now()
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
		now:    func() time.Time { return currentTime },
		logger: slog.New(slog.DiscardHandler),
	}
	authCode := newCodeGrant(t, store)
	response, err := server.codeToken(t.Context(), httptest.NewRequest(http.MethodPost, "/token", nil), &oauth2proto.TokenRequest{
		GrantType:    oauth2proto.GrantTypeAuthorizationCode,
		Code:         authCode,
		RedirectURI:  "https://redirect",
		ClientID:     "client-id",
		ClientSecret: "test-secret",
	})
	if err != nil {
		t.Fatal(err)
	}
	if response.RefreshToken == "" {
		t.Fatal("code exchange did not issue a refresh token")
	}
	page, err := server.ListRefreshSessions(t.Context(), RefreshSessionQuery{UserID: "testsub"})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Sessions) != 1 || page.Sessions[0].ClientID != "client-id" {
		t.Fatalf("unexpected refresh sessions: %#v", page)
	}
	grantID := page.Sessions[0].GrantID
	currentTime = currentTime.Add(time.Second)
	rotated, err := server.refreshToken(t.Context(), httptest.NewRequest(http.MethodPost, "/token", nil), &oauth2proto.TokenRequest{
		GrantType:    oauth2proto.GrantTypeRefreshToken,
		RefreshToken: response.RefreshToken,
		ClientID:     "client-id",
		ClientSecret: "test-secret",
	})
	if err != nil {
		t.Fatal(err)
	}
	if rotated.RefreshToken == "" || rotated.RefreshToken == response.RefreshToken {
		t.Fatal("refresh exchange did not rotate the refresh token")
	}
	page, err = server.ListRefreshSessions(t.Context(), RefreshSessionQuery{UserID: "testsub"})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Sessions) != 1 || page.Sessions[0].GrantID != grantID || !page.Sessions[0].LastUsedAt.Equal(currentTime) {
		t.Fatalf("rotation did not atomically update the session index: %#v", page)
	}
	if err := server.RevokeRefreshSession(t.Context(), "another-user", page.Sessions[0].GrantID); err != ErrNotFound {
		t.Fatalf("cross-user revoke error = %v, want ErrNotFound", err)
	}
	if err := server.RevokeRefreshSession(t.Context(), "testsub", page.Sessions[0].GrantID); err != nil {
		t.Fatal(err)
	}
	page, err = server.ListRefreshSessions(t.Context(), RefreshSessionQuery{UserID: "testsub"})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Sessions) != 0 {
		t.Fatalf("revoked session still listed: %#v", page)
	}
}

func TestListRefreshSessionsDPoPBound(t *testing.T) {
	now := time.Date(2026, 8, 14, 12, 0, 0, 0, time.UTC)
	store := newTestStorage(t)
	server := &Server{config: Config{Storage: store}, now: func() time.Time { return now }}

	for id, thumbprint := range map[string]string{
		"bound":   "abc",
		"empty":   "",
		"unbound": "",
		"none":    "",
	} {
		if err := store.commit(t.Context(), storageCommit{
			Checks: []storageCheck{
				{Kind: storageKindGrant, ID: id},
				{Kind: storageKindSession, ID: id},
			},
			Grants: []storedGrant{{
				ID:             id,
				UserID:         "user",
				ClientID:       "client",
				GrantedAt:      now,
				ExpiresAt:      now.Add(time.Hour),
				DPoPThumbprint: thumbprint,
			}},
			Sessions: []storedRefreshSession{{GrantID: id, UserID: "user", ClientID: "client", ExpiresAt: now.Add(time.Hour), LastUsedAt: now}},
		}); err != nil {
			t.Fatalf("commit %s: %v", id, err)
		}
	}

	page, err := server.ListRefreshSessions(t.Context(), RefreshSessionQuery{UserID: "user"})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, s := range page.Sessions {
		got[s.GrantID] = s.DPoPBound
	}
	want := map[string]bool{"bound": true, "empty": false, "unbound": false, "none": false}
	if !maps.Equal(got, want) {
		t.Fatalf("DPoPBound = %v, want %v", got, want)
	}
}
