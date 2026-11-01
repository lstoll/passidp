package oauth2as

import (
	"testing"
	"time"
)

func TestSQLiteStorageRoundTripsTypedGrant(t *testing.T) {
	db, store := newMigratedSQLStorage(t)
	base := time.Date(2026, time.October, 31, 12, 30, 45, 987654321, time.UTC)
	maxAgeZero := 0
	grant := storedGrant{
		ID:              "new-grant",
		UserID:          "user",
		ClientID:        "client",
		GrantedScopes:   []string{"openid", "profile"},
		RedirectURI:     "https://client.example/callback",
		CodeChallenge:   "challenge",
		Nonce:           "nonce",
		MaxAge:          &maxAgeZero,
		DPoPThumbprint:  "thumbprint",
		GrantedAt:       base,
		AuthenticatedAt: base.Add(time.Second),
		ExpiresAt:       base.Add(time.Hour),
		ACR:             "urn:example:mfa",
		AMR:             []string{"pwd", "otp"},
	}
	emptyOptional := storedGrant{
		ID:        "empty-grant",
		UserID:    "user",
		ClientID:  "client",
		GrantedAt: base,
		ExpiresAt: base.Add(time.Hour),
	}
	session := storedRefreshSession{
		GrantID:    grant.ID,
		UserID:     grant.UserID,
		ClientID:   grant.ClientID,
		CreatedAt:  grant.GrantedAt,
		ExpiresAt:  grant.ExpiresAt,
		LastUsedAt: base.Add(2 * time.Second),
	}
	if err := store.commit(t.Context(), storageCommit{
		Checks: []storageCheck{
			{Kind: storageKindGrant, ID: grant.ID},
			{Kind: storageKindGrant, ID: emptyOptional.ID},
			{Kind: storageKindSession, ID: grant.ID},
		},
		Grants:   []storedGrant{grant, emptyOptional},
		Sessions: []storedRefreshSession{session},
	}); err != nil {
		t.Fatalf("store typed records: %v", err)
	}

	got, err := store.getGrant(t.Context(), grant.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.RedirectURI != grant.RedirectURI || got.CodeChallenge != grant.CodeChallenge || got.Nonce != grant.Nonce || got.DPoPThumbprint != grant.DPoPThumbprint || got.MaxAge == nil || *got.MaxAge != 0 {
		t.Fatalf("typed grant fields did not round trip: %+v", got)
	}
	if !got.GrantedAt.Equal(base.UTC().Truncate(time.Microsecond)) || !got.AuthenticatedAt.Equal(base.Add(time.Second).UTC().Truncate(time.Microsecond)) || !got.ExpiresAt.Equal(base.Add(time.Hour).UTC().Truncate(time.Microsecond)) {
		t.Fatalf("grant timestamps did not round trip at microsecond precision: %+v", got)
	}
	var timestampType string
	var grantedAt int64
	if err := db.QueryRowContext(t.Context(), `SELECT typeof(granted_at), granted_at FROM oauth2as_grants WHERE id = ?`, grant.ID).Scan(&timestampType, &grantedAt); err != nil {
		t.Fatal(err)
	}
	if timestampType != "integer" || grantedAt != base.UnixMicro() {
		t.Fatalf("granted_at storage = (%s, %d), want (integer, %d)", timestampType, grantedAt, base.UnixMicro())
	}
	emptyGot, err := store.getGrant(t.Context(), emptyOptional.ID)
	if err != nil {
		t.Fatal(err)
	}
	if emptyGot.MaxAge != nil || emptyGot.Nonce != "" || emptyGot.CodeChallenge != "" || emptyGot.RedirectURI != "" || emptyGot.DPoPThumbprint != "" {
		t.Fatalf("empty optional fields did not round trip: %+v", emptyGot)
	}

	sessions, err := store.listRefreshSessions(t.Context(), storageRefreshSessionQuery{UserID: grant.UserID, ActiveAt: base, Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(sessions) != 1 || sessions[0].GrantID != grant.ID || !sessions[0].DPoPBound || !sessions[0].LastUsedAt.Equal(session.LastUsedAt.UTC().Truncate(time.Microsecond)) {
		t.Fatalf("typed session did not round trip: %+v", sessions)
	}
}
