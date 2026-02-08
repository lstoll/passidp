package storage

import (
	"bytes"
	"context"
	"crypto/rand"
	"io"
	"testing"
	"time"

	"github.com/google/uuid"
	"lds.li/oauth2ext/oauth2as"
)

func TestStateOAuth2Storage(t *testing.T) {
	state, err := NewState(t.TempDir() + "/state.bolt")
	if err != nil {
		t.Fatalf("failed to create state: %v", err)
	}
	defer state.db.Close()

	oauth2State := state.OAuth2State()
	ctx := context.Background()

	// 1. Test Creating a Grant
	grant := &oauth2as.StoredGrant{
		UserID:        "test_user",
		ClientID:      "test_client",
		GrantedScopes: []string{"openid", "profile"},
		Request: &oauth2as.AuthRequest{
			ClientID: "test_client",
			Scopes:   []string{"openid", "profile"},
		},
		ExpiresAt: time.Now().Add(time.Hour),
		GrantedAt: time.Now(),
	}

	grantID, err := oauth2State.CreateGrant(ctx, grant)
	if err != nil {
		t.Fatalf("failed to create grant: %v", err)
	}
	if grantID == "" {
		t.Fatal("expected grant ID to be returned")
	}
	// Verify grantID is a valid UUID string
	if _, err := uuid.Parse(grantID); err != nil {
		t.Fatalf("expected grant ID to be a valid UUID, got %q: %v", grantID, err)
	}

	// 2. Test Retrieving Grant
	retrieved, err := oauth2State.GetGrant(ctx, grantID)
	if err != nil {
		t.Fatalf("failed to get grant: %v", err)
	}
	if retrieved == nil {
		t.Fatal("expected grant to be found")
	}
	if retrieved.UserID != "test_user" {
		t.Errorf("expected UserID test_user, got %s", retrieved.UserID)
	}

	// 3. Test Auth Code
	authCodeBytes := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, authCodeBytes); err != nil {
		t.Fatalf("failed to generate auth code: %v", err)
	}
	codeID, err := uuid.NewV7()
	if err != nil {
		t.Fatalf("failed to generate code ID: %v", err)
	}
	authCode := &oauth2as.StoredAuthCode{
		Code:             authCodeBytes,
		GrantID:          grantID,
		ValidUntil:       time.Now().Add(10 * time.Minute),
		StorageExpiresAt: time.Now().Add(15 * time.Minute),
	}

	codeIDString := codeID.String()
	if err := oauth2State.CreateAuthCode(ctx, codeIDString, authCode); err != nil {
		t.Fatalf("failed to create auth code: %v", err)
	}

	// 4. Test GetAuthCodeAndGrant
	retrievedAC, retrievedGrant, err := oauth2State.GetAuthCodeAndGrant(ctx, codeIDString)
	if err != nil {
		t.Fatalf("failed to get auth code and grant: %v", err)
	}
	if retrievedAC == nil || retrievedGrant == nil {
		t.Fatal("expected auth code and grant to be found")
	}
	if !bytes.Equal(retrievedAC.Code, authCodeBytes) {
		t.Errorf("auth code mismatch")
	}
	if retrievedGrant.UserID != "test_user" {
		t.Errorf("grant mismatch")
	}

	// 5. Test Refresh Token
	refreshTokenBytes := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, refreshTokenBytes); err != nil {
		t.Fatalf("failed to generate refresh token: %v", err)
	}
	tokenID, err := uuid.NewV7()
	if err != nil {
		t.Fatalf("failed to generate token ID: %v", err)
	}
	refreshToken := &oauth2as.StoredRefreshToken{
		Token:            refreshTokenBytes,
		GrantID:          grantID,
		ValidUntil:       time.Now().Add(24 * time.Hour),
		StorageExpiresAt: time.Now().Add(48 * time.Hour),
	}

	tokenIDString := tokenID.String()
	if err := oauth2State.CreateRefreshToken(ctx, tokenIDString, refreshToken); err != nil {
		t.Fatalf("failed to create refresh token: %v", err)
	}

	// 6. Test GetRefreshTokenAndGrant
	retrievedRT, retrievedGrantRT, err := oauth2State.GetRefreshTokenAndGrant(ctx, tokenIDString)
	if err != nil {
		t.Fatalf("failed to get refresh token and grant: %v", err)
	}
	if retrievedRT == nil || retrievedGrantRT == nil {
		t.Fatal("expected refresh token and grant to be found")
	}
	if !bytes.Equal(retrievedRT.Token, refreshTokenBytes) {
		t.Errorf("refresh token mismatch")
	}
	if retrievedGrantRT.UserID != "test_user" {
		t.Errorf("grant mismatch")
	}

	// 7. Test Update Grant
	// First get the grant to get the current version
	grantToUpdate, err := oauth2State.GetGrant(ctx, grantID)
	if err != nil {
		t.Fatalf("failed to get grant for update: %v", err)
	}
	grantToUpdate.GrantedScopes = []string{"openid", "profile", "email"}
	if err := oauth2State.UpdateGrant(ctx, grantID, grantToUpdate); err != nil {
		t.Fatalf("failed to update grant: %v", err)
	}

	updated, err := oauth2State.GetGrant(ctx, grantID)
	if err != nil {
		t.Fatalf("failed to get updated grant: %v", err)
	}
	if len(updated.GrantedScopes) != 3 {
		t.Errorf("expected 3 scopes, got %d", len(updated.GrantedScopes))
	}
	if updated.Version != 2 {
		t.Errorf("expected version to be 2 after update, got %d", updated.Version)
	}

	// 8. Test Expire Auth Code
	if err := oauth2State.ExpireAuthCode(ctx, codeIDString); err != nil {
		t.Fatalf("failed to expire auth code: %v", err)
	}
	ac, g, err := oauth2State.GetAuthCodeAndGrant(ctx, codeIDString)
	if err != oauth2as.ErrNotFound {
		t.Fatalf("expected ErrNotFound when getting expired auth code, got: %v", err)
	}
	if ac != nil || g != nil {
		t.Error("expected expired auth code to be gone")
	}

	// 9. Test Expire Grant
	if err := oauth2State.ExpireGrant(ctx, grantID); err != nil {
		t.Fatalf("failed to expire grant: %v", err)
	}

	expiredGrant, err := oauth2State.GetGrant(ctx, grantID)
	if err != oauth2as.ErrNotFound {
		t.Fatalf("expected ErrNotFound when getting expired grant, got err=%v grant=%v", err, expiredGrant)
	}
	if expiredGrant != nil {
		t.Error("expected nil grant when expired")
	}

	// 10. List Active Grants
	// Since we just expired the grant, it should NOT appear in active grants
	activeGrants, err := oauth2State.ListActiveGrantsForUser(ctx, "test_user")
	if err != nil {
		t.Fatalf("failed to list active grants: %v", err)
	}
	if len(activeGrants) != 0 {
		t.Errorf("expected 0 active grants, got %d", len(activeGrants))
	}

	// Create a new active grant
	newGrant := &oauth2as.StoredGrant{
		UserID:    "test_user",
		ExpiresAt: time.Now().Add(time.Hour),
	}
	newGrantID, err := oauth2State.CreateGrant(ctx, newGrant)
	if err != nil {
		t.Fatalf("failed to create second grant: %v", err)
	}

	// Create refresh token for the new grant so it appears as active
	newTokenID, err := uuid.NewV7()
	if err != nil {
		t.Fatalf("failed to generate token ID: %v", err)
	}
	newRT := &oauth2as.StoredRefreshToken{
		Token:            []byte("new_refresh_token"),
		GrantID:          newGrantID,
		ValidUntil:       time.Now().Add(time.Hour),
		StorageExpiresAt: time.Now().Add(24 * time.Hour),
	}
	if err := oauth2State.CreateRefreshToken(ctx, newTokenID.String(), newRT); err != nil {
		t.Fatalf("failed to create refresh token for second grant: %v", err)
	}

	activeGrants, err = oauth2State.ListActiveGrantsForUser(ctx, "test_user")
	if err != nil {
		t.Fatalf("failed to list active grants: %v", err)
	}
	if len(activeGrants) != 1 {
		t.Errorf("expected 1 active grant, got %d", len(activeGrants))
	}
}

func TestOauth2ASStorage(t *testing.T) {
	oauth2as.TestStorage(t, func() oauth2as.Storage {
		storage, err := NewState(t.TempDir() + "/state.bolt")
		if err != nil {
			t.Fatalf("failed to create state: %v", err)
		}
		return storage.OAuth2State()
	})
}
