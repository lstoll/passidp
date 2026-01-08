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

	// Test creating a grant
	grantID := uuid.New()
	authCode := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, authCode); err != nil {
		t.Fatalf("failed to generate auth code: %v", err)
	}
	refreshToken := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, refreshToken); err != nil {
		t.Fatalf("failed to generate refresh token: %v", err)
	}
	expiresAt := time.Now().Add(time.Hour)

	grant := &oauth2as.StoredGrant{
		ID:            grantID,
		UserID:        "test_user",
		ClientID:      "test_client",
		GrantedScopes: []string{"openid", "profile"},
		AuthCode:      authCode,
		RefreshToken:  refreshToken,
		Request: &oauth2as.AuthRequest{
			ClientID: "test_client",
			Scopes:   []string{"openid", "profile"},
		},
		ExpiresAt: expiresAt,
		GrantedAt: time.Now(),
	}

	if err := oauth2State.CreateGrant(context.Background(), grant); err != nil {
		t.Fatalf("failed to create grant: %v", err)
	}

	// Test retrieving by ID
	retrieved, err := oauth2State.GetGrant(context.Background(), grantID)
	if err != nil {
		t.Fatalf("failed to get grant: %v", err)
	}
	if retrieved == nil {
		t.Fatal("expected grant to be found")
	}
	if retrieved.ID != grantID {
		t.Errorf("expected ID %s, got %s", grantID, retrieved.ID)
	}
	if !bytes.Equal(retrieved.AuthCode, authCode) {
		t.Errorf("expected auth code %x, got %x", authCode, retrieved.AuthCode)
	}
	if !bytes.Equal(retrieved.RefreshToken, refreshToken) {
		t.Errorf("expected refresh token %x, got %x", refreshToken, retrieved.RefreshToken)
	}
	if retrieved.UserID != "test_user" {
		t.Errorf("expected UserID test_user, got %s", retrieved.UserID)
	}
	if retrieved.ClientID != "test_client" {
		t.Errorf("expected ClientID test_client, got %s", retrieved.ClientID)
	}

	// Test retrieving by auth code
	retrievedByAuthCode, err := oauth2State.GetGrantByAuthCode(context.Background(), authCode)
	if err != nil {
		t.Fatalf("failed to get grant by auth code: %v", err)
	}
	if retrievedByAuthCode == nil {
		t.Fatal("expected grant to be found by auth code")
	}
	if retrievedByAuthCode.ID != grantID {
		t.Errorf("expected ID %s, got %s", grantID, retrievedByAuthCode.ID)
	}

	// Test retrieving by refresh token
	retrievedByRefreshToken, err := oauth2State.GetGrantByRefreshToken(context.Background(), refreshToken)
	if err != nil {
		t.Fatalf("failed to get grant by refresh token: %v", err)
	}
	if retrievedByRefreshToken == nil {
		t.Fatal("expected grant to be found by refresh token")
	}
	if retrievedByRefreshToken.ID != grantID {
		t.Errorf("expected ID %s, got %s", grantID, retrievedByRefreshToken.ID)
	}

	// Test updating a grant
	newRefreshToken := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, newRefreshToken); err != nil {
		t.Fatalf("failed to generate new refresh token: %v", err)
	}
	grant.RefreshToken = newRefreshToken
	grant.GrantedScopes = []string{"openid", "profile", "email"}

	if err := oauth2State.UpdateGrant(context.Background(), grant); err != nil {
		t.Fatalf("failed to update grant: %v", err)
	}

	// Verify update
	updated, err := oauth2State.GetGrant(context.Background(), grantID)
	if err != nil {
		t.Fatalf("failed to get updated grant: %v", err)
	}
	if updated == nil {
		t.Fatal("expected updated grant to be found")
	}
	if !bytes.Equal(updated.RefreshToken, newRefreshToken) {
		t.Errorf("expected new refresh token %x, got %x", newRefreshToken, updated.RefreshToken)
	}
	if len(updated.GrantedScopes) != 3 {
		t.Errorf("expected 3 scopes, got %d", len(updated.GrantedScopes))
	}

	// Verify old refresh token no longer works
	oldTokenGrant, err := oauth2State.GetGrantByRefreshToken(context.Background(), refreshToken)
	if err != nil {
		t.Fatalf("failed to get grant by old refresh token: %v", err)
	}
	if oldTokenGrant != nil {
		t.Error("expected old refresh token to not return a grant")
	}

	// Verify new refresh token works
	newTokenGrant, err := oauth2State.GetGrantByRefreshToken(context.Background(), newRefreshToken)
	if err != nil {
		t.Fatalf("failed to get grant by new refresh token: %v", err)
	}
	if newTokenGrant == nil {
		t.Fatal("expected new refresh token to return a grant")
	}
	if newTokenGrant.ID != grantID {
		t.Errorf("expected ID %s, got %s", grantID, newTokenGrant.ID)
	}

	// Test expiring a grant
	if err := oauth2State.ExpireGrant(context.Background(), grantID); err != nil {
		t.Fatalf("failed to expire grant: %v", err)
	}

	// Test that expired grant is not returned
	expiredGrant, err := oauth2State.GetGrant(context.Background(), grantID)
	if err != nil {
		t.Fatalf("failed to get expired grant: %v", err)
	}
	if expiredGrant != nil {
		t.Error("expected expired grant to be nil")
	}

	// Test that expired grant is not returned by auth code
	expiredByAuthCode, err := oauth2State.GetGrantByAuthCode(context.Background(), authCode)
	if err != nil {
		t.Fatalf("failed to get expired grant by auth code: %v", err)
	}
	if expiredByAuthCode != nil {
		t.Error("expected expired grant to be nil when retrieved by auth code")
	}

	// Test that expired grant is not returned by refresh token
	expiredByRefreshToken, err := oauth2State.GetGrantByRefreshToken(context.Background(), newRefreshToken)
	if err != nil {
		t.Fatalf("failed to get expired grant by refresh token: %v", err)
	}
	if expiredByRefreshToken != nil {
		t.Error("expected expired grant to be nil when retrieved by refresh token")
	}
}
