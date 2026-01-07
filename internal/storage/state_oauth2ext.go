package storage

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"time"

	bolt "go.etcd.io/bbolt"
	"github.com/google/uuid"
	"lds.li/oauth2ext/oauth2as"
)

var _ oauth2as.Storage = (*State)(nil)

const (
	// Bucket names for OAuth2 grant storage
	bucketGrants        = "grants"
	bucketAuthCodes     = "auth_codes"
	bucketRefreshTokens = "refresh_tokens"
)

// storedGrantJSON is a temporary struct with JSON tags for marshaling/unmarshaling
// oauth2as.StoredGrant. This will be removed once oauth2as.StoredGrant has JSON tags.
type storedGrantJSON struct {
	ID            uuid.UUID            `json:"id"`
	UserID        string               `json:"userID"`
	ClientID      string               `json:"clientID"`
	GrantedScopes []string             `json:"grantedScopes"`
	AuthCode      []byte               `json:"authCode,omitempty"`
	RefreshToken  []byte               `json:"refreshToken,omitempty"`
	Request       *oauth2as.AuthRequest `json:"request"`
	GrantedAt     time.Time            `json:"grantedAt"`
	ExpiresAt     time.Time            `json:"expiresAt"`
}

// toStoredGrantJSON converts oauth2as.StoredGrant to storedGrantJSON
func toStoredGrantJSON(g *oauth2as.StoredGrant) *storedGrantJSON {
	return &storedGrantJSON{
		ID:            g.ID,
		UserID:        g.UserID,
		ClientID:      g.ClientID,
		GrantedScopes: g.GrantedScopes,
		AuthCode:      g.AuthCode,
		RefreshToken:  g.RefreshToken,
		Request:       g.Request,
		GrantedAt:     g.GrantedAt,
		ExpiresAt:     g.ExpiresAt,
	}
}

// toStoredGrant converts storedGrantJSON to oauth2as.StoredGrant
func (g *storedGrantJSON) toStoredGrant() *oauth2as.StoredGrant {
	return &oauth2as.StoredGrant{
		ID:            g.ID,
		UserID:        g.UserID,
		ClientID:      g.ClientID,
		GrantedScopes: g.GrantedScopes,
		AuthCode:      g.AuthCode,
		RefreshToken:  g.RefreshToken,
		Request:       g.Request,
		GrantedAt:     g.GrantedAt,
		ExpiresAt:     g.ExpiresAt,
	}
}

// CreateGrant creates a new grant
func (s *State) CreateGrant(ctx context.Context, grant *oauth2as.StoredGrant) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		grantsBucket := tx.Bucket([]byte(bucketGrants))
		if grantsBucket == nil {
			return fmt.Errorf("grants bucket does not exist")
		}

		authCodesBucket := tx.Bucket([]byte(bucketAuthCodes))
		if authCodesBucket == nil {
			return fmt.Errorf("auth codes bucket does not exist")
		}

		refreshTokensBucket := tx.Bucket([]byte(bucketRefreshTokens))
		if refreshTokensBucket == nil {
			return fmt.Errorf("refresh tokens bucket does not exist")
		}

		// Marshal grant to JSON using our tagged struct
		grantJSON := toStoredGrantJSON(grant)
		grantData, err := json.Marshal(grantJSON)
		if err != nil {
			return fmt.Errorf("marshal grant: %w", err)
		}

		// Store grant by ID
		grantKey := grant.ID[:]
		if err := grantsBucket.Put(grantKey, grantData); err != nil {
			return fmt.Errorf("store grant: %w", err)
		}

		// Store auth code -> grant ID mapping if present
		if len(grant.AuthCode) > 0 {
			if err := authCodesBucket.Put(grant.AuthCode, grantKey); err != nil {
				return fmt.Errorf("store auth code mapping: %w", err)
			}
		}

		// Store refresh token -> grant ID mapping if present
		if len(grant.RefreshToken) > 0 {
			if err := refreshTokensBucket.Put(grant.RefreshToken, grantKey); err != nil {
				return fmt.Errorf("store refresh token mapping: %w", err)
			}
		}

		return nil
	})
}

// UpdateGrant updates an existing grant
func (s *State) UpdateGrant(ctx context.Context, grant *oauth2as.StoredGrant) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		grantsBucket := tx.Bucket([]byte(bucketGrants))
		if grantsBucket == nil {
			return fmt.Errorf("grants bucket does not exist")
		}

		authCodesBucket := tx.Bucket([]byte(bucketAuthCodes))
		if authCodesBucket == nil {
			return fmt.Errorf("auth codes bucket does not exist")
		}

		refreshTokensBucket := tx.Bucket([]byte(bucketRefreshTokens))
		if refreshTokensBucket == nil {
			return fmt.Errorf("refresh tokens bucket does not exist")
		}

		// Get existing grant to clean up old mappings
		grantKey := grant.ID[:]
		existingData := grantsBucket.Get(grantKey)
		if existingData != nil {
			var existingGrantJSON storedGrantJSON
			if err := json.Unmarshal(existingData, &existingGrantJSON); err == nil {
				existingGrant := existingGrantJSON.toStoredGrant()
				// Remove old auth code mapping if it exists and changed or removed
				if len(existingGrant.AuthCode) > 0 {
					if len(grant.AuthCode) == 0 || !bytes.Equal(existingGrant.AuthCode, grant.AuthCode) {
						if err := authCodesBucket.Delete(existingGrant.AuthCode); err != nil {
							return fmt.Errorf("delete old auth code mapping: %w", err)
						}
					}
				}
				// Remove old refresh token mapping if it exists and changed or removed
				if len(existingGrant.RefreshToken) > 0 {
					if len(grant.RefreshToken) == 0 || !bytes.Equal(existingGrant.RefreshToken, grant.RefreshToken) {
						if err := refreshTokensBucket.Delete(existingGrant.RefreshToken); err != nil {
							return fmt.Errorf("delete old refresh token mapping: %w", err)
						}
					}
				}
			}
		}

		// Marshal updated grant to JSON using our tagged struct
		grantJSON := toStoredGrantJSON(grant)
		grantData, err := json.Marshal(grantJSON)
		if err != nil {
			return fmt.Errorf("marshal grant: %w", err)
		}

		// Update grant
		if err := grantsBucket.Put(grantKey, grantData); err != nil {
			return fmt.Errorf("update grant: %w", err)
		}

		// Update auth code -> grant ID mapping if present
		if len(grant.AuthCode) > 0 {
			if err := authCodesBucket.Put(grant.AuthCode, grantKey); err != nil {
				return fmt.Errorf("store auth code mapping: %w", err)
			}
		}

		// Update refresh token -> grant ID mapping if present
		if len(grant.RefreshToken) > 0 {
			if err := refreshTokensBucket.Put(grant.RefreshToken, grantKey); err != nil {
				return fmt.Errorf("store refresh token mapping: %w", err)
			}
		}

		return nil
	})
}

// ExpireGrant expires a grant by setting its expiry to now
func (s *State) ExpireGrant(ctx context.Context, id uuid.UUID) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		grantsBucket := tx.Bucket([]byte(bucketGrants))
		if grantsBucket == nil {
			return nil // Grant doesn't exist, nothing to expire
		}

		grantKey := id[:]
		grantData := grantsBucket.Get(grantKey)
		if grantData == nil {
			return nil // Grant doesn't exist, nothing to expire
		}

		// Unmarshal grant
		var grantJSON storedGrantJSON
		if err := json.Unmarshal(grantData, &grantJSON); err != nil {
			return fmt.Errorf("unmarshal grant: %w", err)
		}

		// Set expiry to now
		grantJSON.ExpiresAt = time.Now()

		// Marshal and store back
		updatedData, err := json.Marshal(&grantJSON)
		if err != nil {
			return fmt.Errorf("marshal grant: %w", err)
		}

		if err := grantsBucket.Put(grantKey, updatedData); err != nil {
			return fmt.Errorf("update grant expiry: %w", err)
		}

		return nil
	})
}

// GetGrant retrieves a grant by ID
func (s *State) GetGrant(ctx context.Context, id uuid.UUID) (*oauth2as.StoredGrant, error) {
	var grant *oauth2as.StoredGrant
	err := s.db.View(func(tx *bolt.Tx) error {
		grantsBucket := tx.Bucket([]byte(bucketGrants))
		if grantsBucket == nil {
			return nil // No grants bucket means no grant
		}

		grantKey := id[:]
		grantData := grantsBucket.Get(grantKey)
		if grantData == nil {
			return nil // Grant not found
		}

		var gJSON storedGrantJSON
		if err := json.Unmarshal(grantData, &gJSON); err != nil {
			return fmt.Errorf("unmarshal grant: %w", err)
		}

		// Check if grant is expired
		if time.Now().After(gJSON.ExpiresAt) {
			return nil // Grant expired
		}

		g := gJSON.toStoredGrant()
		grant = g
		return nil
	})

	if err != nil {
		return nil, err
	}

	return grant, nil
}

// GetGrantByAuthCode retrieves a grant by authorization code
func (s *State) GetGrantByAuthCode(ctx context.Context, authCode []byte) (*oauth2as.StoredGrant, error) {
	var grant *oauth2as.StoredGrant
	err := s.db.View(func(tx *bolt.Tx) error {
		authCodesBucket := tx.Bucket([]byte(bucketAuthCodes))
		if authCodesBucket == nil {
			return nil // No auth codes bucket means no grant
		}

		grantsBucket := tx.Bucket([]byte(bucketGrants))
		if grantsBucket == nil {
			return nil // No grants bucket means no grant
		}

		// Look up grant ID from auth code
		grantKey := authCodesBucket.Get(authCode)
		if grantKey == nil {
			return nil // Auth code not found
		}

		// Get grant data
		grantData := grantsBucket.Get(grantKey)
		if grantData == nil {
			return nil // Grant not found
		}

		var gJSON storedGrantJSON
		if err := json.Unmarshal(grantData, &gJSON); err != nil {
			return fmt.Errorf("unmarshal grant: %w", err)
		}

		// Check if grant is expired
		if time.Now().After(gJSON.ExpiresAt) {
			return nil // Grant expired
		}

		g := gJSON.toStoredGrant()
		grant = g
		return nil
	})

	if err != nil {
		return nil, err
	}

	return grant, nil
}

// GetGrantByRefreshToken retrieves a grant by refresh token
func (s *State) GetGrantByRefreshToken(ctx context.Context, refreshToken []byte) (*oauth2as.StoredGrant, error) {
	var grant *oauth2as.StoredGrant
	err := s.db.View(func(tx *bolt.Tx) error {
		refreshTokensBucket := tx.Bucket([]byte(bucketRefreshTokens))
		if refreshTokensBucket == nil {
			return nil // No refresh tokens bucket means no grant
		}

		grantsBucket := tx.Bucket([]byte(bucketGrants))
		if grantsBucket == nil {
			return nil // No grants bucket means no grant
		}

		// Look up grant ID from refresh token
		grantKey := refreshTokensBucket.Get(refreshToken)
		if grantKey == nil {
			return nil // Refresh token not found
		}

		// Get grant data
		grantData := grantsBucket.Get(grantKey)
		if grantData == nil {
			return nil // Grant not found
		}

		var gJSON storedGrantJSON
		if err := json.Unmarshal(grantData, &gJSON); err != nil {
			return fmt.Errorf("unmarshal grant: %w", err)
		}

		// Check if grant is expired
		if time.Now().After(gJSON.ExpiresAt) {
			return nil // Grant expired
		}

		g := gJSON.toStoredGrant()
		grant = g
		return nil
	})

	if err != nil {
		return nil, err
	}

	return grant, nil
}

// ListActiveGrantsForUser retrieves all active grants for a specific user
func (s *State) ListActiveGrantsForUser(ctx context.Context, userID string) ([]*oauth2as.StoredGrant, error) {
	var grants []*oauth2as.StoredGrant
	err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(bucketGrants))
		if b == nil {
			return nil
		}
		c := b.Cursor()

		for k, v := c.First(); k != nil; k, v = c.Next() {
			var gJSON storedGrantJSON
			if err := json.Unmarshal(v, &gJSON); err != nil {
				continue // skip malformed
			}

			if gJSON.UserID != userID {
				continue
			}

			// Check if active: has refresh token and not expired
			if len(gJSON.RefreshToken) == 0 {
				continue
			}
			if time.Now().After(gJSON.ExpiresAt) {
				continue
			}

			grants = append(grants, gJSON.toStoredGrant())
		}
		return nil
	})
	return grants, err
}

// RevokeGrant revokes a grant by removing its refresh token
func (s *State) RevokeGrant(ctx context.Context, id uuid.UUID) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		grantsBucket := tx.Bucket([]byte(bucketGrants))
		if grantsBucket == nil {
			return nil
		}
		refreshTokensBucket := tx.Bucket([]byte(bucketRefreshTokens))
		if refreshTokensBucket == nil {
			return nil
		}

		grantKey := id[:]
		grantData := grantsBucket.Get(grantKey)
		if grantData == nil {
			return nil // already gone
		}

		var gJSON storedGrantJSON
		if err := json.Unmarshal(grantData, &gJSON); err != nil {
			return fmt.Errorf("unmarshal grant: %w", err)
		}

		// Delete refresh token index
		if len(gJSON.RefreshToken) > 0 {
			if err := refreshTokensBucket.Delete(gJSON.RefreshToken); err != nil {
				return fmt.Errorf("delete refresh token mapping: %w", err)
			}
		}

		// Clear refresh token from grant record
		gJSON.RefreshToken = nil

		// Marshal updated grant
		updatedData, err := json.Marshal(&gJSON)
		if err != nil {
			return fmt.Errorf("marshal updated grant: %w", err)
		}

		// Save updated grant
		if err := grantsBucket.Put(grantKey, updatedData); err != nil {
			return fmt.Errorf("update grant: %w", err)
		}

		return nil
	})
}
