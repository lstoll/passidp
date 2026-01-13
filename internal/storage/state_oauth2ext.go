package storage

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	bolt "go.etcd.io/bbolt"
	"lds.li/oauth2ext/oauth2as"
)

const (
	// Bucket names for OAuth2 grant storage
	bucketGrants        = "grants"
	bucketAuthCodes     = "auth_codes"
	bucketRefreshTokens = "refresh_tokens"

	// oauth2GrantRetentionPeriod is how long to keep expired grants for audit purposes
	oauth2GrantRetentionPeriod = 365 * 24 * time.Hour // 1 year
)

// idToKey converts a UUID string to a storage key (UUID binary).
func idToKey(id string) ([]byte, error) {
	uuidVal, err := uuid.Parse(id)
	if err != nil {
		return nil, fmt.Errorf("invalid UUID: %w", err)
	}
	return uuidVal[:], nil
}

// OAuth2State implements oauth2as.Storage using BoltDB
type OAuth2State struct {
	dbAccessor *dbAccessor
}

var _ oauth2as.Storage = (*OAuth2State)(nil)

// CreateGrant creates a new grant and returns a unique opaque identifier.
func (o *OAuth2State) CreateGrant(ctx context.Context, grant *oauth2as.StoredGrant) (string, error) {
	db, release := o.dbAccessor.db()
	defer release()

	// Use UUID v7 for time-ordered IDs
	internalID, err := uuid.NewV7()
	if err != nil {
		return "", fmt.Errorf("generate UUID v7: %w", err)
	}

	// Initialize version for optimistic locking
	grant.Version = 1

	grantID := internalID.String()
	key := internalID[:]

	err = db.Update(func(tx *bolt.Tx) error {
		grantsBucket := tx.Bucket([]byte(bucketGrants))
		if grantsBucket == nil {
			return fmt.Errorf("grants bucket does not exist")
		}

		grantData, err := json.Marshal(grant)
		if err != nil {
			return fmt.Errorf("marshal grant: %w", err)
		}

		if err := grantsBucket.Put(key, grantData); err != nil {
			return fmt.Errorf("store grant: %w", err)
		}

		return nil
	})
	if err != nil {
		return "", err
	}

	return grantID, nil
}

// UpdateGrant updates an existing grant.
func (o *OAuth2State) UpdateGrant(ctx context.Context, id string, grant *oauth2as.StoredGrant) error {
	db, release := o.dbAccessor.db()
	defer release()

	key, err := idToKey(id)
	if err != nil {
		return oauth2as.ErrNotFound
	}

	return db.Update(func(tx *bolt.Tx) error {
		grantsBucket := tx.Bucket([]byte(bucketGrants))
		if grantsBucket == nil {
			return fmt.Errorf("grants bucket does not exist")
		}

		// Get existing grant for optimistic locking
		existingData := grantsBucket.Get(key)
		if existingData == nil {
			return oauth2as.ErrNotFound
		}

		var existing oauth2as.StoredGrant
		if err := json.Unmarshal(existingData, &existing); err != nil {
			return fmt.Errorf("unmarshal existing grant: %w", err)
		}

		// Optimistic locking: check version matches
		if existing.Version != grant.Version {
			return oauth2as.ErrConcurrentUpdate
		}

		grant.Version = existing.Version + 1

		grantData, err := json.Marshal(grant)
		if err != nil {
			return fmt.Errorf("marshal grant: %w", err)
		}

		if err := grantsBucket.Put(key, grantData); err != nil {
			return fmt.Errorf("update grant: %w", err)
		}

		return nil
	})
}

// ExpireGrant expires a grant by setting its expiry to now.
func (o *OAuth2State) ExpireGrant(ctx context.Context, id string) error {
	db, release := o.dbAccessor.db()
	defer release()

	key, err := idToKey(id)
	if err != nil {
		return nil // Invalid ID means grant not found
	}

	return db.Update(func(tx *bolt.Tx) error {
		grantsBucket := tx.Bucket([]byte(bucketGrants))
		if grantsBucket == nil {
			return nil
		}

		grantData := grantsBucket.Get(key)
		if grantData == nil {
			return nil // Grant doesn't exist
		}

		var grant oauth2as.StoredGrant
		if err := json.Unmarshal(grantData, &grant); err != nil {
			return fmt.Errorf("unmarshal grant: %w", err)
		}

		grant.ExpiresAt = time.Now()

		updatedData, err := json.Marshal(&grant)
		if err != nil {
			return fmt.Errorf("marshal grant: %w", err)
		}

		if err := grantsBucket.Put(key, updatedData); err != nil {
			return fmt.Errorf("update grant expiry: %w", err)
		}

		return nil
	})
}

// GetGrant retrieves a grant by ID.
func (o *OAuth2State) GetGrant(ctx context.Context, id string) (*oauth2as.StoredGrant, error) {
	db, release := o.dbAccessor.db()
	defer release()

	key, err := idToKey(id)
	if err != nil {
		return nil, oauth2as.ErrNotFound
	}

	var grant *oauth2as.StoredGrant

	err = db.View(func(tx *bolt.Tx) error {
		grantsBucket := tx.Bucket([]byte(bucketGrants))
		if grantsBucket == nil {
			return oauth2as.ErrNotFound
		}

		grantData := grantsBucket.Get(key)
		if grantData == nil {
			return oauth2as.ErrNotFound
		}

		var g oauth2as.StoredGrant
		if err := json.Unmarshal(grantData, &g); err != nil {
			return fmt.Errorf("unmarshal grant: %w", err)
		}

		grant = &g
		return nil
	})

	if err != nil {
		return nil, err
	}

	return grant, nil
}

// CreateAuthCode creates a new authorization code associated with a grant.
func (o *OAuth2State) CreateAuthCode(ctx context.Context, userID, grantID, codeID string, code *oauth2as.StoredAuthCode) error {
	db, release := o.dbAccessor.db()
	defer release()

	// Initialize version for optimistic locking
	code.Version = 1

	grantKey, err := idToKey(grantID)
	if err != nil {
		return fmt.Errorf("invalid grant ID: %w", err)
	}
	codeKey, err := idToKey(codeID)
	if err != nil {
		return fmt.Errorf("invalid code ID: %w", err)
	}

	key := append([]byte(userID), 0)
	key = append(key, grantKey...)
	key = append(key, 0)
	key = append(key, codeKey...)

	return db.Update(func(tx *bolt.Tx) error {
		authCodesBucket := tx.Bucket([]byte(bucketAuthCodes))
		if authCodesBucket == nil {
			return fmt.Errorf("auth codes bucket does not exist")
		}

		data, err := json.Marshal(code)
		if err != nil {
			return fmt.Errorf("marshal auth code: %w", err)
		}

		if err := authCodesBucket.Put(key, data); err != nil {
			return fmt.Errorf("store auth code: %w", err)
		}
		return nil
	})
}

// ExpireAuthCode expires an authorization code (deletes it).
func (o *OAuth2State) ExpireAuthCode(ctx context.Context, userID, grantID, codeID string) error {
	db, release := o.dbAccessor.db()
	defer release()

	grantKey, err := idToKey(grantID)
	if err != nil {
		return oauth2as.ErrNotFound
	}
	codeKey, err := idToKey(codeID)
	if err != nil {
		return oauth2as.ErrNotFound
	}

	key := append([]byte(userID), 0)
	key = append(key, grantKey...)
	key = append(key, 0)
	key = append(key, codeKey...)

	return db.Update(func(tx *bolt.Tx) error {
		authCodesBucket := tx.Bucket([]byte(bucketAuthCodes))
		if authCodesBucket == nil {
			return oauth2as.ErrNotFound
		}

		if authCodesBucket.Get(key) == nil {
			return oauth2as.ErrNotFound
		}

		if err := authCodesBucket.Delete(key); err != nil {
			return fmt.Errorf("delete auth code: %w", err)
		}
		return nil
	})
}

// GetAuthCodeAndGrant retrieves an auth code and its associated grant.
func (o *OAuth2State) GetAuthCodeAndGrant(ctx context.Context, userID, grantID, codeID string) (*oauth2as.StoredAuthCode, *oauth2as.StoredGrant, error) {
	db, release := o.dbAccessor.db()
	defer release()

	grantKey, err := idToKey(grantID)
	if err != nil {
		return nil, nil, oauth2as.ErrNotFound
	}
	codeKey, err := idToKey(codeID)
	if err != nil {
		return nil, nil, oauth2as.ErrNotFound
	}

	key := append([]byte(userID), 0)
	key = append(key, grantKey...)
	key = append(key, 0)
	key = append(key, codeKey...)

	var authCode *oauth2as.StoredAuthCode
	var grant *oauth2as.StoredGrant

	err = db.View(func(tx *bolt.Tx) error {
		authCodesBucket := tx.Bucket([]byte(bucketAuthCodes))
		if authCodesBucket == nil {
			return oauth2as.ErrNotFound
		}
		grantsBucket := tx.Bucket([]byte(bucketGrants))
		if grantsBucket == nil {
			return oauth2as.ErrNotFound
		}

		// Get Auth Code
		acData := authCodesBucket.Get(key)
		if acData == nil {
			return oauth2as.ErrNotFound
		}
		var ac oauth2as.StoredAuthCode
		if err := json.Unmarshal(acData, &ac); err != nil {
			return fmt.Errorf("unmarshal auth code: %w", err)
		}

		grantData := grantsBucket.Get(grantKey)
		if grantData == nil {
			// Inconsistent state: auth code exists but grant doesn't
			return oauth2as.ErrNotFound
		}
		var g oauth2as.StoredGrant
		if err := json.Unmarshal(grantData, &g); err != nil {
			return fmt.Errorf("unmarshal grant: %w", err)
		}

		authCode = &ac
		grant = &g
		return nil
	})

	if err != nil {
		return nil, nil, err
	}

	return authCode, grant, nil
}

// CreateRefreshToken creates a new refresh token associated with a grant.
func (o *OAuth2State) CreateRefreshToken(ctx context.Context, userID, grantID, tokenID string, token *oauth2as.StoredRefreshToken) error {
	db, release := o.dbAccessor.db()
	defer release()

	// Initialize version for optimistic locking
	token.Version = 1

	grantKey, err := idToKey(grantID)
	if err != nil {
		return fmt.Errorf("invalid grant ID: %w", err)
	}
	tokenKey, err := idToKey(tokenID)
	if err != nil {
		return fmt.Errorf("invalid token ID: %w", err)
	}

	key := append([]byte(userID), 0)
	key = append(key, grantKey...)
	key = append(key, 0)
	key = append(key, tokenKey...)

	return db.Update(func(tx *bolt.Tx) error {
		refreshTokensBucket := tx.Bucket([]byte(bucketRefreshTokens))
		if refreshTokensBucket == nil {
			return fmt.Errorf("refresh tokens bucket does not exist")
		}

		data, err := json.Marshal(token)
		if err != nil {
			return fmt.Errorf("marshal refresh token: %w", err)
		}

		if err := refreshTokensBucket.Put(key, data); err != nil {
			return fmt.Errorf("store refresh token: %w", err)
		}

		return nil
	})
}

// UpdateRefreshToken updates an existing refresh token.
func (o *OAuth2State) UpdateRefreshToken(ctx context.Context, userID, grantID, tokenID string, token *oauth2as.StoredRefreshToken) error {
	db, release := o.dbAccessor.db()
	defer release()

	grantKey, err := idToKey(grantID)
	if err != nil {
		return oauth2as.ErrNotFound
	}
	tokenKey, err := idToKey(tokenID)
	if err != nil {
		return oauth2as.ErrNotFound
	}

	key := append([]byte(userID), 0)
	key = append(key, grantKey...)
	key = append(key, 0)
	key = append(key, tokenKey...)

	return db.Update(func(tx *bolt.Tx) error {
		refreshTokensBucket := tx.Bucket([]byte(bucketRefreshTokens))
		if refreshTokensBucket == nil {
			return fmt.Errorf("refresh tokens bucket does not exist")
		}

		// Get existing token for optimistic locking
		existingData := refreshTokensBucket.Get(key)
		if existingData == nil {
			return oauth2as.ErrNotFound
		}

		var existing oauth2as.StoredRefreshToken
		if err := json.Unmarshal(existingData, &existing); err != nil {
			return fmt.Errorf("unmarshal existing refresh token: %w", err)
		}

		// Optimistic locking: check version matches
		if existing.Version != token.Version {
			return oauth2as.ErrConcurrentUpdate
		}

		// Increment version
		token.Version = existing.Version + 1

		data, err := json.Marshal(token)
		if err != nil {
			return fmt.Errorf("marshal refresh token: %w", err)
		}

		if err := refreshTokensBucket.Put(key, data); err != nil {
			return fmt.Errorf("update refresh token: %w", err)
		}
		return nil
	})
}

// ExpireRefreshToken expires a refresh token (deletes it).
func (o *OAuth2State) ExpireRefreshToken(ctx context.Context, userID, grantID, tokenID string) error {
	db, release := o.dbAccessor.db()
	defer release()

	grantKey, err := idToKey(grantID)
	if err != nil {
		return oauth2as.ErrNotFound
	}
	tokenKey, err := idToKey(tokenID)
	if err != nil {
		return oauth2as.ErrNotFound
	}

	key := append([]byte(userID), 0)
	key = append(key, grantKey...)
	key = append(key, 0)
	key = append(key, tokenKey...)

	return db.Update(func(tx *bolt.Tx) error {
		refreshTokensBucket := tx.Bucket([]byte(bucketRefreshTokens))
		if refreshTokensBucket == nil {
			return oauth2as.ErrNotFound
		}

		if refreshTokensBucket.Get(key) == nil {
			return oauth2as.ErrNotFound
		}

		if err := refreshTokensBucket.Delete(key); err != nil {
			return fmt.Errorf("delete refresh token: %w", err)
		}
		return nil
	})
}

// GetRefreshTokenAndGrant retrieves a refresh token and its associated grant.
func (o *OAuth2State) GetRefreshTokenAndGrant(ctx context.Context, userID, grantID, tokenID string) (*oauth2as.StoredRefreshToken, *oauth2as.StoredGrant, error) {
	db, release := o.dbAccessor.db()
	defer release()

	grantKey, err := idToKey(grantID)
	if err != nil {
		return nil, nil, oauth2as.ErrNotFound
	}
	tokenKey, err := idToKey(tokenID)
	if err != nil {
		return nil, nil, oauth2as.ErrNotFound
	}

	key := append([]byte(userID), 0)
	key = append(key, grantKey...)
	key = append(key, 0)
	key = append(key, tokenKey...)

	var refreshToken *oauth2as.StoredRefreshToken
	var grant *oauth2as.StoredGrant

	err = db.View(func(tx *bolt.Tx) error {
		refreshTokensBucket := tx.Bucket([]byte(bucketRefreshTokens))
		if refreshTokensBucket == nil {
			return oauth2as.ErrNotFound
		}
		grantsBucket := tx.Bucket([]byte(bucketGrants))
		if grantsBucket == nil {
			return oauth2as.ErrNotFound
		}

		rtData := refreshTokensBucket.Get(key)
		if rtData == nil {
			return oauth2as.ErrNotFound
		}
		var rt oauth2as.StoredRefreshToken
		if err := json.Unmarshal(rtData, &rt); err != nil {
			return fmt.Errorf("unmarshal refresh token: %w", err)
		}

		grantData := grantsBucket.Get(grantKey)
		if grantData == nil {
			return oauth2as.ErrNotFound
		}
		var g oauth2as.StoredGrant
		if err := json.Unmarshal(grantData, &g); err != nil {
			return fmt.Errorf("unmarshal grant: %w", err)
		}

		refreshToken = &rt
		grant = &g
		return nil
	})

	if err != nil {
		return nil, nil, err
	}

	return refreshToken, grant, nil
}

// GrantWithID wraps a StoredGrant with its ID
type GrantWithID struct {
	ID    string
	Grant *oauth2as.StoredGrant
}

// ListActiveGrantsForUser retrieves all active grants for a specific user.
// It filters for grants that have at least one valid (unexpired) refresh token.
// This is not part of the oauth2as.Storage interface but used by the app.
func (o *OAuth2State) ListActiveGrantsForUser(ctx context.Context, userID string) ([]GrantWithID, error) {
	db, release := o.dbAccessor.db()
	defer release()

	var grants []GrantWithID

	err := db.View(func(tx *bolt.Tx) error {
		grantsBucket := tx.Bucket([]byte(bucketGrants))
		if grantsBucket == nil {
			return nil
		}
		refreshTokensBucket := tx.Bucket([]byte(bucketRefreshTokens))
		if refreshTokensBucket == nil {
			return nil
		}

		now := time.Now()

		prefix := []byte(userID)
		prefix = append(prefix, 0)

		c := refreshTokensBucket.Cursor()
		activeGrantIDs := make(map[string]bool)

		for k, v := c.Seek(prefix); k != nil && bytes.HasPrefix(k, prefix); k, v = c.Next() {
			var rt oauth2as.StoredRefreshToken
			if err := json.Unmarshal(v, &rt); err != nil {
				continue
			}

			if !now.After(rt.ValidUntil) {
				activeGrantIDs[rt.GrantID] = true
			}
		}

		for grantID := range activeGrantIDs {
			grantKey, err := idToKey(grantID)
			if err != nil {
				continue
			}

			grantData := grantsBucket.Get(grantKey)
			if grantData == nil {
				continue
			}

			var g oauth2as.StoredGrant
			if err := json.Unmarshal(grantData, &g); err != nil {
				continue
			}

			if g.UserID != userID {
				continue
			}

			if now.After(g.ExpiresAt) {
				continue
			}

			grants = append(grants, GrantWithID{
				ID:    grantID,
				Grant: &g,
			})
		}

		return nil
	})
	return grants, err
}

// RevokeAllGrantsForUser revokes all grants for a specific user.
func (o *OAuth2State) RevokeAllGrantsForUser(ctx context.Context, userID string) error {
	grants, err := o.ListActiveGrantsForUser(ctx, userID)
	if err != nil {
		return err
	}

	for _, g := range grants {
		if err := o.RevokeGrant(ctx, g.ID); err != nil {
			return err
		}
	}
	return nil
}

// RevokeGrant revokes a grant by expiring it.
// This is not part of the oauth2as.Storage interface but used by the app.
func (o *OAuth2State) RevokeGrant(ctx context.Context, id string) error {
	return o.ExpireGrant(ctx, id)
}

// GarbageCollect removes expired auth codes, refresh tokens, and grants that expired more than oauth2GrantRetentionPeriod ago.
// Returns the counts of deleted items.
func (o *OAuth2State) GarbageCollect() (authCodesDeleted, refreshTokensDeleted, grantsDeleted int, err error) {
	now := time.Now()
	grantCutoff := now.Add(-oauth2GrantRetentionPeriod)

	db, release := o.dbAccessor.db()
	defer release()

	err = db.Update(func(tx *bolt.Tx) error {
		authCodesBucket := tx.Bucket([]byte(bucketAuthCodes))
		if authCodesBucket != nil {
			c := authCodesBucket.Cursor()
			for k, v := c.First(); k != nil; k, v = c.Next() {
				var ac oauth2as.StoredAuthCode
				if err := json.Unmarshal(v, &ac); err != nil {
					// Invalid, delete
					if err := authCodesBucket.Delete(k); err == nil {
						authCodesDeleted++
					}
					continue
				}

				if now.After(ac.StorageExpiresAt) {
					if err := authCodesBucket.Delete(k); err == nil {
						authCodesDeleted++
					}
				}
			}
		}

		refreshTokensBucket := tx.Bucket([]byte(bucketRefreshTokens))
		if refreshTokensBucket != nil {
			c := refreshTokensBucket.Cursor()
			for k, v := c.First(); k != nil; k, v = c.Next() {
				var rt oauth2as.StoredRefreshToken
				if err := json.Unmarshal(v, &rt); err != nil {
					// Invalid, delete
					if err := refreshTokensBucket.Delete(k); err == nil {
						refreshTokensDeleted++
					}
					continue
				}

				if now.After(rt.StorageExpiresAt) {
					if err := refreshTokensBucket.Delete(k); err == nil {
						refreshTokensDeleted++
					}
				}
			}
		}

		grantsBucket := tx.Bucket([]byte(bucketGrants))
		if grantsBucket != nil {
			c := grantsBucket.Cursor()
			for k, v := c.First(); k != nil; k, v = c.Next() {
				var g oauth2as.StoredGrant
				if err := json.Unmarshal(v, &g); err != nil {
					// Invalid, delete
					continue
				}

				if g.ExpiresAt.Before(grantCutoff) {
					if err := grantsBucket.Delete(k); err == nil {
						grantsDeleted++
					}
				}
			}
		}

		return nil
	})

	return authCodesDeleted, refreshTokensDeleted, grantsDeleted, err
}
