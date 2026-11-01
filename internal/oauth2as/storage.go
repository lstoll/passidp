package oauth2as

import (
	"context"
	"errors"
	"time"
)

var (
	// ErrNotFound is returned when a record cannot be found in storage.
	ErrNotFound        = errors.New("not found")
	errStorageConflict = errors.New("storage conflict")
)

// storedAuthCode represents an authorization code that is issued during the
// authorization flow. Auth codes are short-lived and single-use.
type storedAuthCode struct {
	// ID is the hex SHA-256 digest of the full authorization code.
	ID      string
	GrantID string
	// ValidUntil is the time at which the code is no longer valid for use.
	ValidUntil time.Time
	// StorageExpiresAt is the time at which the code can be deleted from storage.
	// This is typically after ValidUntil to allow for cleanup.
	StorageExpiresAt time.Time
}

// storedRefreshToken represents a refresh token that can be used to obtain new
// access tokens. Refresh tokens are long-lived and support rotation with grace periods.
type storedRefreshToken struct {
	// ID is the hex SHA-256 digest of the full refresh token.
	ID      string
	GrantID string
	// ValidUntil is the time at which the token is no longer valid for use.
	ValidUntil time.Time
	// StorageExpiresAt is the time at which the token can be deleted from storage.
	// This is typically after ValidUntil plus any grace period.
	StorageExpiresAt time.Time
	// ReplacedByTokenID is the ID of the token that replaced this one during rotation.
	// Used for tracking rotation chains and enforcing grace period policies.
	ReplacedByTokenID string
}

type storedGrant struct {
	ID string
	// UserID is the user ID that was granted access.
	UserID string
	// ClientID is the client ID that was granted access.
	ClientID string
	// GrantedScopes are the scopes that were actually granted.
	GrantedScopes []string
	// Fields retained from the authorization request for exchange and token claims.
	RedirectURI    string
	CodeChallenge  string
	Nonce          string
	MaxAge         *int
	DPoPThumbprint string
	// GrantedAt is the time at which the grant was granted.
	GrantedAt time.Time
	// AuthenticatedAt is when the End-User last actively authenticated. Emitted
	// as the auth_time claim in ID tokens.
	AuthenticatedAt time.Time
	// ExpiresAt is the time at which the grant will expire.
	ExpiresAt time.Time

	// ACR is the Authentication Context Class Reference satisfied for this grant.
	ACR string
	// AMR lists the Authentication Methods References for this grant.
	AMR            []string
	storageVersion uint64
}

type storedRefreshSession struct {
	GrantID         string
	UserID          string
	ClientID        string
	GrantedScopes   []string
	CreatedAt       time.Time
	AuthenticatedAt time.Time
	ExpiresAt       time.Time
	LastUsedAt      time.Time
	DPoPBound       bool
}

// CleanupOptions controls physical removal of expired storage records.
type CleanupOptions struct {
	// Before removes records whose physical retention deadline is at or before
	// this time. It defaults to the current time.
	Before time.Time
	// Limit bounds the number of primary records removed in one call. It
	// defaults to 500 and cannot exceed 10000.
	Limit int
}

// CleanupResult describes one bounded cleanup pass.
type CleanupResult struct {
	// Deleted is the number of primary records removed. Rows removed by foreign
	// key cascades are not included.
	Deleted int
	// More reports whether another cleanup call could remove more records for
	// the same cutoff.
	More bool
}

const (
	defaultCleanupLimit = 500
	maxCleanupLimit     = 10_000
)

// Cleanup physically removes expired storage records. Protocol validity does
// not depend on cleanup being run.
func (s *Storage) Cleanup(ctx context.Context, options CleanupOptions) (CleanupResult, error) {
	if options.Before.IsZero() {
		options.Before = time.Now()
	}
	if options.Limit == 0 {
		options.Limit = defaultCleanupLimit
	}
	if options.Limit < 0 || options.Limit > maxCleanupLimit {
		return CleanupResult{}, errors.New("oauth2as: cleanup limit must be between 0 and 10000")
	}
	return s.cleanup(ctx, options)
}

type storageRefreshSessionQuery struct {
	UserID        string
	ClientID      string
	ActiveAt      time.Time
	AfterLastUsed time.Time
	AfterGrantID  string
	Limit         int
}
