package oauth2as

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

var (
	// ErrNotFound is returned when a record cannot be found in storage.
	ErrNotFound        = errors.New("not found")
	errStorageConflict = errors.New("storage conflict")
)

type storageKind string

const (
	storageKindGrant        storageKind = "grant"
	storageKindAuthCode     storageKind = "auth_code"
	storageKindRefreshToken storageKind = "refresh_token"
	storageKindSession      storageKind = "session"
)

// storageRef identifies one stored record.
type storageRef struct {
	Kind storageKind
	ID   string
}

// storageCheck is a precondition for an atomic commit. Version zero requires
// that the record does not exist; any other value requires an exact match.
type storageCheck struct {
	Kind    storageKind
	ID      string
	Version uint64
}

func (c storageCheck) ref() storageRef { return storageRef{Kind: c.Kind, ID: c.ID} }

// storageCommit is an atomic conditional batch. All checks must be evaluated
// against one consistent view. If any check fails, Commit must return
// errStorageConflict without applying any put or delete. A put creates version
// one or increments the existing version. Mutating one record more than once
// makes a commit invalid and must not apply any changes.
type storageCommit struct {
	Checks        []storageCheck
	Grants        []storedGrant
	AuthCodes     []storedAuthCode
	RefreshTokens []storedRefreshToken
	Sessions      []storedRefreshSession
	Deletes       []storageRef
}

// storedAuthCode represents an authorization code that is issued during the
// authorization flow. Auth codes are short-lived and single-use.
type storedAuthCode struct {
	ID      string
	Code    []byte `json:"code,omitzero"`
	GrantID string `json:"grantId,omitzero"`
	// ValidUntil is the time at which the code is no longer valid for use.
	ValidUntil time.Time `json:"validUntil,omitzero"`
	// StorageExpiresAt is the time at which the code can be deleted from storage.
	// This is typically after ValidUntil to allow for cleanup.
	StorageExpiresAt time.Time `json:"storageExpiresAt,omitzero"`
	// EncryptedGrantKey is the key used to encrypt the grant metadata, encrypted
	// with this auth code.
	EncryptedGrantKey []byte `json:"encryptedGrantKey,omitzero"`
	storageVersion    uint64
}

// storedRefreshToken represents a refresh token that can be used to obtain new
// access tokens. Refresh tokens are long-lived and support rotation with grace periods.
type storedRefreshToken struct {
	ID      string
	Token   []byte `json:"token,omitzero"`
	GrantID string `json:"grantId,omitzero"`
	// ValidUntil is the time at which the token is no longer valid for use.
	ValidUntil time.Time `json:"validUntil,omitzero"`
	// StorageExpiresAt is the time at which the token can be deleted from storage.
	// This is typically after ValidUntil plus any grace period.
	StorageExpiresAt time.Time `json:"storageExpiresAt,omitzero"`
	// ReplacedByTokenID is the ID of the token that replaced this one during rotation.
	// Used for tracking rotation chains and enforcing grace period policies.
	ReplacedByTokenID string `json:"replacedByTokenID,omitzero"`
	// EncryptedGrantKey is the key used to encrypt the grant metadata, encrypted
	// with this refresh token.
	EncryptedGrantKey []byte `json:"encryptedGrantKey,omitzero"`
	storageVersion    uint64
}

type storedGrant struct {
	ID string
	// UserID is the user ID that was granted access.
	UserID string `json:"userId,omitzero"`
	// ClientID is the client ID that was granted access.
	ClientID string `json:"clientId,omitzero"`
	// GrantedScopes are the scopes that were actually granted.
	GrantedScopes []string `json:"grantedScopes,omitzero"`
	// Request captures the request that was used to grant access. Used for
	// finalizing the code flow.
	Request *AuthRequest `json:"request,omitzero"`
	// GrantedAt is the time at which the grant was granted.
	GrantedAt time.Time `json:"grantedAt,omitzero"`
	// AuthenticatedAt is when the End-User last actively authenticated. Emitted
	// as the auth_time claim in ID tokens.
	AuthenticatedAt time.Time `json:"authenticatedAt,omitzero"`
	// ExpiresAt is the time at which the grant will expire.
	ExpiresAt time.Time `json:"expiresAt,omitzero"`

	// AdditionalState contains private protocol state encoded inside the
	// library-owned grant record.
	AdditionalState json.RawMessage `json:"additionalState,omitzero"`

	// Metadata stores unencrypted application-specific data that can be accessed
	// without a valid token (e.g., grant creation timestamp, grant type).
	Metadata []byte `json:"metadata,omitzero"`
	// EncryptedMetadata stores sensitive application data encrypted with the
	// Grant Key. Only accessible with a valid token from this grant.
	//
	// Common use case: storing upstream IDP refresh tokens when this AS acts
	// as an OAuth2 client to another provider. The upstream refresh token is
	// encrypted here and can only be decrypted by presenting a valid token.
	EncryptedMetadata []byte `json:"encryptedMetadata,omitzero"`
	// ACR is the Authentication Context Class Reference satisfied for this grant.
	ACR string `json:"acr,omitzero"`
	// AMR lists the Authentication Methods References for this grant.
	AMR            []string `json:"amr,omitzero"`
	storageVersion uint64
}

type storedAdditionalState struct {
	DPoPThumbprint *string `json:"dpopThumbprint,omitzero"`
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
	storageVersion  uint64
}

type storageBackend interface {
	GetGrant(ctx context.Context, id string) (storedGrant, error)
	GetAuthCode(ctx context.Context, id string) (storedAuthCode, error)
	GetRefreshToken(ctx context.Context, id string) (storedRefreshToken, error)
	Commit(ctx context.Context, commit storageCommit) error
	ListRefreshSessions(ctx context.Context, query storageRefreshSessionQuery) ([]storedRefreshSession, error)
	Cleanup(ctx context.Context, options CleanupOptions) (CleanupResult, error)
	Migrate(ctx context.Context) error
}

// Storage is an opaque authorization-server storage implementation. Construct
// one with [NewSQLStorage] or [NewMemoryStorage]. A Storage must be dedicated to
// one issuer.
type Storage struct {
	backend storageBackend
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

// Migrate applies pending schema migrations. It is safe to call on every
// process start. In-memory storage is a no-op.
func (s *Storage) Migrate(ctx context.Context) error {
	if s == nil || s.backend == nil {
		return errors.New("oauth2as: invalid storage")
	}
	return s.backend.Migrate(ctx)
}

// Cleanup physically removes expired storage records. Protocol validity does
// not depend on cleanup being run.
func (s *Storage) Cleanup(ctx context.Context, options CleanupOptions) (CleanupResult, error) {
	if s == nil || s.backend == nil {
		return CleanupResult{}, errors.New("oauth2as: invalid storage")
	}
	if options.Before.IsZero() {
		options.Before = time.Now()
	}
	if options.Limit == 0 {
		options.Limit = defaultCleanupLimit
	}
	if options.Limit < 0 || options.Limit > maxCleanupLimit {
		return CleanupResult{}, errors.New("oauth2as: cleanup limit must be between 0 and 10000")
	}
	return s.backend.Cleanup(ctx, options)
}

func (s *Storage) getGrant(ctx context.Context, id string) (*storedGrant, error) {
	grant, err := s.backend.GetGrant(ctx, id)
	if err != nil {
		return nil, err
	}
	return &grant, nil
}

func (s *Storage) getAuthCode(ctx context.Context, id string) (*storedAuthCode, error) {
	code, err := s.backend.GetAuthCode(ctx, id)
	if err != nil {
		return nil, err
	}
	return &code, nil
}

func (s *Storage) getRefreshToken(ctx context.Context, id string) (*storedRefreshToken, error) {
	token, err := s.backend.GetRefreshToken(ctx, id)
	if err != nil {
		return nil, err
	}
	return &token, nil
}

func (s *Storage) commit(ctx context.Context, commit storageCommit) error {
	if err := validateStorageCommit(commit); err != nil {
		return err
	}
	return s.backend.Commit(ctx, commit)
}

type storageRefreshSessionQuery struct {
	UserID        string
	ClientID      string
	ActiveAt      time.Time
	AfterLastUsed time.Time
	AfterGrantID  string
	Limit         int
}

func (s *Storage) listRefreshSessions(ctx context.Context, query storageRefreshSessionQuery) ([]storedRefreshSession, error) {
	return s.backend.ListRefreshSessions(ctx, query)
}

func validateStorageCommit(commit storageCommit) error {
	mutated := make(map[storageRef]struct{}, len(commit.Grants)+len(commit.AuthCodes)+len(commit.RefreshTokens)+len(commit.Sessions)+len(commit.Deletes))
	add := func(ref storageRef) error {
		if ref.ID == "" {
			return fmt.Errorf("storage commit missing %s id", ref.Kind)
		}
		if _, exists := mutated[ref]; exists {
			return fmt.Errorf("storage commit mutates %s %q more than once", ref.Kind, ref.ID)
		}
		mutated[ref] = struct{}{}
		return nil
	}
	for i := range commit.Grants {
		if err := add(storageRef{Kind: storageKindGrant, ID: commit.Grants[i].ID}); err != nil {
			return err
		}
	}
	for i := range commit.AuthCodes {
		if err := add(storageRef{Kind: storageKindAuthCode, ID: commit.AuthCodes[i].ID}); err != nil {
			return err
		}
	}
	for i := range commit.RefreshTokens {
		if err := add(storageRef{Kind: storageKindRefreshToken, ID: commit.RefreshTokens[i].ID}); err != nil {
			return err
		}
	}
	for i := range commit.Sessions {
		if err := add(storageRef{Kind: storageKindSession, ID: commit.Sessions[i].GrantID}); err != nil {
			return err
		}
	}
	for _, ref := range commit.Deletes {
		if err := add(ref); err != nil {
			return err
		}
	}
	return nil
}

func hasCreateCheck(checks []storageCheck, ref storageRef) bool {
	for _, check := range checks {
		if check.ref() == ref && check.Version == 0 {
			return true
		}
	}
	return false
}
