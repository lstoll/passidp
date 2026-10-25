package oauth2as

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"
)

const (
	defaultRefreshSessionPageSize = 50
	maxRefreshSessionPageSize     = 200
)

// RefreshSessionQuery selects active grant-level refresh sessions. UserID is
// required. ClientID optionally narrows the result to one OAuth client.
// ActiveAt defaults to the server clock. Cursor values are opaque and are only
// valid with the same UserID and ClientID.
type RefreshSessionQuery struct {
	UserID   string
	ClientID string
	ActiveAt time.Time
	Limit    int
	Cursor   string
}

// RefreshSession describes one grant with a currently usable refresh-token
// family. Individual rotated token records are intentionally not exposed.
type RefreshSession struct {
	GrantID         string
	UserID          string
	ClientID        string
	GrantedScopes   []string
	CreatedAt       time.Time
	AuthenticatedAt time.Time
	ExpiresAt       time.Time
	LastUsedAt      time.Time
}

// RefreshSessionPage is one page of active refresh sessions.
type RefreshSessionPage struct {
	Sessions   []RefreshSession
	NextCursor string
}

// ListRefreshSessions lists active refresh-token families for a user. Session
// indexes are maintained atomically with token issuance and rotation.
func (s *Server) ListRefreshSessions(ctx context.Context, query RefreshSessionQuery) (RefreshSessionPage, error) {
	if query.UserID == "" {
		return RefreshSessionPage{}, fmt.Errorf("user ID is required")
	}
	if query.Limit < 0 || query.Limit > maxRefreshSessionPageSize {
		return RefreshSessionPage{}, fmt.Errorf("limit must be between 0 and %d", maxRefreshSessionPageSize)
	}
	limit := query.Limit
	if limit == 0 {
		limit = defaultRefreshSessionPageSize
	}
	activeAt := query.ActiveAt
	if activeAt.IsZero() {
		activeAt = s.now()
	}
	afterLastUsed, afterGrantID, err := decodeRefreshSessionCursor(query.Cursor, query.UserID, query.ClientID)
	if err != nil {
		return RefreshSessionPage{}, fmt.Errorf("invalid refresh session cursor")
	}
	found, err := s.config.Storage.listRefreshSessions(ctx, storageRefreshSessionQuery{
		UserID:        query.UserID,
		ClientID:      query.ClientID,
		ActiveAt:      activeAt,
		AfterLastUsed: afterLastUsed,
		AfterGrantID:  afterGrantID,
		Limit:         limit + 1,
	})
	if err != nil {
		return RefreshSessionPage{}, fmt.Errorf("list refresh sessions: %w", err)
	}

	result := RefreshSessionPage{Sessions: make([]RefreshSession, min(len(found), limit))}
	for i := range result.Sessions {
		stored := found[i]
		result.Sessions[i] = RefreshSession{
			GrantID:         stored.GrantID,
			UserID:          stored.UserID,
			ClientID:        stored.ClientID,
			GrantedScopes:   slices.Clone(stored.GrantedScopes),
			CreatedAt:       stored.CreatedAt,
			AuthenticatedAt: stored.AuthenticatedAt,
			ExpiresAt:       stored.ExpiresAt,
			LastUsedAt:      stored.LastUsedAt,
		}
	}
	if len(found) > limit {
		last := found[limit-1]
		result.NextCursor = encodeRefreshSessionCursor(query.UserID, query.ClientID, last.LastUsedAt, last.GrantID)
	}
	return result, nil
}

// RevokeRefreshSession revokes a user's grant-level refresh session. Existing
// access tokens remain independently valid until their expiry, but no token
// associated with the grant can be refreshed and UserInfo rejects the grant.
// It returns [ErrNotFound] when the grant does not exist or belongs to another
// user.
func (s *Server) RevokeRefreshSession(ctx context.Context, userID, grantID string) error {
	if userID == "" || grantID == "" {
		return ErrNotFound
	}
	grant, err := s.config.Storage.getGrant(ctx, grantID)
	if err != nil {
		return err
	}
	if grant.UserID != userID {
		return ErrNotFound
	}
	if err := s.config.Storage.commit(ctx, storageCommit{
		Checks:  []storageCheck{{Kind: storageKindGrant, ID: grantID, Version: grant.storageVersion}},
		Deletes: []storageRef{{Kind: storageKindGrant, ID: grantID}},
	}); err != nil {
		if errors.Is(err, errStorageConflict) {
			return ErrNotFound
		}
		return fmt.Errorf("revoke refresh session: %w", err)
	}
	return nil
}

func encodeRefreshSessionCursor(userID, clientID string, lastUsed time.Time, grantID string) string {
	return strings.Join([]string{
		base64.RawURLEncoding.EncodeToString([]byte(userID)),
		base64.RawURLEncoding.EncodeToString([]byte(clientID)),
		base64.RawURLEncoding.EncodeToString([]byte(strconv.FormatInt(lastUsed.UnixMicro(), 10))),
		base64.RawURLEncoding.EncodeToString([]byte(grantID)),
	}, ".")
}

func decodeRefreshSessionCursor(cursor, userID, clientID string) (time.Time, string, error) {
	if cursor == "" {
		return time.Time{}, "", nil
	}
	parts := strings.Split(cursor, ".")
	if len(parts) != 4 {
		return time.Time{}, "", fmt.Errorf("invalid cursor")
	}
	values := make([]string, len(parts))
	for i, part := range parts {
		decoded, err := base64.RawURLEncoding.Strict().DecodeString(part)
		if err != nil || base64.RawURLEncoding.EncodeToString(decoded) != part {
			return time.Time{}, "", fmt.Errorf("invalid cursor")
		}
		values[i] = string(decoded)
	}
	micros, err := strconv.ParseInt(values[2], 10, 64)
	if err != nil || values[0] != userID || values[1] != clientID || values[3] == "" {
		return time.Time{}, "", fmt.Errorf("invalid cursor")
	}
	return timeFromMicros(micros), values[3], nil
}
