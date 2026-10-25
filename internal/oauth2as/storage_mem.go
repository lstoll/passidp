package oauth2as

import (
	"bytes"
	"context"
	"maps"
	"net/url"
	"slices"
	"sort"
	"sync"
	"time"
)

var _ storageBackend = (*memoryStorage)(nil)

type memoryStorage struct {
	mu            sync.RWMutex
	grants        map[string]storedGrant
	authCodes     map[string]storedAuthCode
	refreshTokens map[string]storedRefreshToken
	sessions      map[string]storedRefreshSession
}

// NewMemoryStorage creates an empty in-memory store. It is intended for tests
// and local development, not production use.
func NewMemoryStorage() *Storage {
	return &Storage{backend: newMemoryBackend()}
}

func newMemoryBackend() *memoryStorage {
	return &memoryStorage{
		grants:        make(map[string]storedGrant),
		authCodes:     make(map[string]storedAuthCode),
		refreshTokens: make(map[string]storedRefreshToken),
		sessions:      make(map[string]storedRefreshSession),
	}
}

func (m *memoryStorage) GetGrant(_ context.Context, id string) (storedGrant, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	grant, ok := m.grants[id]
	if !ok {
		return storedGrant{}, ErrNotFound
	}
	return cloneGrant(grant), nil
}

func (m *memoryStorage) GetAuthCode(_ context.Context, id string) (storedAuthCode, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	code, ok := m.authCodes[id]
	if !ok {
		return storedAuthCode{}, ErrNotFound
	}
	return cloneAuthCode(code), nil
}

func (m *memoryStorage) GetRefreshToken(_ context.Context, id string) (storedRefreshToken, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	token, ok := m.refreshTokens[id]
	if !ok {
		return storedRefreshToken{}, ErrNotFound
	}
	return cloneRefreshToken(token), nil
}

func (m *memoryStorage) Commit(_ context.Context, commit storageCommit) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	versions := make(map[storageRef]uint64, len(commit.Checks))
	for _, check := range commit.Checks {
		version, exists := m.version(check.ref())
		if check.Version == 0 {
			if exists {
				return errStorageConflict
			}
			continue
		}
		if !exists || version != check.Version {
			return errStorageConflict
		}
		versions[check.ref()] = version
	}

	for i := range commit.Grants {
		grant := cloneGrant(commit.Grants[i])
		grant.storageVersion = m.nextVersion(versions, storageRef{Kind: storageKindGrant, ID: grant.ID})
		m.grants[grant.ID] = grant
	}
	for i := range commit.AuthCodes {
		code := cloneAuthCode(commit.AuthCodes[i])
		code.storageVersion = m.nextVersion(versions, storageRef{Kind: storageKindAuthCode, ID: code.ID})
		m.authCodes[code.ID] = code
	}
	for i := range commit.RefreshTokens {
		token := cloneRefreshToken(commit.RefreshTokens[i])
		token.storageVersion = m.nextVersion(versions, storageRef{Kind: storageKindRefreshToken, ID: token.ID})
		m.refreshTokens[token.ID] = token
	}
	for i := range commit.Sessions {
		session := cloneRefreshSession(commit.Sessions[i])
		session.storageVersion = m.nextVersion(versions, storageRef{Kind: storageKindSession, ID: session.GrantID})
		m.sessions[session.GrantID] = session
	}
	for _, ref := range commit.Deletes {
		m.deleteRef(ref)
	}
	return nil
}

func (m *memoryStorage) nextVersion(versions map[storageRef]uint64, ref storageRef) uint64 {
	if version, ok := versions[ref]; ok {
		return version + 1
	}
	version, _ := m.version(ref)
	return version + 1
}

func (m *memoryStorage) version(ref storageRef) (uint64, bool) {
	switch ref.Kind {
	case storageKindGrant:
		grant, ok := m.grants[ref.ID]
		return grant.storageVersion, ok
	case storageKindAuthCode:
		code, ok := m.authCodes[ref.ID]
		return code.storageVersion, ok
	case storageKindRefreshToken:
		token, ok := m.refreshTokens[ref.ID]
		return token.storageVersion, ok
	case storageKindSession:
		session, ok := m.sessions[ref.ID]
		return session.storageVersion, ok
	default:
		return 0, false
	}
}

func (m *memoryStorage) Cleanup(_ context.Context, options CleanupOptions) (CleanupResult, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	deleted := 0
	remaining := options.Limit
	for _, grantID := range expiredIDs(m.sessions, remaining, func(session storedRefreshSession) time.Time { return session.ExpiresAt }, options.Before) {
		m.deleteRef(storageRef{Kind: storageKindSession, ID: grantID})
		deleted++
		remaining--
	}
	for _, id := range expiredIDs(m.authCodes, remaining, func(code storedAuthCode) time.Time { return code.StorageExpiresAt }, options.Before) {
		m.deleteRef(storageRef{Kind: storageKindAuthCode, ID: id})
		deleted++
		remaining--
	}
	for _, id := range expiredIDs(m.refreshTokens, remaining, func(token storedRefreshToken) time.Time { return token.StorageExpiresAt }, options.Before) {
		m.deleteRef(storageRef{Kind: storageKindRefreshToken, ID: id})
		deleted++
		remaining--
	}
	for _, id := range expiredIDs(m.grants, remaining, func(grant storedGrant) time.Time { return grant.ExpiresAt }, options.Before) {
		m.deleteRef(storageRef{Kind: storageKindGrant, ID: id})
		deleted++
		remaining--
	}
	more := remaining == 0 && (hasExpiredMap(m.sessions, options.Before, func(session storedRefreshSession) time.Time { return session.ExpiresAt }) ||
		hasExpiredMap(m.authCodes, options.Before, func(code storedAuthCode) time.Time { return code.StorageExpiresAt }) ||
		hasExpiredMap(m.refreshTokens, options.Before, func(token storedRefreshToken) time.Time { return token.StorageExpiresAt }) ||
		hasExpiredMap(m.grants, options.Before, func(grant storedGrant) time.Time { return grant.ExpiresAt }))
	return CleanupResult{Deleted: deleted, More: more}, nil
}

func expiredIDs[T any](items map[string]T, limit int, expiry func(T) time.Time, before time.Time) []string {
	if limit == 0 {
		return nil
	}
	ids := make([]string, 0)
	for id, item := range items {
		exp := expiry(item)
		if !exp.IsZero() && !exp.After(before) {
			ids = append(ids, id)
			if len(ids) == limit {
				break
			}
		}
	}
	return ids
}

func hasExpiredMap[T any](items map[string]T, before time.Time, expiry func(T) time.Time) bool {
	for _, item := range items {
		exp := expiry(item)
		if !exp.IsZero() && !exp.After(before) {
			return true
		}
	}
	return false
}

func (*memoryStorage) Migrate(context.Context) error { return nil }

func (m *memoryStorage) ListRefreshSessions(_ context.Context, query storageRefreshSessionQuery) ([]storedRefreshSession, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make([]storedRefreshSession, 0, query.Limit)
	for grantID, session := range m.sessions {
		grant, ok := m.grants[grantID]
		if !ok {
			continue
		}
		if grant.UserID != query.UserID || (query.ClientID != "" && grant.ClientID != query.ClientID) ||
			session.ExpiresAt.UnixMicro() <= query.ActiveAt.UnixMicro() {
			continue
		}
		if query.AfterGrantID != "" {
			lastUsed := session.LastUsedAt.UnixMicro()
			after := query.AfterLastUsed.UnixMicro()
			if lastUsed > after || (lastUsed == after && session.GrantID <= query.AfterGrantID) {
				continue
			}
		}
		listed := cloneRefreshSession(session)
		listed.UserID = grant.UserID
		listed.ClientID = grant.ClientID
		listed.GrantedScopes = slices.Clone(grant.GrantedScopes)
		listed.CreatedAt = grant.GrantedAt
		listed.AuthenticatedAt = authTimeFromGrant(&grant)
		result = append(result, listed)
	}
	sort.Slice(result, func(i, j int) bool {
		left, right := result[i].LastUsedAt.UnixMicro(), result[j].LastUsedAt.UnixMicro()
		if left != right {
			return left > right
		}
		return result[i].GrantID < result[j].GrantID
	})
	return slices.Clip(result[:min(len(result), query.Limit)]), nil
}

func (m *memoryStorage) deleteRef(ref storageRef) {
	switch ref.Kind {
	case storageKindGrant:
		m.deleteGrantChildren(ref.ID)
		delete(m.grants, ref.ID)
	case storageKindAuthCode:
		delete(m.authCodes, ref.ID)
	case storageKindRefreshToken:
		delete(m.refreshTokens, ref.ID)
	case storageKindSession:
		delete(m.sessions, ref.ID)
	}
}

func (m *memoryStorage) deleteGrantChildren(grantID string) {
	for id, code := range m.authCodes {
		if code.GrantID == grantID {
			delete(m.authCodes, id)
		}
	}
	for id, token := range m.refreshTokens {
		if token.GrantID == grantID {
			delete(m.refreshTokens, id)
		}
	}
	delete(m.sessions, grantID)
}

func cloneGrant(grant storedGrant) storedGrant {
	grant.GrantedScopes = slices.Clone(grant.GrantedScopes)
	grant.AMR = slices.Clone(grant.AMR)
	grant.Metadata = bytes.Clone(grant.Metadata)
	grant.EncryptedMetadata = bytes.Clone(grant.EncryptedMetadata)
	grant.AdditionalState = bytes.Clone(grant.AdditionalState)
	grant.Request = cloneAuthRequest(grant.Request)
	return grant
}

func cloneAuthCode(code storedAuthCode) storedAuthCode {
	code.Code = bytes.Clone(code.Code)
	code.EncryptedGrantKey = bytes.Clone(code.EncryptedGrantKey)
	return code
}

func cloneRefreshToken(token storedRefreshToken) storedRefreshToken {
	token.Token = bytes.Clone(token.Token)
	token.EncryptedGrantKey = bytes.Clone(token.EncryptedGrantKey)
	return token
}

func cloneRefreshSession(session storedRefreshSession) storedRefreshSession {
	session.GrantedScopes = slices.Clone(session.GrantedScopes)
	return session
}

func cloneAuthRequest(request *AuthRequest) *AuthRequest {
	if request == nil {
		return nil
	}
	cloned := *request
	cloned.Scopes = slices.Clone(request.Scopes)
	cloned.ACRValues = slices.Clone(request.ACRValues)
	if request.MaxAge != nil {
		maxAge := *request.MaxAge
		cloned.MaxAge = &maxAge
	}
	if request.Raw != nil {
		cloned.Raw = url.Values(maps.Clone(map[string][]string(request.Raw)))
		for key, values := range cloned.Raw {
			cloned.Raw[key] = slices.Clone(values)
		}
	}
	return &cloned
}

func (m *memoryStorage) refreshTokenCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.refreshTokens)
}
