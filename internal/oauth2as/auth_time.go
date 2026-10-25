package oauth2as

import "time"

// AuthTimeExceeded reports whether authenticatedAt is older than maxAge seconds
// relative to now. Per OIDC, max_age=0 always requires re-authentication. If
// authenticatedAt is unknown, this returns true so callers fail closed. A
// negative maxAge is invalid and returns false.
func AuthTimeExceeded(authenticatedAt time.Time, maxAge int, now time.Time) bool {
	if maxAge < 0 {
		return false
	}
	if maxAge == 0 {
		return true
	}
	if authenticatedAt.IsZero() {
		return true
	}
	if int64(maxAge) > int64(time.Duration(1<<63-1)/time.Second) {
		return false
	}
	return now.Sub(authenticatedAt) > time.Duration(maxAge)*time.Second
}

func authTimeFromGrant(grant *storedGrant) time.Time {
	if grant == nil {
		return time.Time{}
	}
	if !grant.AuthenticatedAt.IsZero() {
		return grant.AuthenticatedAt
	}
	return grant.GrantedAt
}

func maxAgeFromGrant(grant *storedGrant) *int {
	if grant == nil || grant.Request == nil {
		return nil
	}
	if grant.Request.MaxAge == nil {
		return nil
	}
	return new(*grant.Request.MaxAge)
}
