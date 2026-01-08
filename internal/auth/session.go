package auth

import (
	"context"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
	"lds.li/web/session"
)

const (
	authSessSessionKey = "auth-sess"
	authFlowValidFor   = 10 * time.Minute
)

// authSess is the session data for authentication
type authSess struct {
	LoggedinUserID uuid.NullUUID
	ExpiresAt      time.Time
	Flows          map[string]authSessFlow
}

type authSessFlow struct {
	ID       string
	ReturnTo string
	// WebauthnData is the data for the webauthn login, for this flow.
	WebauthnData *webauthn.SessionData
	StartedAt    time.Time
}

// UserIDFromContext returns the logged in user from the session accessible in
// the context.
func UserIDFromContext(ctx context.Context) (*uuid.UUID, bool) {
	sess := session.MustFromContext(ctx)
	as, ok := sess.Get(authSessSessionKey).(*authSess)
	if !ok {
		return nil, false
	}
	if !as.LoggedinUserID.Valid {
		return nil, false
	}
	if time.Now().After(as.ExpiresAt) {
		return nil, false
	}
	return &as.LoggedinUserID.UUID, as.LoggedinUserID.Valid
}
