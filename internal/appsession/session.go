// Package appsession defines the complete typed browser-session payload.
package appsession

import (
	"context"
	"net/http"
	"time"
	"uuid"

	"lds.li/passidp/internal/oauth2as"
	"lds.li/session"
)

type Data struct {
	Auth         Auth                            `json:"auth,omitzero"`
	Enrollment   *Enrollment                     `json:"enrollment,omitzero"`
	AuthRequests map[string]oauth2as.AuthRequest `json:"authRequests,omitzero"`
}

type Auth struct {
	LoggedInUserID  *uuid.UUID          `json:"loggedInUserId,omitzero"`
	AuthenticatedAt time.Time           `json:"authenticatedAt,omitzero"`
	ExpiresAt       time.Time           `json:"expiresAt,omitzero"`
	Flows           map[string]AuthFlow `json:"flows,omitzero"`
}

type AuthFlow struct {
	ReturnTo       string    `json:"returnTo,omitzero"`
	PasskeyRequest []byte    `json:"passkeyRequest,omitzero"`
	StartedAt      time.Time `json:"startedAt,omitzero"`
}

type Enrollment struct {
	ForUserID    string `json:"forUserId,omitzero"`
	EnrollmentID string `json:"enrollmentId,omitzero"`
	KeyName      string `json:"keyName,omitzero"`
	ReturnTo     string `json:"returnTo,omitzero"`
}

type contextKey struct{}

// Bind exposes the typed session through this package after the upstream
// manager has attached it to the request context.
func Bind(manager *session.Manager[Data]) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			sess := manager.FromContext(r.Context())
			ctx := context.WithValue(r.Context(), contextKey{}, sess)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func FromContext(ctx context.Context) *session.Session[Data] {
	sess, ok := ctx.Value(contextKey{}).(*session.Session[Data])
	if !ok {
		panic("appsession: no session in context")
	}
	return sess
}

// WithManagerContext exposes a manager-owned session through this package.
// It is primarily useful with sessiontest.WithSession.
func WithManagerContext(ctx context.Context, manager *session.Manager[Data]) context.Context {
	return context.WithValue(ctx, contextKey{}, manager.FromContext(ctx))
}
