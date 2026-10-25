package oidcsvr

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"lds.li/passidp/internal/oauth2as/oauth2proto"
	"lds.li/web"
)

func TestWriteOAuth2ProtoError(t *testing.T) {
	t.Run("auth error redirects", func(t *testing.T) {
		rw := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/authorization", nil)
		br := web.NewRequestFrom(req)
		w := web.NewResponseWriter(rw)

		err := &oauth2proto.AuthError{
			State:       "state-123",
			Code:        oauth2proto.AuthErrorCodeAccessDenied,
			Description: "not allowed",
			RedirectURI: "https://client.example/callback",
		}
		if got := writeOAuth2ProtoError(w, br, err); got != nil {
			t.Fatalf("writeOAuth2ProtoError() = %v, want nil", got)
		}
		if rw.Code != http.StatusFound {
			t.Fatalf("status = %d, want %d", rw.Code, http.StatusFound)
		}

		loc := rw.Header().Get("Location")
		u, perr := url.Parse(loc)
		if perr != nil {
			t.Fatalf("parse location: %v", perr)
		}
		q := u.Query()
		if q.Get("error") != string(oauth2proto.AuthErrorCodeAccessDenied) {
			t.Fatalf("error = %q", q.Get("error"))
		}
		if q.Get("error_description") != "not allowed" {
			t.Fatalf("error_description = %q", q.Get("error_description"))
		}
		if q.Get("state") != "state-123" {
			t.Fatalf("state = %q", q.Get("state"))
		}
	})

	t.Run("non-auth error passes through", func(t *testing.T) {
		rw := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/authorization", nil)
		br := web.NewRequestFrom(req)
		w := web.NewResponseWriter(rw)

		in := errTestPassThrough{}
		got := writeOAuth2ProtoError(w, br, in)
		if got != in {
			t.Fatalf("expected same error back, got %v", got)
		}
	})
}

type errTestPassThrough struct{}

func (errTestPassThrough) Error() string { return "pass through" }
