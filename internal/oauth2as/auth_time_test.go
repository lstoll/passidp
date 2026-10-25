package oauth2as

import (
	"testing"
	"time"
)

func TestAuthTimeExceeded(t *testing.T) {
	base := time.Date(2026, 7, 11, 12, 0, 0, 0, time.UTC)

	for _, tc := range []struct {
		Name     string
		AuthTime time.Time
		MaxAge   int
		Now      time.Time
		Want     bool
	}{
		{
			Name:     "max_age zero always exceeded",
			AuthTime: base,
			MaxAge:   0,
			Now:      base.Add(time.Minute),
			Want:     true,
		},
		{
			Name:     "within max_age",
			AuthTime: base,
			MaxAge:   300,
			Now:      base.Add(299 * time.Second),
			Want:     false,
		},
		{
			Name:     "exceeds max_age",
			AuthTime: base,
			MaxAge:   300,
			Now:      base.Add(301 * time.Second),
			Want:     true,
		},
		{
			Name:     "zero auth time requires authentication",
			AuthTime: time.Time{},
			MaxAge:   300,
			Now:      base,
			Want:     true,
		},
		{
			Name:     "negative max_age ignored",
			AuthTime: base.Add(-time.Hour),
			MaxAge:   -1,
			Now:      base,
			Want:     false,
		},
		{
			Name:     "large max_age does not overflow",
			AuthTime: base,
			MaxAge:   int(^uint(0) >> 1),
			Now:      base.Add(24 * time.Hour),
			Want:     false,
		},
	} {
		t.Run(tc.Name, func(t *testing.T) {
			if got := AuthTimeExceeded(tc.AuthTime, tc.MaxAge, tc.Now); got != tc.Want {
				t.Fatalf("AuthTimeExceeded() = %v, want %v", got, tc.Want)
			}
		})
	}
}

func TestMaxAgeFromGrantReturnsCopy(t *testing.T) {
	maxAge := 60
	grant := &storedGrant{Request: &AuthRequest{MaxAge: &maxAge}}
	got := maxAgeFromGrant(grant)
	if got == nil || *got != maxAge {
		t.Fatalf("max age: got %v", got)
	}
	*got = 30
	if *grant.Request.MaxAge != 60 {
		t.Fatal("returned max age aliases stored grant")
	}
}
