package oidcsvr

import (
	"slices"

	"lds.li/passidp/internal/config"
	"lds.li/passidp/internal/oauth2as"
)

func defaultIDTokenClaims(user *config.User) map[string]any {
	claims := map[string]any{
		"email":          user.Email,
		"email_verified": true,
		"picture":        gravatarURL(user.Email),
		"name":           user.FullName,
	}
	if len(user.Groups) > 0 {
		claims["groups"] = slices.Clone(user.Groups)
	}
	if user.PreferredUsername != "" {
		claims["preferred_username"] = user.PreferredUsername
	}
	return claims
}

// idTokenClaimsFromMap maps policy-facing JSON claims into the
// application-owned portion of an oauth2ext ID token. oauth2ext constructs and
// validates all protocol claims itself. "sub" is lifted onto Subject; remaining
// non-null entries go into Additional.
func idTokenClaimsFromMap(claims map[string]any) *oauth2as.IDTokenClaims {
	result := &oauth2as.IDTokenClaims{Additional: map[string]any{}}
	for k, v := range claims {
		if v == nil {
			continue
		}
		if k == "sub" {
			if s, ok := v.(string); ok {
				result.Subject = s
			}
			continue
		}
		result.Additional[k] = v
	}
	return result
}
