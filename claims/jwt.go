package claims

import "github.com/tink-crypto/tink-go/v2/jwt"

func JWTOptsFromIDClaims(claims *IDClaims) *jwt.RawJWTOptions {
	cc := map[string]any{}
	if claims.HasEmail() {
		cc["email"] = claims.GetEmail()
	}
	if claims.HasEmailVerified() {
		cc["email_verified"] = claims.GetEmailVerified()
	}
	if claims.HasPicture() {
		cc["picture"] = claims.GetPicture()
	}
	if claims.HasName() {
		cc["name"] = claims.GetName()
	}
	if len(claims.GetGroups()) > 0 {
		cc["groups"] = sliceToAny(claims.GetGroups())
	}
	if claims.HasPreferredUsername() {
		cc["preferred_username"] = claims.GetPreferredUsername()
	}

	o := &jwt.RawJWTOptions{}
	if len(cc) > 0 {
		o.CustomClaims = cc
	}
	if claims.HasSubject() {
		o.Subject = new(claims.GetSubject())
	}

	return o
}

func sliceToAny[T any](s []T) []any {
	a := make([]any, len(s))
	for i, v := range s {
		a[i] = v
	}
	return a
}
