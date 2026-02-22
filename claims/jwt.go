package claims

import (
	"errors"
	"fmt"

	"github.com/tink-crypto/tink-go/v2/jwt"
	"golang.org/x/oauth2"
	"lds.li/oauth2ext/claims"
)

func RawJWTOptsFromIDClaims(claims *IDClaims) *jwt.RawJWTOptions {
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

type VerifiedIDClaims struct {
	cl *IDClaims
}

func (v *VerifiedIDClaims) Claims() (*IDClaims, error) {
	// TODO - this is pretty weak. consumers are just going to pass the claims
	// around, defeatung the purpose of a special verified claims type. we
	// should consider how to make this better, maybe need to generate the type
	// or something.
	if v.cl == nil {
		return nil, errors.New("no claims")
	}
	return v.cl, nil
}

func verifiedIDClaimsFromJWT(v *jwt.VerifiedJWT) (*VerifiedIDClaims, error) {
	cb := IDClaims_builder{}
	if v.HasSubject() {
		sub, err := v.Subject()
		if err != nil {
			return nil, err
		}
		cb.Subject = &sub
	}
	if v.HasStringClaim("email") {
		s, err := v.StringClaim("email")
		if err != nil {
			return nil, err
		}
		cb.Email = &s
	}
	if v.HasBooleanClaim("email_verified") {
		b, err := v.BooleanClaim("email_verified")
		if err != nil {
			return nil, err
		}
		cb.EmailVerified = &b
	}
	if v.HasStringClaim("picture") {
		s, err := v.StringClaim("picture")
		if err != nil {
			return nil, err
		}
		cb.Picture = &s
	}
	if v.HasStringClaim("name") {
		s, err := v.StringClaim("name")
		if err != nil {
			return nil, err
		}
		cb.Name = &s
	}
	if v.HasArrayClaim("groups") {
		arr, err := v.ArrayClaim("groups")
		if err != nil {
			return nil, err
		}
		groups := make([]string, len(arr))
		for i, e := range arr {
			s, ok := e.(string)
			if !ok {
				return nil, fmt.Errorf("claims: groups[%d] is not a string", i)
			}
			groups[i] = s
		}
		cb.Groups = groups
	}
	if v.HasStringClaim("preferred_username") {
		s, err := v.StringClaim("preferred_username")
		if err != nil {
			return nil, err
		}
		cb.PreferredUsername = &s
	}
	return &VerifiedIDClaims{cl: cb.Build()}, nil
}

var _ claims.Validator[*VerifiedIDClaims] = (*Validator)(nil)

type Validator struct {
	provider claims.Provider
	opts     *ValidatorOpts
}

type ValidatorOpts struct {
	// TODO - app specific options here?
}

func NewValidator(provider claims.Provider, opts *ValidatorOpts) *Validator {
	return &Validator{provider: provider, opts: opts}
}

// ValidatorOpts returns the basic tink validator options that will be used to
// validate the JWT initially. The issuer will always be overridden by the
// provider's issuer.
func (v *Validator) ValidatorOpts() *jwt.ValidatorOpts {
	issuer := v.provider.Issuer()
	return &jwt.ValidatorOpts{
		ExpectedIssuer: &issuer,
	}
}

// Validate is passed the verified JWT and can perform additional checks,
// before returning the claims type.
func (v *Validator) Validate(jwt *jwt.VerifiedJWT) (*VerifiedIDClaims, error) {
	return verifiedIDClaimsFromJWT(jwt)
}

// CompactFromToken is used to extract the compact JWT from the OAuth2 token.
func (v *Validator) CompactFromToken(token oauth2.Token) (string, error) {
	return token.Extra("id_token").(string), nil
}

func sliceToAny[T any](s []T) []any {
	a := make([]any, len(s))
	for i, v := range s {
		a[i] = v
	}
	return a
}
