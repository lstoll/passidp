package auth

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
	"lds.li/webauthn-oidc-idp/internal/config"
)

type WebAuthnUser struct {
	user *config.User
	// overrideID is the ID used for the webauthn user, if it differs from the
	// user's webauthn handle. This is used to handle credentials make before we
	// set an explicit webauthn handle per-user.
	overrideID  []byte
	credentials []webauthn.Credential
}

// NewWebAuthnUser creates a new WebAuthnUser for registration (without credentials)
func NewWebAuthnUser(user *config.User) *WebAuthnUser {
	return &WebAuthnUser{
		user: user,
	}
}

func (u *WebAuthnUser) WebAuthnID() []byte {
	if len(u.overrideID) > 0 {
		return u.overrideID
	}
	return u.user.WebauthnHandle[:]
}

func (u *WebAuthnUser) WebAuthnName() string {
	return u.user.Email
}

func (u *WebAuthnUser) WebAuthnDisplayName() string {
	return u.user.FullName
}

func (u *WebAuthnUser) WebAuthnIcon() string {
	return ""
}

func (u *WebAuthnUser) WebAuthnCredentials() []webauthn.Credential {
	return u.credentials
}

func (a *Authenticator) NewDiscoverableUserHandler(ctx context.Context) webauthn.DiscoverableUserHandler {
	return func(rawID, userHandle []byte) (user webauthn.User, err error) {
		var cfgUser *config.User
		var validateID []byte

		// this handles a variety of userHandle formats, that we've used over
		// time. if we ever clean things up it would be nice to remove some of
		// the fallbacks.

		// If the userHandle is a valid UUID4 in bytes, use it directly. This is
		// our "current" approach.
		if len(userHandle) == 16 && ((userHandle[6]&0xf0)>>4) == 4 {
			// it's a UUID4/7, likely the distinct webauthn handle
			handle, err := uuid.FromBytes(userHandle)
			if err != nil {
				return nil, fmt.Errorf("invalid UUIDv4: %w", err)
			}
			cfgUser, err = a.Config.Users.GetUserByWebauthnHandle(handle)
			if err != nil {
				return nil, fmt.Errorf("getting user by webauthn handle: %w", err)
			}
		} else if err := uuid.Validate(string(userHandle)); err == nil {
			// string UUID, likely the user ID
			cfgUser, err = a.Config.Users.GetUserByStringID(string(userHandle))
			if err != nil {
				return nil, fmt.Errorf("getting user by string ID: %w", err)
			}
			validateID = []byte(cfgUser.ID.String())
		} else {
			// process it as a fallback subject. This matches the earliest
			// credentials we issued against this software.
			for _, u := range a.Config.Users {
				if u.OverrideSubject == string(userHandle) {
					cfgUser = u
					break
				}
			}
			if cfgUser == nil {
				return nil, fmt.Errorf("user not found")
			}
			validateID = []byte(cfgUser.OverrideSubject)
		}

		// Get user credentials
		creds, err := a.Queries.GetUserCredentials(ctx, cfgUser.ID)
		if err != nil {
			return nil, fmt.Errorf("getting user credentials: %w", err)
		}

		wu := &WebAuthnUser{
			user:       cfgUser,
			overrideID: validateID,
		}
		for _, c := range creds {
			var cred webauthn.Credential
			if err := json.Unmarshal(c.CredentialData, &cred); err != nil {
				return nil, fmt.Errorf("unmarshalling credential: %w", err)
			}
			wu.credentials = append(wu.credentials, cred)
		}

		return wu, nil
	}
}
