package config

import (
	"fmt"

	"github.com/google/uuid"
)

// note : `uuidgen | tr '[:upper:]' '[:lower:]'` can be used on macOS to generate a UUID.

// User represent a user of the system.
type User struct {
	// ID is the users unique ID, must be a UUID.
	ID uuid.UUID `json:"id,omitzero"`
	// Email is the users email address. Used for email, and the profile pic
	// from gravatar.
	Email string `json:"email,omitzero"`
	// FullName is the users full name.
	FullName string `json:"fullName,omitzero"`
	// OverrideSubject is the subject to use for the user, if the client is
	// requesting an override subject.
	OverrideSubject string `json:"overrideSubject,omitzero"`
	// WebauthnHandle is the users webauthn handle. Should be a UUIDv4, that
	// differs from the users ID.
	WebauthnHandle uuid.UUID `json:"webauthnHandle,omitzero"`
	// Groups is a list of group names that a user is a member of.
	Groups []string `json:"groups,omitzero"`

	// EnrollmentKey is a key that can be used to enroll a user. THIS SHOULD NOT
	// BE SET OUTSIDE THE E2E TESTS. It will be replaced with a better model in
	// the near future.
	EnrollmentKey string `json:"-"`
}

// TODO(lstoll) - make a value ref in future when enrollment doesnt need to
// mutate in place.

type Users []*User

func (u Users) GetUser(id uuid.UUID) (*User, error) {
	for _, user := range u {
		if user.ID == id {
			return user, nil
		}
	}
	return nil, fmt.Errorf("user %s not found", id)
}

func (u Users) GetUserByStringID(id string) (*User, error) {
	uuid, err := uuid.Parse(id)
	if err != nil {
		return nil, fmt.Errorf("parse user id: %w", err)
	}
	for _, user := range u {
		if user.ID == uuid {
			return user, nil
		}
	}
	return nil, fmt.Errorf("user %s not found", id)
}

func (u Users) GetUserByWebauthnHandle(handle uuid.UUID) (*User, error) {
	for _, user := range u {
		if user.WebauthnHandle == handle {
			return user, nil
		}
	}
	return nil, fmt.Errorf("user with webauthn handle %s not found", handle)
}
