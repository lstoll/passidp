package storage

import (
	"errors"
	"fmt"
	"io/fs"
	"time"

	"crawshaw.dev/jsonfile"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
)

// CredentialStore represents the on-disk store for webauthn credentials.
type CredentialStore struct {
	Credentials []*Credential `json:"credentials,omitzero"`
}

// Credential is an individual webauthn credential stored in the database.
type Credential struct {
	// ID is a unique identifier for this credential.
	ID uuid.UUID `json:"id,omitzero"`
	// CredentialID is the ID for the credential, opaque bytes from go-webauthn
	// credential data.
	CredentialID []byte `json:"credential_id,omitzero"`
	// UserID is the ID of the user this credential is associated with.
	UserID uuid.UUID `json:"user_id,omitzero"`
	// Name is the name of the credential.
	Name string `json:"name,omitzero"`
	// CredentialData is the credential data from go-webauthn
	CredentialData *webauthn.Credential `json:"credential_data,omitzero"`
	// CreatedAt is the time the credential was created.
	CreatedAt time.Time `json:"created_at,omitzero"`
}

// OpenCredentialStore opens an existing credential store at the given path. If
// the file does not exist, it will return an error.
func OpenCredentialStore(path string) (*jsonfile.JSONFile[CredentialStore], error) {
	s, err := jsonfile.Load[CredentialStore](path)
	if err != nil {
		return nil, fmt.Errorf("load credential store from %s: %w", path, err)
	}
	return s, nil
}

// NewCredentialStore creates a new credential store at the given path. If the
// file does not exist, it will be created. If the file exists, it will be
// loaded.
func NewCredentialStore(path string) (*jsonfile.JSONFile[CredentialStore], error) {
	s, err := jsonfile.Load[CredentialStore](path)
	if errors.Is(err, fs.ErrNotExist) {
		s, err = jsonfile.New[CredentialStore](path)
		if err != nil {
			return nil, fmt.Errorf("create credential store: %w", err)
		}
		return s, nil
	} else if err != nil {
		return nil, fmt.Errorf("load credential store from %s: %w", path, err)
	}
	return s, nil
}
