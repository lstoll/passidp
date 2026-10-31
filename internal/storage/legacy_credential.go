package storage

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"uuid"
)

// legacyWebAuthnCredential is the JSON shape of a go-webauthn Credential.
type legacyWebAuthnCredential struct {
	ID        []byte   `json:"id"`
	PublicKey []byte   `json:"publicKey"`
	Transport []string `json:"transport"`
	Flags     struct {
		UserPresent    bool `json:"userPresent"`
		UserVerified   bool `json:"userVerified"`
		BackupEligible bool `json:"backupEligible"`
		BackupState    bool `json:"backupState"`
	} `json:"flags"`
	Authenticator struct {
		AAGUID    []byte `json:"AAGUID"`
		SignCount uint32 `json:"signCount"`
	} `json:"authenticator"`
	Attestation struct {
		AuthenticatorData []byte `json:"authenticatorData"`
		Object            []byte `json:"object"`
	} `json:"attestation"`
}

const (
	authDataFlagUP = 1 << 0
	authDataFlagUV = 1 << 2
	authDataFlagBE = 1 << 3
	authDataFlagBS = 1 << 4
	authDataFlagAT = 1 << 6
)

// ImportLegacyCredentials converts go-webauthn credential blobs into C2SP
// passkey records. Converted entries are removed from Credentials.
// Blobs that cannot be converted are left in place.
func (cs *CredentialStore) ImportLegacyCredentials(rpID string) {
	if len(cs.Credentials) == 0 {
		return
	}
	kept := make([]*Credential, 0, len(cs.Credentials))
	for _, cred := range cs.Credentials {
		if cred == nil {
			continue
		}
		if cs.hasPasskeyID(cred.ID) {
			continue
		}
		record, err := PasskeyRecordFromLegacyCredential(cred, rpID)
		if err != nil {
			kept = append(kept, cred)
			continue
		}
		if cs.hasPasskeyRecord(cred.UserID, record) {
			continue
		}
		cs.AddPasskey(cred.UserID, nil, &Passkey{
			ID:        cred.ID,
			Record:    record,
			Name:      cred.Name,
			CreatedAt: cred.CreatedAt,
		})
	}
	if len(kept) == 0 {
		cs.Credentials = nil
		return
	}
	cs.Credentials = kept
}

func (cs *CredentialStore) hasPasskeyID(id uuid.UUID) bool {
	if id == uuid.Nil() {
		return false
	}
	for _, user := range cs.Users {
		for _, passkey := range user.Passkeys {
			if passkey.ID == id {
				return true
			}
		}
	}
	return false
}

func (cs *CredentialStore) hasPasskeyRecord(accountID uuid.UUID, record string) bool {
	user := cs.passkeyUser(accountID)
	if user == nil {
		return false
	}
	for _, passkey := range user.Passkeys {
		if passkey.Record == record {
			return true
		}
	}
	return false
}

// PasskeyRecordFromLegacyCredential builds a C2SP passkey record from a
// stored go-webauthn credential. rpID is used only when synthesizing
// authenticator data from decomposed fields.
func PasskeyRecordFromLegacyCredential(cred *Credential, rpID string) (string, error) {
	if cred == nil || len(cred.CredentialData) == 0 || string(cred.CredentialData) == "null" {
		return "", fmt.Errorf("missing credential data")
	}
	var blob legacyWebAuthnCredential
	if err := json.Unmarshal(cred.CredentialData, &blob); err != nil {
		return "", fmt.Errorf("decode credential data: %w", err)
	}
	if len(blob.ID) == 0 {
		blob.ID = slices.Clone(cred.CredentialID)
	}

	authData, err := legacyRegistrationAuthData(&blob, rpID)
	if err != nil {
		return "", err
	}
	if err := checkRegistrationAuthData(authData); err != nil {
		return "", err
	}
	return encodePasskeyRecord(authData, blob.Transport), nil
}

func legacyRegistrationAuthData(blob *legacyWebAuthnCredential, rpID string) ([]byte, error) {
	if len(blob.Attestation.AuthenticatorData) > 0 {
		return blob.Attestation.AuthenticatorData, nil
	}
	if len(blob.Attestation.Object) > 0 {
		ad, err := attestationObjectAuthData(blob.Attestation.Object)
		if err == nil && len(ad) > 0 {
			return ad, nil
		}
	}
	return synthesizeRegistrationAuthData(blob, rpID)
}

func synthesizeRegistrationAuthData(blob *legacyWebAuthnCredential, rpID string) ([]byte, error) {
	if rpID == "" {
		return nil, fmt.Errorf("credential is missing registration authenticator data")
	}
	if len(blob.ID) < 16 || len(blob.ID) > 1023 {
		return nil, fmt.Errorf("credential ID is %d bytes, expected between 16 and 1023", len(blob.ID))
	}
	if len(blob.PublicKey) == 0 {
		return nil, fmt.Errorf("credential is missing public key")
	}

	var flags byte = authDataFlagAT
	if blob.Flags.UserPresent {
		flags |= authDataFlagUP
	}
	if blob.Flags.UserVerified {
		flags |= authDataFlagUV
	}
	if blob.Flags.BackupEligible {
		flags |= authDataFlagBE
	}
	if blob.Flags.BackupState && blob.Flags.BackupEligible {
		flags |= authDataFlagBS
	}
	// Older go-webauthn blobs (notably security keys) stored all-zero
	// flags even after successful UV logins. Treat a blank flags struct
	// as unknown and assume UP+UV, which this IdP required at login.
	if flags == authDataFlagAT {
		flags |= authDataFlagUP | authDataFlagUV
	}

	rpIDHash := sha256.Sum256([]byte(rpID))
	var aaguid [16]byte
	copy(aaguid[:], blob.Authenticator.AAGUID)

	ad := make([]byte, 0, 37+16+2+len(blob.ID)+len(blob.PublicKey))
	ad = append(ad, rpIDHash[:]...)
	ad = append(ad, flags)
	ad = binary.BigEndian.AppendUint32(ad, blob.Authenticator.SignCount)
	ad = append(ad, aaguid[:]...)
	ad = binary.BigEndian.AppendUint16(ad, uint16(len(blob.ID)))
	ad = append(ad, blob.ID...)
	ad = append(ad, blob.PublicKey...)
	return ad, nil
}

func checkRegistrationAuthData(ad []byte) error {
	if len(ad) < 55 {
		return fmt.Errorf("authenticator data is %d bytes, expected at least 55", len(ad))
	}
	if ad[32]&authDataFlagAT == 0 {
		return fmt.Errorf("authenticator data is not from registration")
	}
	return nil
}

func encodePasskeyRecord(authData []byte, transports []string) string {
	var b strings.Builder
	b.WriteString("$webauthn$v=1$")
	if param, ok := transportsParam(transports); ok {
		b.WriteString("transports=")
		b.WriteString(param)
		b.WriteByte('$')
	}
	b.WriteString(base64.RawStdEncoding.EncodeToString(authData))
	return b.String()
}

func transportsParam(transports []string) (string, bool) {
	names := make([]string, 0, len(transports))
	seen := make(map[string]struct{}, len(transports))
	for _, name := range transports {
		if name == "" || !transportNameOK(name) {
			return "", false
		}
		if _, dup := seen[name]; dup {
			continue
		}
		seen[name] = struct{}{}
		names = append(names, name)
	}
	if len(names) == 0 {
		return "", false
	}
	slices.Sort(names)
	return strings.Join(names, "+"), true
}

func transportNameOK(name string) bool {
	if len(name) > 32 {
		return false
	}
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '/' || r == '.' || r == '-':
		default:
			return false
		}
	}
	return true
}

// attestationObjectAuthData returns the authData member of a CTAP2 CBOR
// attestation object.
func attestationObjectAuthData(b []byte) ([]byte, error) {
	s := cborString(b)
	var pairs uint16
	if !s.readMapHeader(&pairs) {
		return nil, fmt.Errorf("parse attestation object: bad map header")
	}
	var authData []byte
	var found bool
	for range pairs {
		var key string
		if !s.readString(&key) {
			return nil, fmt.Errorf("parse attestation object: bad map key")
		}
		if key != "authData" {
			if !s.skip() {
				return nil, fmt.Errorf("parse attestation object: bad %q value", key)
			}
			continue
		}
		if found {
			return nil, fmt.Errorf("parse attestation object: duplicate authData")
		}
		if !s.readBytes(&authData) {
			return nil, fmt.Errorf("parse attestation object: bad authData")
		}
		found = true
	}
	if !found {
		return nil, fmt.Errorf("parse attestation object: no authData")
	}
	if len(s) != 0 {
		return nil, fmt.Errorf("parse attestation object: %d unexpected trailing bytes", len(s))
	}
	return authData, nil
}

// cborString is a tiny CTAP2 CBOR reader for attestation objects.
type cborString []byte

func (s *cborString) readTypeAndArgument() (major uint8, arg uint16, ok bool) {
	if len(*s) < 1 {
		return
	}
	major = (*s)[0] >> 5
	minor := (*s)[0] & 0x1f
	switch {
	case minor <= 23:
		arg = uint16(minor)
		*s = (*s)[1:]
	case minor == 24:
		if len(*s) < 2 {
			return
		}
		arg = uint16((*s)[1])
		if arg <= 23 {
			return
		}
		*s = (*s)[2:]
	case minor == 25:
		if len(*s) < 3 {
			return
		}
		arg = binary.BigEndian.Uint16((*s)[1:])
		if arg <= 0xff {
			return
		}
		*s = (*s)[3:]
	default:
		return
	}
	ok = true
	return
}

func (s *cborString) readBytes(out *[]byte) bool {
	major, arg, ok := s.readTypeAndArgument()
	if !ok || major != 2 {
		return false
	}
	if len(*s) < int(arg) {
		return false
	}
	*out = (*s)[:arg]
	*s = (*s)[arg:]
	return true
}

func (s *cborString) readString(out *string) bool {
	major, arg, ok := s.readTypeAndArgument()
	if !ok || major != 3 {
		return false
	}
	if len(*s) < int(arg) {
		return false
	}
	*out = string((*s)[:arg])
	*s = (*s)[arg:]
	return true
}

func (s *cborString) readMapHeader(out *uint16) bool {
	major, arg, ok := s.readTypeAndArgument()
	if !ok || major != 5 {
		return false
	}
	*out = arg
	return true
}

func (s *cborString) skip() bool {
	return s.skipN(8)
}

func (s *cborString) skipN(depth int) bool {
	major, arg, ok := s.readTypeAndArgument()
	if !ok {
		return false
	}
	switch major {
	case 0, 1:
		return true
	case 2, 3:
		if len(*s) < int(arg) {
			return false
		}
		*s = (*s)[arg:]
		return true
	case 4, 5:
		if depth == 0 {
			return false
		}
		items := int(arg)
		if major == 5 {
			items *= 2
		}
		for range items {
			if !s.skipN(depth - 1) {
				return false
			}
		}
		return true
	default:
		return false
	}
}
