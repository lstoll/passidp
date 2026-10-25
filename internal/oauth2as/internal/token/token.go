package token

import (
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"strings"
	"unicode/utf8"
)

const (
	tokenNamespace     = "o2as"
	tokenVersion       = "1"
	secretSize         = 32
	maxTokenLength     = 512
	maxTokenIDSize     = 128
	maxUsageNameSize   = 64
	maxUsagePrefixSize = 16
)

var (
	tokenEncoding   = base64.RawURLEncoding.Strict()
	tokenKDFSaltV1  = []byte("lds.li/oauth2ext/oauth2as/token-kdf/v1")
	errInvalidToken = errors.New("invalid token")
)

type Usage struct {
	// Name is the full name of the usage, included in key derivation.
	Name string
	// Prefix is the short value included in the user-token envelope.
	Prefix string
}

type ParsedToken struct {
	usage  Usage
	id     string
	secret [secretSize]byte
}

// ID returns the record ID used to look up the token in storage.
func (p *ParsedToken) ID() string { return p.id }

// Verify authenticates a parsed token against the stored verifier and binds it
// to its grant and subject.
func (p *ParsedToken) Verify(storedValue []byte, grantID, subject string) (*Token, error) {
	if p == nil || len(storedValue) != sha256.Size {
		return nil, errInvalidToken
	}
	stored, kek, context, err := deriveTokenMaterial(p.secret, p.usage, p.id, grantID, subject)
	if err != nil {
		return nil, fmt.Errorf("deriving token material: %w", err)
	}
	if subtle.ConstantTimeCompare(stored[:], storedValue) != 1 {
		return nil, errInvalidToken
	}
	return &Token{
		usage:   p.usage,
		id:      p.id,
		secret:  p.secret,
		stored:  stored,
		kek:     kek,
		context: context,
	}, nil
}

// Token is an authenticated opaque authorization code or refresh token.
type Token struct {
	usage  Usage
	id     string
	secret [secretSize]byte
	stored [sha256.Size]byte
	kek    [32]byte

	// context is the canonical usage/token/grant/subject binding used as AEAD
	// associated data when wrapping a grant key.
	context []byte
}

// New generates a token bound to its storage record, grant, and subject.
func New(usage Usage, tokenID, grantID, subject string) (Token, error) {
	if err := validateUsage(usage); err != nil {
		return Token{}, err
	}
	if err := validateTokenID(tokenID); err != nil {
		return Token{}, err
	}
	var secret [secretSize]byte
	if _, err := rand.Read(secret[:]); err != nil {
		return Token{}, fmt.Errorf("generating token secret: %w", err)
	}
	stored, kek, context, err := deriveTokenMaterial(secret, usage, tokenID, grantID, subject)
	if err != nil {
		return Token{}, fmt.Errorf("deriving token material: %w", err)
	}
	return Token{
		usage:   usage,
		id:      tokenID,
		secret:  secret,
		stored:  stored,
		kek:     kek,
		context: context,
	}, nil
}

// UserToken returns the value presented to the OAuth client. Token deliberately
// does not implement fmt.Stringer to reduce accidental secret logging.
func (t *Token) UserToken() string {
	if t == nil {
		return ""
	}
	return strings.Join([]string{
		tokenNamespace,
		t.usage.Prefix,
		tokenVersion,
		tokenEncoding.EncodeToString([]byte(t.id)),
		tokenEncoding.EncodeToString(t.secret[:]),
	}, ".")
}

// ID returns the token's storage record ID.
func (t *Token) ID() string {
	if t == nil {
		return ""
	}
	return t.id
}

// Stored returns the verifier stored with the token record.
func (t *Token) Stored() []byte {
	if t == nil {
		return nil
	}
	return append([]byte(nil), t.stored[:]...)
}

// ParseUserToken parses the versioned public envelope. Errors are deliberately
// generic because callers handle untrusted token input.
func ParseUserToken(userToken string, expected Usage) (*ParsedToken, error) {
	if len(userToken) == 0 || len(userToken) > maxTokenLength || validateUsage(expected) != nil {
		return nil, errInvalidToken
	}
	parts := strings.Split(userToken, ".")
	if len(parts) != 5 || parts[0] != tokenNamespace || parts[1] != expected.Prefix || parts[2] != tokenVersion {
		return nil, errInvalidToken
	}
	id, err := tokenEncoding.DecodeString(parts[3])
	if err != nil || len(id) == 0 || len(id) > maxTokenIDSize || !utf8.Valid(id) || tokenEncoding.EncodeToString(id) != parts[3] {
		return nil, errInvalidToken
	}
	secret, err := tokenEncoding.DecodeString(parts[4])
	if err != nil || len(secret) != secretSize || tokenEncoding.EncodeToString(secret) != parts[4] {
		return nil, errInvalidToken
	}
	parsed := &ParsedToken{usage: expected, id: string(id)}
	copy(parsed.secret[:], secret)
	clear(secret)
	return parsed, nil
}

func deriveTokenMaterial(secret [secretSize]byte, usage Usage, tokenID, grantID, subject string) (stored, kek [32]byte, context []byte, err error) {
	context, err = encodeContext("token-binding", tokenVersion, usage.Name, usage.Prefix, tokenID, grantID, subject)
	if err != nil {
		return stored, kek, nil, err
	}
	storedInfo, err := encodeContext("stored-verifier", string(context))
	if err != nil {
		return stored, kek, nil, err
	}
	kekInfo, err := encodeContext("grant-key-encryption", string(context))
	if err != nil {
		return stored, kek, nil, err
	}
	derived, err := hkdf.Key(sha256.New, secret[:], tokenKDFSaltV1, string(storedInfo), len(stored))
	if err != nil {
		return stored, kek, nil, err
	}
	copy(stored[:], derived)
	clear(derived)
	derived, err = hkdf.Key(sha256.New, secret[:], tokenKDFSaltV1, string(kekInfo), len(kek))
	if err != nil {
		return stored, kek, nil, err
	}
	copy(kek[:], derived)
	clear(derived)
	return stored, kek, context, nil
}

func validateUsage(usage Usage) error {
	if usage.Name == "" || len(usage.Name) > maxUsageNameSize {
		return fmt.Errorf("token usage name must be between 1 and %d bytes", maxUsageNameSize)
	}
	if usage.Prefix == "" || len(usage.Prefix) > maxUsagePrefixSize || !isTokenPrefix(usage.Prefix) {
		return fmt.Errorf("token usage prefix must be between 1 and %d URL-safe ASCII characters", maxUsagePrefixSize)
	}
	return nil
}

func isTokenPrefix(prefix string) bool {
	for _, char := range []byte(prefix) {
		if (char < 'a' || char > 'z') && (char < 'A' || char > 'Z') && (char < '0' || char > '9') && char != '-' && char != '_' {
			return false
		}
	}
	return true
}

func validateTokenID(tokenID string) error {
	if tokenID == "" || len(tokenID) > maxTokenIDSize || !utf8.ValidString(tokenID) {
		return fmt.Errorf("token ID must be valid UTF-8 between 1 and %d bytes", maxTokenIDSize)
	}
	return nil
}

// encodeContext provides an unambiguous encoding for cryptographic domain and
// record bindings. Values are uint32-length-prefixed UTF-8 byte strings.
func encodeContext(fields ...string) ([]byte, error) {
	size := 0
	for _, field := range fields {
		if uint64(len(field)) > math.MaxUint32 {
			return nil, fmt.Errorf("context field is too large")
		}
		if size > math.MaxInt-4-len(field) {
			return nil, fmt.Errorf("context is too large")
		}
		size += 4 + len(field)
	}
	result := make([]byte, 0, size)
	for _, field := range fields {
		result = binary.BigEndian.AppendUint32(result, uint32(len(field)))
		result = append(result, field...)
	}
	return result, nil
}
