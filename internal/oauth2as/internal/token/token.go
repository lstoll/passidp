package token

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
)

const maxTokenSuffixLength = 256

// Kind identifies one of the OAuth token types supported by this package.
type Kind uint8

const (
	AuthorizationCode Kind = iota + 1
	RefreshToken
)

var errInvalidToken = errors.New("invalid token")

// New creates an opaque token and its hexadecimal SHA-256 storage ID.
func New(kind Kind) (raw string, id string) {
	prefix := tokenPrefix(kind)
	if prefix == "" {
		panic("invalid token kind")
	}
	raw = prefix + rand.Text()
	sum := sha256.Sum256([]byte(raw))
	return raw, hex.EncodeToString(sum[:])
}

// Digest validates a presented token's expected kind and returns its
// hexadecimal SHA-256 storage ID.
func Digest(raw string, expected Kind) (string, error) {
	prefix := tokenPrefix(expected)
	if prefix == "" || len(raw) <= len(prefix) || len(raw)-len(prefix) > maxTokenSuffixLength || raw[:len(prefix)] != prefix {
		return "", errInvalidToken
	}
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:]), nil
}

func tokenPrefix(kind Kind) string {
	switch kind {
	case AuthorizationCode:
		return "pc1_"
	case RefreshToken:
		return "pr1_"
	default:
		return ""
	}
}
