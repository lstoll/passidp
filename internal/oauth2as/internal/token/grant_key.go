package token

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
)

const (
	grantKeySize        = 32
	aeadAlgorithmAESGCM = 1
)

var (
	metadataEnvelopeHeader = []byte{'o', '2', 'm', 1, aeadAlgorithmAESGCM}
	grantKeyEnvelopeHeader = []byte{'o', '2', 'k', 1, aeadAlgorithmAESGCM}
	errInvalidCiphertext   = errors.New("invalid ciphertext")
)

// GrantKey is the AES-256 data-encryption key for one grant's metadata.
type GrantKey struct {
	key [grantKeySize]byte
}

// GenerateGrantKey creates a new random grant data-encryption key.
func GenerateGrantKey() (*GrantKey, error) {
	key := new(GrantKey)
	if _, err := rand.Read(key.key[:]); err != nil {
		return nil, fmt.Errorf("generating grant key: %w", err)
	}
	return key, nil
}

// EncryptMetadata encrypts metadata and binds it to its grant ID.
func (k *GrantKey) EncryptMetadata(plaintext []byte, grantID string) ([]byte, error) {
	if k == nil {
		return nil, fmt.Errorf("invalid grant key")
	}
	aad, err := encodeContext("grant-metadata", grantID)
	if err != nil {
		return nil, err
	}
	return seal(k.key, metadataEnvelopeHeader, plaintext, aad)
}

// DecryptMetadata decrypts metadata bound to its grant ID.
func (k *GrantKey) DecryptMetadata(ciphertext []byte, grantID string) ([]byte, error) {
	if k == nil {
		return nil, fmt.Errorf("invalid grant key")
	}
	aad, err := encodeContext("grant-metadata", grantID)
	if err != nil {
		return nil, err
	}
	return open(k.key, metadataEnvelopeHeader, ciphertext, aad)
}

// WrapForToken encrypts this grant key with a verified token's derived KEK.
func (k *GrantKey) WrapForToken(token *Token) ([]byte, error) {
	if k == nil || token == nil || len(token.context) == 0 {
		return nil, fmt.Errorf("invalid grant key or token")
	}
	aad, err := encodeContext("wrapped-grant-key", string(token.context))
	if err != nil {
		return nil, err
	}
	return seal(token.kek, grantKeyEnvelopeHeader, k.key[:], aad)
}

// UnwrapGrantKey decrypts the grant key wrapped for this verified token.
func (t *Token) UnwrapGrantKey(wrapped []byte) (*GrantKey, error) {
	if t == nil || len(t.context) == 0 {
		return nil, fmt.Errorf("invalid token")
	}
	aad, err := encodeContext("wrapped-grant-key", string(t.context))
	if err != nil {
		return nil, err
	}
	plaintext, err := open(t.kek, grantKeyEnvelopeHeader, wrapped, aad)
	if err != nil {
		return nil, err
	}
	defer clear(plaintext)
	if len(plaintext) != grantKeySize {
		return nil, errInvalidCiphertext
	}
	key := new(GrantKey)
	copy(key.key[:], plaintext)
	return key, nil
}

func seal(key [32]byte, header, plaintext, additionalData []byte) ([]byte, error) {
	aead, err := newAEAD(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("generating AEAD nonce: %w", err)
	}
	aad := envelopeAAD(header, additionalData)
	result := make([]byte, 0, len(header)+len(nonce)+len(plaintext)+aead.Overhead())
	result = append(result, header...)
	result = append(result, nonce...)
	return aead.Seal(result, nonce, plaintext, aad), nil
}

func open(key [32]byte, header, ciphertext, additionalData []byte) ([]byte, error) {
	aead, err := newAEAD(key)
	if err != nil {
		return nil, err
	}
	if len(ciphertext) < len(header)+aead.NonceSize()+aead.Overhead() || !bytes.Equal(ciphertext[:len(header)], header) {
		return nil, errInvalidCiphertext
	}
	nonce := ciphertext[len(header) : len(header)+aead.NonceSize()]
	sealed := ciphertext[len(header)+aead.NonceSize():]
	plaintext, err := aead.Open(nil, nonce, sealed, envelopeAAD(header, additionalData))
	if err != nil {
		return nil, errInvalidCiphertext
	}
	return plaintext, nil
}

func newAEAD(key [32]byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, fmt.Errorf("creating AES cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("creating AES-GCM: %w", err)
	}
	return aead, nil
}

func envelopeAAD(header, additionalData []byte) []byte {
	aad := make([]byte, 0, len(header)+len(additionalData))
	aad = append(aad, header...)
	aad = append(aad, additionalData...)
	return aad
}
