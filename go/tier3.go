package sesame

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"strings"
)

// AES-256-GCM parameters.
const (
	KeyLen = 32
	IVLen  = 12
	TagLen = 16
)

var errBadIV = errors.New("sesame: IV must be 12 bytes")

// AADForHeaders builds the GCM associated data:
// version LF key-id LF timestamp LF nonce [LF scope].
func AADForHeaders(version, keyID, timestamp, nonce string, scope *string) []byte {
	fields := []string{version, keyID, timestamp, nonce}
	if scope != nil {
		fields = append(fields, *scope)
	}
	return []byte(strings.Join(fields, "\n"))
}

// Seal encrypts plaintext with AES-256-GCM, returning ciphertext || tag.
func Seal(key, iv, aad, plaintext []byte) ([]byte, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	if len(iv) != IVLen {
		return nil, errBadIV
	}
	return gcm.Seal(nil, iv, plaintext, aad), nil
}

// Open decrypts ciphertext || tag; returns an error on authentication failure.
func Open(key, iv, aad, ctAndTag []byte) ([]byte, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	if len(iv) != IVLen {
		return nil, errBadIV
	}
	return gcm.Open(nil, iv, ctAndTag, aad)
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}
