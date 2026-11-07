// Package fieldcrypto implements the R3-ENC versioned AES-256-GCM envelope.
package fieldcrypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strings"
)

const (
	// Prefix identifies version-1 envelopes: s2a1.<base64(nonce||ciphertext||tag)>.
	Prefix        = "s2a1."
	AES256KeySize = 32
)

var (
	ErrInvalidKey      = errors.New("fieldcrypto: encryption key must be 32 bytes")
	ErrUnknownVersion  = errors.New("fieldcrypto: unknown envelope version")
	ErrInvalidEnvelope = errors.New("fieldcrypto: invalid envelope")
	ErrDecrypt         = errors.New("fieldcrypto: decrypt failed")
)

// IsEnvelope reports whether value uses a known versioned prefix.
func IsEnvelope(value string) bool {
	return strings.HasPrefix(value, Prefix)
}

// Encrypt seals plaintext with a random nonce and the supplied AAD.
func Encrypt(key []byte, plaintext, aad string) (string, error) {
	if len(key) != AES256KeySize {
		return "", ErrInvalidKey
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("fieldcrypto: create cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("fieldcrypto: create gcm: %w", err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("fieldcrypto: nonce: %w", err)
	}
	sealed := gcm.Seal(nonce, nonce, []byte(plaintext), []byte(aad))
	return Prefix + base64.StdEncoding.EncodeToString(sealed), nil
}

// Decrypt opens a versioned envelope. Values that are not envelopes are
// returned unchanged so historical plaintext remains readable.
func Decrypt(key []byte, value, aad string) (string, error) {
	if !IsEnvelope(value) {
		if looksLikeUnknownVersion(value) {
			return "", ErrUnknownVersion
		}
		return value, nil
	}
	if len(key) != AES256KeySize {
		return "", ErrInvalidKey
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(value, Prefix))
	if err != nil {
		return "", ErrInvalidEnvelope
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("fieldcrypto: create cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("fieldcrypto: create gcm: %w", err)
	}
	if len(raw) < gcm.NonceSize() {
		return "", ErrInvalidEnvelope
	}
	nonce, ciphertext := raw[:gcm.NonceSize()], raw[gcm.NonceSize():]
	plain, err := gcm.Open(nil, nonce, ciphertext, []byte(aad))
	if err != nil {
		return "", ErrDecrypt
	}
	return string(plain), nil
}

func looksLikeUnknownVersion(value string) bool {
	if len(value) < 5 {
		return false
	}
	if strings.HasPrefix(value, "s2a") && value[3] >= '0' && value[3] <= '9' && value[4] == '.' {
		return !strings.HasPrefix(value, Prefix)
	}
	return false
}
