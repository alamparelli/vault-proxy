package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
)

// File format: [salt:16][nonce:12][ciphertext+tag]

// wipe zeroes a byte slice to remove sensitive data from memory.
func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// Encrypt encrypts plaintext with a password. Returns salt+nonce+ciphertext.
func Encrypt(plaintext, password []byte) ([]byte, error) {
	salt := make([]byte, SaltSize)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, fmt.Errorf("generate salt: %w", err)
	}

	key := DeriveKey(password, salt)
	defer wipe(key)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create gcm: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}

	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)

	// salt + nonce + ciphertext
	out := make([]byte, 0, SaltSize+len(nonce)+len(ciphertext))
	out = append(out, salt...)
	out = append(out, nonce...)
	out = append(out, ciphertext...)
	return out, nil
}

// Decrypt decrypts data produced by Encrypt using the given password.
func Decrypt(data, password []byte) ([]byte, error) {
	if len(data) < SaltSize+12 { // salt + min nonce
		return nil, errors.New("ciphertext too short")
	}

	salt := data[:SaltSize]
	key := DeriveKey(password, salt)
	defer wipe(key)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create gcm: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(data) < SaltSize+nonceSize {
		return nil, errors.New("ciphertext too short for nonce")
	}

	nonce := data[SaltSize : SaltSize+nonceSize]
	ciphertext := data[SaltSize+nonceSize:]

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, errors.New("decryption failed: wrong password or corrupted data")
	}

	return plaintext, nil
}
