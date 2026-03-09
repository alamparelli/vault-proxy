package crypto

import (
	"bytes"
	"testing"
)

func TestEncryptDecryptRoundTrip(t *testing.T) {
	plaintext := []byte(`{"services":{"openrouter":{"token":"sk-123"}}}`)
	password := []byte("test-master-password")

	encrypted, err := Encrypt(plaintext, password)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	if bytes.Equal(encrypted, plaintext) {
		t.Fatal("encrypted data should differ from plaintext")
	}

	decrypted, err := Decrypt(encrypted, password)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}

	if !bytes.Equal(decrypted, plaintext) {
		t.Fatalf("decrypted data mismatch: got %q, want %q", decrypted, plaintext)
	}
}

func TestDecryptWrongPassword(t *testing.T) {
	plaintext := []byte("secret data")
	encrypted, err := Encrypt(plaintext, []byte("correct"))
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	_, err = Decrypt(encrypted, []byte("wrong"))
	if err == nil {
		t.Fatal("expected error with wrong password")
	}
}

func TestDecryptTooShort(t *testing.T) {
	_, err := Decrypt([]byte("short"), []byte("pass"))
	if err == nil {
		t.Fatal("expected error with short ciphertext")
	}
}

func TestEncryptDifferentSalts(t *testing.T) {
	plaintext := []byte("same data")
	password := []byte("same pass")

	enc1, _ := Encrypt(plaintext, password)
	enc2, _ := Encrypt(plaintext, password)

	if bytes.Equal(enc1, enc2) {
		t.Fatal("two encryptions should produce different output (random salt/nonce)")
	}
}
