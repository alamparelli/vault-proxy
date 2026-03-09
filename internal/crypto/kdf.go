package crypto

import "golang.org/x/crypto/argon2"

const (
	SaltSize   = 16
	KeySize    = 32 // AES-256
	argonTime  = 3
	argonMem   = 64 * 1024 // 64 MB
	argonLanes = 4
)

// DeriveKey derives a 256-bit key from password and salt using Argon2id.
func DeriveKey(password []byte, salt []byte) []byte {
	return argon2.IDKey(password, salt, argonTime, argonMem, argonLanes, KeySize)
}
