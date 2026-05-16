package oauth2

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"strings"
	"testing"
	"time"
)

// generateAppleTestKey returns a fresh P-256 key encoded as PKCS8 PEM (the
// format Apple ships as .p8).
func generateAppleTestKey(t *testing.T) ([]byte, *ecdsa.PrivateKey) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("marshal pkcs8: %v", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	return pemBytes, priv
}

func TestSignAppleJWT_ValidShape(t *testing.T) {
	pemBytes, priv := generateAppleTestKey(t)
	now := time.Unix(1_700_000_000, 0).UTC()

	jwt, expiresAt, err := SignAppleJWT(pemBytes, "ABC1234567", "11111111-2222-3333-4444-555555555555", "", now)
	if err != nil {
		t.Fatalf("SignAppleJWT: %v", err)
	}
	if expiresAt != now.Add(AppleJWTLifetime).Unix() {
		t.Errorf("expiresAt = %d, want %d", expiresAt, now.Add(AppleJWTLifetime).Unix())
	}

	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		t.Fatalf("expected 3 JWT parts, got %d", len(parts))
	}

	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatalf("decode header: %v", err)
	}
	var header map[string]string
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		t.Fatalf("parse header: %v", err)
	}
	if header["alg"] != "ES256" {
		t.Errorf("alg = %q, want ES256", header["alg"])
	}
	if header["kid"] != "ABC1234567" {
		t.Errorf("kid = %q, want ABC1234567", header["kid"])
	}
	if header["typ"] != "JWT" {
		t.Errorf("typ = %q, want JWT", header["typ"])
	}

	claimsJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode claims: %v", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(claimsJSON, &claims); err != nil {
		t.Fatalf("parse claims: %v", err)
	}
	if claims["iss"] != "11111111-2222-3333-4444-555555555555" {
		t.Errorf("iss = %v", claims["iss"])
	}
	if claims["aud"] != AppleDefaultAudience {
		t.Errorf("aud = %v, want %s", claims["aud"], AppleDefaultAudience)
	}
	if got, want := int64(claims["iat"].(float64)), now.Unix(); got != want {
		t.Errorf("iat = %d, want %d", got, want)
	}
	if got, want := int64(claims["exp"].(float64)), expiresAt; got != want {
		t.Errorf("exp = %d, want %d", got, want)
	}

	// Signature must be 64 bytes (r||s for P-256) — i.e. 86 chars when raw-url
	// base64 encoded without padding.
	if !VerifyAppleJWTSignature(jwt, &priv.PublicKey) {
		t.Errorf("signature failed verification with own public key")
	}
}

func TestSignAppleJWT_CustomAudience(t *testing.T) {
	pemBytes, _ := generateAppleTestKey(t)
	jwt, _, err := SignAppleJWT(pemBytes, "K", "I", "devicecheck-v1", time.Now())
	if err != nil {
		t.Fatalf("SignAppleJWT: %v", err)
	}
	parts := strings.Split(jwt, ".")
	body, _ := base64.RawURLEncoding.DecodeString(parts[1])
	var claims map[string]any
	_ = json.Unmarshal(body, &claims)
	if claims["aud"] != "devicecheck-v1" {
		t.Errorf("aud = %v, want devicecheck-v1", claims["aud"])
	}
}

func TestSignAppleJWT_MissingFields(t *testing.T) {
	pemBytes, _ := generateAppleTestKey(t)
	if _, _, err := SignAppleJWT(pemBytes, "", "I", "", time.Now()); err == nil {
		t.Error("expected error when key_id is empty")
	}
	if _, _, err := SignAppleJWT(pemBytes, "K", "", "", time.Now()); err == nil {
		t.Error("expected error when issuer_id is empty")
	}
}

func TestSignAppleJWT_BogusPEM(t *testing.T) {
	if _, _, err := SignAppleJWT([]byte("not a pem block"), "K", "I", "", time.Now()); err == nil {
		t.Error("expected error on non-PEM input")
	}
}

func TestSignAppleJWT_WrongCurve(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	der, _ := x509.MarshalPKCS8PrivateKey(priv)
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})

	if _, _, err := SignAppleJWT(pemBytes, "K", "I", "", time.Now()); err == nil {
		t.Error("expected error on P-384 key (Apple requires P-256)")
	}
}
