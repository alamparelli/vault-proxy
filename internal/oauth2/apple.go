package oauth2

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"
)

// AppleJWTLifetime is the lifetime applied to each signed Apple ASC JWT.
// Apple enforces a 20-minute maximum (1200s) on the `exp` claim; we use the
// full window to minimise re-sign churn.
const AppleJWTLifetime = 20 * time.Minute

// AppleDefaultAudience is the audience claim required by the App Store Connect
// API. Older Apple services (e.g. DeviceCheck) use different audiences and can
// be overridden via Auth.AppleAudience.
const AppleDefaultAudience = "appstoreconnect-v1"

// SignAppleJWT produces an ES256-signed JWT for the App Store Connect API.
// The .p8 file Apple ships is a PKCS8-encoded ECDSA P-256 private key.
// Unlike Google's service_account flow there is no upstream token exchange:
// the JWT *is* the credential, attached as `Authorization: Bearer <jwt>`.
//
// audience can be empty — defaults to AppleDefaultAudience.
func SignAppleJWT(p8Data []byte, keyID, issuerID, audience string, now time.Time) (token string, expiresAt int64, err error) {
	if keyID == "" {
		return "", 0, fmt.Errorf("apple key_id is required")
	}
	if issuerID == "" {
		return "", 0, fmt.Errorf("apple issuer_id is required")
	}
	if audience == "" {
		audience = AppleDefaultAudience
	}

	key, err := parseECPrivateKeyP256(p8Data)
	if err != nil {
		return "", 0, err
	}

	expires := now.Add(AppleJWTLifetime).Unix()
	header := map[string]string{"alg": "ES256", "kid": keyID, "typ": "JWT"}
	claims := map[string]any{
		"iss": issuerID,
		"iat": now.Unix(),
		"exp": expires,
		"aud": audience,
	}

	headerJSON, _ := json.Marshal(header)
	claimsJSON, _ := json.Marshal(claims)
	signingInput := base64.RawURLEncoding.EncodeToString(headerJSON) + "." +
		base64.RawURLEncoding.EncodeToString(claimsJSON)

	digest := sha256.Sum256([]byte(signingInput))
	r, sBig, err := ecdsa.Sign(rand.Reader, key, digest[:])
	if err != nil {
		return "", 0, fmt.Errorf("ecdsa sign: %w", err)
	}

	// JWS ES256 signatures are the fixed-width r||s concatenation, NOT the ASN.1
	// DER encoding that ecdsa.Sign would emit if we called MarshalECDSASignature.
	// For P-256 each integer is left-padded to 32 bytes.
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	sBig.FillBytes(sig[32:])

	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig), expires, nil
}

func parseECPrivateKeyP256(pemData []byte) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found in apple key file")
	}

	// Apple .p8 keys are PKCS8. Fall back to SEC1 in case a user provides a
	// hand-converted key.
	if k, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		ec, ok := k.(*ecdsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("apple key is not ECDSA (got %T)", k)
		}
		if ec.Curve != elliptic.P256() {
			return nil, fmt.Errorf("apple key must use P-256 curve")
		}
		return ec, nil
	}
	ec, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse apple .p8: %w", err)
	}
	if ec.Curve != elliptic.P256() {
		return nil, fmt.Errorf("apple key must use P-256 curve")
	}
	return ec, nil
}

// VerifyAppleJWTSignature is a test helper exposed at package scope. Returns
// true if the JWT's signature is valid under pub. Production code does not
// call this — Apple verifies the signature on the API side.
func VerifyAppleJWTSignature(jwt string, pub *ecdsa.PublicKey) bool {
	// Find last '.'
	dot1 := -1
	dot2 := -1
	for i := 0; i < len(jwt); i++ {
		if jwt[i] == '.' {
			if dot1 == -1 {
				dot1 = i
			} else {
				dot2 = i
			}
		}
	}
	if dot1 < 0 || dot2 < 0 {
		return false
	}
	signingInput := jwt[:dot2]
	sigB64 := jwt[dot2+1:]
	sig, err := base64.RawURLEncoding.DecodeString(sigB64)
	if err != nil || len(sig) != 64 {
		return false
	}
	digest := sha256.Sum256([]byte(signingInput))
	r := new(big.Int).SetBytes(sig[:32])
	s := new(big.Int).SetBytes(sig[32:])
	return ecdsa.Verify(pub, digest[:], r, s)
}
