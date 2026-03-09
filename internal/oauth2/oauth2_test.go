package oauth2

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRefreshAccessToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if ct := r.Header.Get("Content-Type"); ct != "application/x-www-form-urlencoded" {
			t.Errorf("expected form content-type, got %s", ct)
		}

		if err := r.ParseForm(); err != nil {
			t.Fatalf("parse form: %v", err)
		}
		if got := r.FormValue("grant_type"); got != "refresh_token" {
			t.Errorf("grant_type = %q, want %q", got, "refresh_token")
		}
		if got := r.FormValue("client_id"); got != "test-client-id" {
			t.Errorf("client_id = %q, want %q", got, "test-client-id")
		}
		if got := r.FormValue("client_secret"); got != "test-client-secret" {
			t.Errorf("client_secret = %q, want %q", got, "test-client-secret")
		}
		if got := r.FormValue("refresh_token"); got != "test-refresh-token" {
			t.Errorf("refresh_token = %q, want %q", got, "test-refresh-token")
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"access_token": "new-access-token",
			"expires_in":   3600,
			"token_type":   "Bearer",
		})
	}))
	defer srv.Close()

	result, err := RefreshAccessToken(
		context.Background(),
		srv.Client(),
		srv.URL,
		"test-client-id",
		"test-client-secret",
		"test-refresh-token",
		nil,
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.AccessToken != "new-access-token" {
		t.Errorf("AccessToken = %q, want %q", result.AccessToken, "new-access-token")
	}
	if result.ExpiresAt == 0 {
		t.Error("ExpiresAt should be non-zero")
	}
	if result.RefreshToken != "" {
		t.Errorf("RefreshToken = %q, want empty (no rotation)", result.RefreshToken)
	}
}

func TestRefreshAccessTokenRotation(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"access_token":  "new-access-token",
			"expires_in":    3600,
			"token_type":    "Bearer",
			"refresh_token": "rotated-refresh-token",
		})
	}))
	defer srv.Close()

	result, err := RefreshAccessToken(
		context.Background(),
		srv.Client(),
		srv.URL,
		"cid", "csecret", "old-rt",
		nil,
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.RefreshToken != "rotated-refresh-token" {
		t.Errorf("RefreshToken = %q, want %q", result.RefreshToken, "rotated-refresh-token")
	}
}

func TestRefreshAccessTokenError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"error":"invalid_grant"}`))
	}))
	defer srv.Close()

	_, err := RefreshAccessToken(
		context.Background(),
		srv.Client(),
		srv.URL,
		"cid", "csecret", "bad-rt",
		nil,
	)
	if err == nil {
		t.Fatal("expected error for 401 response, got nil")
	}
}

// generateTestSAJSON creates a service account JSON with a real RSA key for testing.
func generateTestSAJSON(t *testing.T, tokenURL string) []byte {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}

	privDER := x509.MarshalPKCS1PrivateKey(key)
	privPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privDER,
	})

	sa := map[string]string{
		"client_email": "test@test.iam.gserviceaccount.com",
		"private_key":  string(privPEM),
		"token_uri":    tokenURL,
	}
	b, err := json.Marshal(sa)
	if err != nil {
		t.Fatalf("marshal SA JSON: %v", err)
	}
	return b
}

func TestExchangeServiceAccountJWT(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}

		if err := r.ParseForm(); err != nil {
			t.Fatalf("parse form: %v", err)
		}
		if got := r.FormValue("grant_type"); got != "urn:ietf:params:oauth:grant-type:jwt-bearer" {
			t.Errorf("grant_type = %q, want jwt-bearer URN", got)
		}
		assertion := r.FormValue("assertion")
		if assertion == "" {
			t.Error("assertion is empty")
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"access_token": "sa-access-token",
			"expires_in":   3600,
			"token_type":   "Bearer",
		})
	}))
	defer srv.Close()

	saJSON := generateTestSAJSON(t, srv.URL)

	result, err := ExchangeServiceAccountJWT(
		context.Background(),
		srv.Client(),
		saJSON,
		[]string{"https://www.googleapis.com/auth/cloud-platform"},
		srv.URL,
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.AccessToken != "sa-access-token" {
		t.Errorf("AccessToken = %q, want %q", result.AccessToken, "sa-access-token")
	}
	if result.ExpiresAt == 0 {
		t.Error("ExpiresAt should be non-zero")
	}
}

func TestExchangeServiceAccountJWTInvalidKey(t *testing.T) {
	sa := map[string]string{
		"client_email": "test@test.iam.gserviceaccount.com",
		"private_key":  "not-a-valid-pem",
	}
	saJSON, _ := json.Marshal(sa)

	_, err := ExchangeServiceAccountJWT(
		context.Background(),
		http.DefaultClient,
		saJSON,
		[]string{"scope"},
		"https://unused.example.com/token",
	)
	if err == nil {
		t.Fatal("expected error for invalid PEM key, got nil")
	}
}
