package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/alessandrolamparelli/vault-proxy/internal/vault"
)

func setupTestServer(t *testing.T) (*Server, string) {
	t.Helper()
	dir := t.TempDir()
	store := vault.NewStore(dir)
	server := NewServer(store, time.Hour)
	ts := httptest.NewServer(server)
	t.Cleanup(ts.Close)
	return server, ts.URL
}

func unlock(t *testing.T, url, password string) string {
	t.Helper()
	body, _ := json.Marshal(map[string]string{"password": password})
	resp, err := http.Post(url+"/auth/unlock", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("unlock request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		data, _ := io.ReadAll(resp.Body)
		t.Fatalf("unlock failed: %s", data)
	}

	var token struct{ ID string }
	json.NewDecoder(resp.Body).Decode(&token)
	return token.ID
}

func TestHealth(t *testing.T) {
	_, url := setupTestServer(t)

	resp, _ := http.Get(url + "/health")
	defer resp.Body.Close()

	var result map[string]string
	json.NewDecoder(resp.Body).Decode(&result)
	if result["status"] != "locked" {
		t.Fatalf("expected locked, got %s", result["status"])
	}
}

func TestUnlockAndLock(t *testing.T) {
	_, url := setupTestServer(t)

	token := unlock(t, url, "master")
	if token == "" {
		t.Fatal("expected non-empty token")
	}

	// Health should show unlocked
	resp, _ := http.Get(url + "/health")
	var result map[string]string
	json.NewDecoder(resp.Body).Decode(&result)
	resp.Body.Close()
	if result["status"] != "unlocked" {
		t.Fatal("expected unlocked")
	}

	// Lock
	req, _ := http.NewRequest("POST", url+"/auth/lock", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, _ = http.DefaultClient.Do(req)
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("lock failed: %d", resp.StatusCode)
	}
}

func TestServicesCRUD(t *testing.T) {
	_, url := setupTestServer(t)
	token := unlock(t, url, "master")

	// Add service
	svc := `{"name":"openrouter","base_url":"https://openrouter.ai/api","auth":{"type":"bearer","token":"sk-123"}}`
	req, _ := http.NewRequest("POST", url+"/services", bytes.NewReader([]byte(svc)))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, _ := http.DefaultClient.Do(req)
	if resp.StatusCode != 201 {
		data, _ := io.ReadAll(resp.Body)
		t.Fatalf("add service: %d %s", resp.StatusCode, data)
	}
	resp.Body.Close()

	// List services
	req, _ = http.NewRequest("GET", url+"/services", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, _ = http.DefaultClient.Do(req)
	defer resp.Body.Close()

	var services []vault.ServiceInfo
	json.NewDecoder(resp.Body).Decode(&services)
	if len(services) != 1 || services[0].Name != "openrouter" {
		t.Fatalf("expected 1 service, got %+v", services)
	}

	// Token in response should NOT be visible (SafeInfo)
	data, _ := json.Marshal(services[0])
	if bytes.Contains(data, []byte("sk-123")) {
		t.Fatal("secret token leaked in service list")
	}
}

func TestProxyScopeRestrictions(t *testing.T) {
	_, url := setupTestServer(t)
	adminToken := unlock(t, url, "master")

	// Create proxy-scoped token
	body, _ := json.Marshal(map[string]string{"scope": "proxy"})
	req, _ := http.NewRequest("POST", url+"/tokens", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+adminToken)
	req.Header.Set("Content-Type", "application/json")
	resp, _ := http.DefaultClient.Do(req)

	var proxyToken struct{ ID string }
	json.NewDecoder(resp.Body).Decode(&proxyToken)
	resp.Body.Close()

	// Proxy token should NOT be able to add services
	svc := `{"name":"test","base_url":"https://test.com","auth":{"type":"bearer","token":"t"}}`
	req, _ = http.NewRequest("POST", url+"/services", bytes.NewReader([]byte(svc)))
	req.Header.Set("Authorization", "Bearer "+proxyToken.ID)
	req.Header.Set("Content-Type", "application/json")
	resp, _ = http.DefaultClient.Do(req)
	resp.Body.Close()
	if resp.StatusCode != 403 {
		t.Fatalf("proxy token should not add services, got %d", resp.StatusCode)
	}

	// Proxy token CAN list services
	req, _ = http.NewRequest("GET", url+"/services", nil)
	req.Header.Set("Authorization", "Bearer "+proxyToken.ID)
	resp, _ = http.DefaultClient.Do(req)
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("proxy token should list services, got %d", resp.StatusCode)
	}
}

func TestProxyHandler(t *testing.T) {
	// Start a fake upstream API
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify auth was injected
		auth := r.Header.Get("Authorization")
		if auth != "Bearer sk-secret-key" {
			t.Errorf("expected injected bearer, got %q", auth)
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"model":"test","response":"hello"}`)
	}))
	defer upstream.Close()

	dir := t.TempDir()
	store := vault.NewStore(dir)
	server := NewServer(store, time.Hour)
	ts := httptest.NewServer(server)
	defer ts.Close()

	token := unlock(t, ts.URL, "master")

	// Add service pointing to our fake upstream
	svc := fmt.Sprintf(`{"name":"testapi","base_url":"%s","auth":{"type":"bearer","token":"sk-secret-key"}}`, upstream.URL)
	req, _ := http.NewRequest("POST", ts.URL+"/services", bytes.NewReader([]byte(svc)))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, _ := http.DefaultClient.Do(req)
	resp.Body.Close()

	// Proxy a request
	proxyBody := `{"prompt":"test"}`
	req, _ = http.NewRequest("POST", ts.URL+"/proxy/testapi/v1/chat", bytes.NewReader([]byte(proxyBody)))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, _ = http.DefaultClient.Do(req)
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		data, _ := io.ReadAll(resp.Body)
		t.Fatalf("proxy failed: %d %s", resp.StatusCode, data)
	}

	var result map[string]string
	json.NewDecoder(resp.Body).Decode(&result)
	if result["response"] != "hello" {
		t.Fatalf("unexpected proxy response: %+v", result)
	}
}

func TestProxyStripsCallerAuth(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		// Should be the injected token, not the vault session token
		if auth != "Bearer injected-token" {
			t.Errorf("auth header not properly replaced: got %q", auth)
		}
		w.WriteHeader(200)
	}))
	defer upstream.Close()

	dir := t.TempDir()
	store := vault.NewStore(dir)
	server := NewServer(store, time.Hour)
	ts := httptest.NewServer(server)
	defer ts.Close()

	token := unlock(t, ts.URL, "master")

	svc := fmt.Sprintf(`{"name":"svc","base_url":"%s","auth":{"type":"bearer","token":"injected-token"}}`, upstream.URL)
	req, _ := http.NewRequest("POST", ts.URL+"/services", bytes.NewReader([]byte(svc)))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, _ := http.DefaultClient.Do(req)
	resp.Body.Close()

	req, _ = http.NewRequest("GET", ts.URL+"/proxy/svc/test", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, _ = http.DefaultClient.Do(req)
	resp.Body.Close()
}
