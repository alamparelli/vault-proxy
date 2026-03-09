package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
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

	// Add service pointing to our fake upstream (tls_skip_verify allows HTTP in tests)
	svc := fmt.Sprintf(`{"name":"testapi","base_url":"%s","auth":{"type":"bearer","token":"sk-secret-key"},"tls_skip_verify":true}`, upstream.URL)
	req, _ := http.NewRequest("POST", ts.URL+"/services", bytes.NewReader([]byte(svc)))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, _ := http.DefaultClient.Do(req)
	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("add service failed: %d %s", resp.StatusCode, body)
	}
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

	svc := fmt.Sprintf(`{"name":"svc","base_url":"%s","auth":{"type":"bearer","token":"injected-token"},"tls_skip_verify":true}`, upstream.URL)
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

func TestFilesCRUD(t *testing.T) {
	_, url := setupTestServer(t)
	token := unlock(t, url, "master")

	// Upload a file via multipart POST /files
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	w.WriteField("name", "test-file")
	part, err := w.CreateFormFile("file", "test.json")
	if err != nil {
		t.Fatalf("create form file: %v", err)
	}
	part.Write([]byte(`{"key":"value"}`))
	w.Close()

	req, _ := http.NewRequest("POST", url+"/files", &buf)
	req.Header.Set("Content-Type", w.FormDataContentType())
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("upload request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		data, _ := io.ReadAll(resp.Body)
		t.Fatalf("upload file: expected 201, got %d %s", resp.StatusCode, data)
	}

	var fileInfo struct {
		Name     string `json:"name"`
		MimeType string `json:"mime_type"`
		Size     int    `json:"size"`
	}
	json.NewDecoder(resp.Body).Decode(&fileInfo)
	if fileInfo.Name != "test-file" {
		t.Fatalf("expected file name 'test-file', got %q", fileInfo.Name)
	}
	if fileInfo.Size != len(`{"key":"value"}`) {
		t.Fatalf("expected size %d, got %d", len(`{"key":"value"}`), fileInfo.Size)
	}

	// List files via GET /files
	req, _ = http.NewRequest("GET", url+"/files", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp2, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("list request: %v", err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("list files: expected 200, got %d", resp2.StatusCode)
	}

	var files []struct {
		Name string `json:"name"`
	}
	json.NewDecoder(resp2.Body).Decode(&files)
	if len(files) != 1 || files[0].Name != "test-file" {
		t.Fatalf("expected 1 file named 'test-file', got %+v", files)
	}

	// Download file via GET /files/{name}
	req, _ = http.NewRequest("GET", url+"/files/test-file", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp3, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("download request: %v", err)
	}
	defer resp3.Body.Close()
	if resp3.StatusCode != http.StatusOK {
		t.Fatalf("download file: expected 200, got %d", resp3.StatusCode)
	}

	body, _ := io.ReadAll(resp3.Body)
	if string(body) != `{"key":"value"}` {
		t.Fatalf("download content mismatch: got %q", body)
	}
	if ct := resp3.Header.Get("Content-Disposition"); ct == "" {
		t.Fatal("expected Content-Disposition header on download")
	}

	// Delete file via DELETE /files/{name}
	req, _ = http.NewRequest("DELETE", url+"/files/test-file", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp4, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("delete request: %v", err)
	}
	defer resp4.Body.Close()
	if resp4.StatusCode != http.StatusOK {
		t.Fatalf("delete file: expected 200, got %d", resp4.StatusCode)
	}

	// Verify file is gone - list should be empty
	req, _ = http.NewRequest("GET", url+"/files", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp5, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("list after delete request: %v", err)
	}
	defer resp5.Body.Close()

	var filesAfter []struct {
		Name string `json:"name"`
	}
	json.NewDecoder(resp5.Body).Decode(&filesAfter)
	if len(filesAfter) != 0 {
		t.Fatalf("expected 0 files after delete, got %+v", filesAfter)
	}

	// Download deleted file should 404
	req, _ = http.NewRequest("GET", url+"/files/test-file", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp6, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("download deleted request: %v", err)
	}
	defer resp6.Body.Close()
	if resp6.StatusCode != http.StatusNotFound {
		t.Fatalf("download deleted file: expected 404, got %d", resp6.StatusCode)
	}
}

func TestFilesProxyScopeBlocked(t *testing.T) {
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

	if proxyToken.ID == "" {
		t.Fatal("expected non-empty proxy token")
	}

	// POST /files - upload should be blocked
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	w.WriteField("name", "blocked-file")
	part, _ := w.CreateFormFile("file", "test.txt")
	part.Write([]byte("data"))
	w.Close()

	req, _ = http.NewRequest("POST", url+"/files", &buf)
	req.Header.Set("Content-Type", w.FormDataContentType())
	req.Header.Set("Authorization", "Bearer "+proxyToken.ID)
	resp, _ = http.DefaultClient.Do(req)
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("proxy token POST /files: expected 403, got %d", resp.StatusCode)
	}

	// GET /files - list should be blocked
	req, _ = http.NewRequest("GET", url+"/files", nil)
	req.Header.Set("Authorization", "Bearer "+proxyToken.ID)
	resp, _ = http.DefaultClient.Do(req)
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("proxy token GET /files: expected 403, got %d", resp.StatusCode)
	}

	// GET /files/{name} - download should be blocked
	req, _ = http.NewRequest("GET", url+"/files/any-file", nil)
	req.Header.Set("Authorization", "Bearer "+proxyToken.ID)
	resp, _ = http.DefaultClient.Do(req)
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("proxy token GET /files/{name}: expected 403, got %d", resp.StatusCode)
	}

	// DELETE /files/{name} - delete should be blocked
	req, _ = http.NewRequest("DELETE", url+"/files/any-file", nil)
	req.Header.Set("Authorization", "Bearer "+proxyToken.ID)
	resp, _ = http.DefaultClient.Do(req)
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("proxy token DELETE /files/{name}: expected 403, got %d", resp.StatusCode)
	}
}
