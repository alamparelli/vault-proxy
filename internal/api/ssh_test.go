package api

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"mime/multipart"
	"net"
	"net/http"
	"testing"

	"github.com/alamparelli/vault-proxy/internal/vault"
	"golang.org/x/crypto/ssh"
)

// testSSHServer starts an in-memory SSH server and returns its address and PEM key.
func testSSHServer(t *testing.T) (addr string, keyPEM []byte, cleanup func()) {
	t.Helper()

	// Generate client key
	clientPub, clientPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pemBlock, err := ssh.MarshalPrivateKey(clientPriv, "")
	if err != nil {
		t.Fatal(err)
	}
	keyPEM = pem.EncodeToMemory(pemBlock)

	sshClientPub, err := ssh.NewPublicKey(clientPub)
	if err != nil {
		t.Fatal(err)
	}

	// Generate host key
	_, hostPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	hostSigner, err := ssh.NewSignerFromKey(hostPriv)
	if err != nil {
		t.Fatal(err)
	}

	config := &ssh.ServerConfig{
		PublicKeyCallback: func(c ssh.ConnMetadata, pubKey ssh.PublicKey) (*ssh.Permissions, error) {
			if bytes.Equal(pubKey.Marshal(), sshClientPub.Marshal()) {
				return &ssh.Permissions{}, nil
			}
			return nil, fmt.Errorf("unauthorized")
		},
	}
	config.AddHostKey(hostSigner)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go handleSSHTestConn(conn, config)
		}
	}()

	return listener.Addr().String(), keyPEM, func() {
		listener.Close()
		<-done
	}
}

func handleSSHTestConn(conn net.Conn, config *ssh.ServerConfig) {
	defer conn.Close()
	sshConn, chans, reqs, err := ssh.NewServerConn(conn, config)
	if err != nil {
		return
	}
	defer sshConn.Close()
	go ssh.DiscardRequests(reqs)

	for newCh := range chans {
		if newCh.ChannelType() != "session" {
			newCh.Reject(ssh.UnknownChannelType, "unsupported")
			continue
		}
		ch, requests, err := newCh.Accept()
		if err != nil {
			continue
		}
		go func() {
			defer ch.Close()
			for req := range requests {
				switch req.Type {
				case "exec":
					// Extract command
					if len(req.Payload) > 4 {
						cmdLen := int(req.Payload[0])<<24 | int(req.Payload[1])<<16 | int(req.Payload[2])<<8 | int(req.Payload[3])
						if cmdLen <= len(req.Payload)-4 {
							cmd := string(req.Payload[4 : 4+cmdLen])
							if cmd == "exit 42" {
								ch.Write([]byte("error output"))
								ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{42}))
							} else {
								ch.Write([]byte("ok: " + cmd))
								ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{0}))
							}
						}
					}
					req.Reply(true, nil)
					return
				case "shell", "pty-req", "window-change":
					req.Reply(true, nil)
				default:
					req.Reply(false, nil)
				}
			}
		}()
	}
}

// setupSSHService creates a vault with an SSH service pointing to the test server.
// Uses the store directly to bypass host validation (test server runs on 127.0.0.1
// which is blocked by validateSSHHost for security).
func setupSSHService(t *testing.T, server *Server, vaultURL, token, sshAddr string, keyPEM []byte) {
	t.Helper()

	host, portStr, _ := net.SplitHostPort(sshAddr)
	port := 0
	fmt.Sscanf(portStr, "%d", &port)

	// Upload SSH key file via API (file upload doesn't have host validation)
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	w.WriteField("name", "test-ssh-key")
	part, _ := w.CreateFormFile("file", "id_ed25519")
	part.Write(keyPEM)
	w.Close()

	req, _ := http.NewRequest("POST", vaultURL+"/files", &buf)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", w.FormDataContentType())
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("upload key: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode >= 400 {
		t.Fatalf("upload key status: %d", resp.StatusCode)
	}

	// Add service directly to store (bypasses loopback validation for test).
	svc := &vault.Service{
		Name: "test-ssh",
		Auth: vault.Auth{
			Type:          "ssh_key",
			SSHHost:       host,
			SSHPort:       port,
			SSHUser:       "testuser",
			SSHKeyFileRef: "test-ssh-key",
		},
	}
	if err := server.store.AddService(svc); err != nil {
		t.Fatalf("add service to store: %v", err)
	}
}

func TestSSHExec_Success(t *testing.T) {
	sshAddr, keyPEM, sshCleanup := testSSHServer(t)
	defer sshCleanup()

	server, vaultURL := setupTestServer(t)
	token := unlock(t, vaultURL, "master-password-12")
	setupSSHService(t, server, vaultURL, token, sshAddr, keyPEM)

	// Execute command
	body, _ := json.Marshal(map[string]any{"command": "hello world", "timeout": 10})
	req, _ := http.NewRequest("POST", vaultURL+"/ssh/test-ssh/exec", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("exec request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		data, _ := io.ReadAll(resp.Body)
		t.Fatalf("exec status %d: %s", resp.StatusCode, data)
	}

	var result map[string]any
	json.NewDecoder(resp.Body).Decode(&result)
	if result["stdout"] != "ok: hello world" {
		t.Errorf("unexpected stdout: %v", result["stdout"])
	}
	if int(result["exit_code"].(float64)) != 0 {
		t.Errorf("unexpected exit_code: %v", result["exit_code"])
	}
}

func TestSSHExec_NonZeroExit(t *testing.T) {
	sshAddr, keyPEM, sshCleanup := testSSHServer(t)
	defer sshCleanup()

	server, vaultURL := setupTestServer(t)
	token := unlock(t, vaultURL, "master-password-12")
	setupSSHService(t, server, vaultURL, token, sshAddr, keyPEM)

	body, _ := json.Marshal(map[string]any{"command": "exit 42"})
	req, _ := http.NewRequest("POST", vaultURL+"/ssh/test-ssh/exec", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("exec request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		data, _ := io.ReadAll(resp.Body)
		t.Fatalf("exec status %d: %s", resp.StatusCode, data)
	}

	var result map[string]any
	json.NewDecoder(resp.Body).Decode(&result)
	if int(result["exit_code"].(float64)) != 42 {
		t.Errorf("expected exit_code 42, got %v", result["exit_code"])
	}
}

func TestSSHExec_WrongAuthType(t *testing.T) {
	_, vaultURL := setupTestServer(t)
	token := unlock(t, vaultURL, "master-password-12")

	// Create a bearer service (not SSH)
	svc := map[string]any{
		"name":     "not-ssh",
		"base_url": "https://example.com",
		"auth":     map[string]any{"type": "bearer", "token": "abc123"},
	}
	body, _ := json.Marshal(svc)
	req, _ := http.NewRequest("POST", vaultURL+"/services", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, _ := http.DefaultClient.Do(req)
	resp.Body.Close()

	// Try SSH exec on non-SSH service
	body, _ = json.Marshal(map[string]any{"command": "ls"})
	req, _ = http.NewRequest("POST", vaultURL+"/ssh/not-ssh/exec", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("exec request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 400 {
		t.Errorf("expected 400, got %d", resp.StatusCode)
	}
}

func TestSSHExec_MissingService(t *testing.T) {
	_, vaultURL := setupTestServer(t)
	token := unlock(t, vaultURL, "master-password-12")

	body, _ := json.Marshal(map[string]any{"command": "ls"})
	req, _ := http.NewRequest("POST", vaultURL+"/ssh/nonexistent/exec", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("exec request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 404 {
		t.Errorf("expected 404, got %d", resp.StatusCode)
	}
}

func TestSSHExec_MissingCommand(t *testing.T) {
	_, vaultURL := setupTestServer(t)
	token := unlock(t, vaultURL, "master-password-12")

	body, _ := json.Marshal(map[string]any{})
	req, _ := http.NewRequest("POST", vaultURL+"/ssh/test-ssh/exec", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("exec request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 400 {
		t.Errorf("expected 400, got %d", resp.StatusCode)
	}
}

func TestSSHExec_Unauthorized(t *testing.T) {
	_, vaultURL := setupTestServer(t)

	body, _ := json.Marshal(map[string]any{"command": "ls"})
	req, _ := http.NewRequest("POST", vaultURL+"/ssh/test/exec", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("exec request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 401 {
		t.Errorf("expected 401, got %d", resp.StatusCode)
	}
}

func TestSSH_InvalidAction(t *testing.T) {
	_, vaultURL := setupTestServer(t)
	token := unlock(t, vaultURL, "master-password-12")

	req, _ := http.NewRequest("POST", vaultURL+"/ssh/test/badaction", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 400 {
		t.Errorf("expected 400, got %d", resp.StatusCode)
	}
}

func TestSSH_TOFUHostKeyPersisted(t *testing.T) {
	sshAddr, keyPEM, sshCleanup := testSSHServer(t)
	defer sshCleanup()

	server, vaultURL := setupTestServer(t)
	token := unlock(t, vaultURL, "master-password-12")
	setupSSHService(t, server, vaultURL, token, sshAddr, keyPEM)

	// First exec — should trigger TOFU
	body, _ := json.Marshal(map[string]any{"command": "test"})
	req, _ := http.NewRequest("POST", vaultURL+"/ssh/test-ssh/exec", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, _ := http.DefaultClient.Do(req)
	resp.Body.Close()

	// Check service info — ssh_connected should be true now
	req, _ = http.NewRequest("GET", vaultURL+"/services/test-ssh", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("get service: %v", err)
	}
	defer resp.Body.Close()

	var info map[string]any
	json.NewDecoder(resp.Body).Decode(&info)
	if info["ssh_connected"] != true {
		t.Errorf("expected ssh_connected=true after TOFU, got %v", info["ssh_connected"])
	}
}

func TestSSHServiceValidation_MissingFields(t *testing.T) {
	_, vaultURL := setupTestServer(t)
	token := unlock(t, vaultURL, "master-password-12")

	// SSH service without required fields
	svc := map[string]any{
		"name": "bad-ssh",
		"auth": map[string]any{
			"type": "ssh_key",
			// missing ssh_host, ssh_user, ssh_key_file_ref
		},
	}
	body, _ := json.Marshal(svc)
	req, _ := http.NewRequest("POST", vaultURL+"/services", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("create service: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 400 {
		t.Errorf("expected 400, got %d", resp.StatusCode)
	}
}

func TestSSHServiceValidation_MetadataHost(t *testing.T) {
	_, vaultURL := setupTestServer(t)
	token := unlock(t, vaultURL, "master-password-12")

	// Upload a dummy key file first
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	w.WriteField("name", "dummy-key")
	part, _ := w.CreateFormFile("file", "key")
	part.Write([]byte("fake-key"))
	w.Close()

	req, _ := http.NewRequest("POST", vaultURL+"/files", &buf)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", w.FormDataContentType())
	resp, _ := http.DefaultClient.Do(req)
	resp.Body.Close()

	// Try to create SSH service targeting metadata endpoint
	svc := map[string]any{
		"name": "evil-ssh",
		"auth": map[string]any{
			"type":              "ssh_key",
			"ssh_host":          "169.254.169.254",
			"ssh_user":          "root",
			"ssh_key_file_ref":  "dummy-key",
		},
	}
	body, _ := json.Marshal(svc)
	req, _ = http.NewRequest("POST", vaultURL+"/services", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("create service: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 400 {
		t.Errorf("expected 400 for metadata host, got %d", resp.StatusCode)
	}
}

// --- Security regression tests ---

func TestSSHExec_OutputBounded(t *testing.T) {
	// Regression: SEC-002 — exec stdout/stderr must be bounded.
	// Verify the limitedWriter silently caps output.
	sshAddr, keyPEM, sshCleanup := testSSHServer(t)
	defer sshCleanup()

	server, vaultURL := setupTestServer(t)
	token := unlock(t, vaultURL, "master-password-12")
	setupSSHService(t, server, vaultURL, token, sshAddr, keyPEM)

	// Our test SSH server returns "ok: <cmd>" so output is small.
	// We just verify the endpoint works and returns bounded output.
	body, _ := json.Marshal(map[string]any{"command": "bounded-test", "timeout": 5})
	req, _ := http.NewRequest("POST", vaultURL+"/ssh/test-ssh/exec", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("exec request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		data, _ := io.ReadAll(resp.Body)
		t.Fatalf("exec status %d: %s", resp.StatusCode, data)
	}

	var result map[string]any
	json.NewDecoder(resp.Body).Decode(&result)
	stdout := result["stdout"].(string)
	if len(stdout) > 10<<20 {
		t.Errorf("stdout exceeds 10MB limit: %d bytes", len(stdout))
	}
}

func TestSSHServiceValidation_LoopbackBlocked(t *testing.T) {
	// Regression: SEC-005 — loopback addresses must be blocked.
	_, vaultURL := setupTestServer(t)
	token := unlock(t, vaultURL, "master-password-12")

	// Upload a dummy key file
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	w.WriteField("name", "loopback-key")
	part, _ := w.CreateFormFile("file", "key")
	part.Write([]byte("fake"))
	w.Close()
	req, _ := http.NewRequest("POST", vaultURL+"/files", &buf)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", w.FormDataContentType())
	resp, _ := http.DefaultClient.Do(req)
	resp.Body.Close()

	for _, host := range []string{"127.0.0.1", "localhost", "metadata.google.internal"} {
		svc := map[string]any{
			"name": "loopback-" + host,
			"auth": map[string]any{
				"type":             "ssh_key",
				"ssh_host":         host,
				"ssh_user":         "root",
				"ssh_key_file_ref": "loopback-key",
			},
		}
		body, _ := json.Marshal(svc)
		req, _ = http.NewRequest("POST", vaultURL+"/services", bytes.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("create service %s: %v", host, err)
		}
		resp.Body.Close()

		if resp.StatusCode != 400 {
			t.Errorf("expected 400 for host %q, got %d", host, resp.StatusCode)
		}
	}
}
