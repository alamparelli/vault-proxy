// Package client is a portable HTTP client for vault-server.
// Any Go project can import this — no internal dependencies.
package client

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

const (
	defaultAddr = "http://127.0.0.1:8390"
	envAddr     = "VAULT_ADDR"
	envToken    = "VAULT_TOKEN"
)

// Client talks to the vault server. Portable — any Go tool can import this.
type Client struct {
	Addr   string
	Token  string
	client *http.Client
}

// New creates a client from environment variables.
func New() *Client {
	addr := os.Getenv(envAddr)
	if addr == "" {
		addr = defaultAddr
	}
	return &Client{
		Addr:   strings.TrimRight(addr, "/"),
		Token:  os.Getenv(envToken),
		client: &http.Client{Timeout: 60 * time.Second},
	}
}

// NewWithToken creates a client with explicit addr and token.
func NewWithToken(addr, token string) *Client {
	if addr == "" {
		addr = defaultAddr
	}
	return &Client{
		Addr:   strings.TrimRight(addr, "/"),
		Token:  token,
		client: &http.Client{Timeout: 60 * time.Second},
	}
}

// Health checks the vault server status.
func (c *Client) Health() (string, error) {
	resp, err := c.do("GET", "/health", nil)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	var result struct {
		Status string `json:"status"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", err
	}
	return result.Status, nil
}

// Unlock authenticates with the master password. Returns an admin token.
func (c *Client) Unlock(password string) (string, error) {
	body, _ := json.Marshal(map[string]string{"password": password})
	resp, err := c.do("POST", "/auth/unlock", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", readError(resp)
	}

	var token struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&token); err != nil {
		return "", err
	}
	return token.ID, nil
}

// Lock locks the vault.
func (c *Client) Lock() error {
	resp, err := c.do("POST", "/auth/lock", nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return readError(resp)
	}
	return nil
}

// ListServices returns all configured services (no secrets).
func (c *Client) ListServices() ([]ServiceInfo, error) {
	resp, err := c.do("GET", "/services", nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, readError(resp)
	}

	var services []ServiceInfo
	if err := json.NewDecoder(resp.Body).Decode(&services); err != nil {
		return nil, err
	}
	return services, nil
}

// AddService creates or updates a service. The payload is raw JSON
// matching vault-server's POST /services schema.
func (c *Client) AddService(jsonPayload io.Reader) error {
	resp, err := c.do("POST", "/services", jsonPayload)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return readError(resp)
	}
	return nil
}

// RemoveService deletes a service by name.
func (c *Client) RemoveService(name string) error {
	resp, err := c.do("DELETE", "/services/"+name, nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return readError(resp)
	}
	return nil
}

// TestService tests connectivity of a service by proxying a GET to its base URL.
func (c *Client) TestService(name string) error {
	resp, err := c.do("GET", "/proxy/"+name+"/", nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 500 {
		return readError(resp)
	}
	return nil
}

// CreateToken creates a new token with the given scope.
func (c *Client) CreateToken(scope string) (string, error) {
	body, _ := json.Marshal(map[string]string{"scope": scope})
	resp, err := c.do("POST", "/tokens", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		return "", readError(resp)
	}

	var token struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&token); err != nil {
		return "", err
	}
	return token.ID, nil
}

// ListTokens returns active tokens (no secret material).
func (c *Client) ListTokens() ([]TokenInfo, error) {
	resp, err := c.do("GET", "/tokens", nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, readError(resp)
	}

	var tokens []TokenInfo
	if err := json.NewDecoder(resp.Body).Decode(&tokens); err != nil {
		return nil, err
	}
	return tokens, nil
}

// RevokeToken revokes a token by ID.
func (c *Client) RevokeToken(id string) error {
	resp, err := c.do("DELETE", "/tokens/"+id, nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return readError(resp)
	}
	return nil
}

// Proxy sends an HTTP request through the vault proxy.
// Returns the raw response for the caller to handle (streaming, etc).
func (c *Client) Proxy(service, method, path string, body io.Reader) (*http.Response, error) {
	endpoint := fmt.Sprintf("/proxy/%s/%s", service, strings.TrimPrefix(path, "/"))
	return c.do(method, endpoint, body)
}

func (c *Client) do(method, path string, body io.Reader) (*http.Response, error) {
	url := c.Addr + path
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return nil, err
	}

	if c.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	return c.client.Do(req)
}

func readError(resp *http.Response) error {
	data, _ := io.ReadAll(resp.Body)
	return fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(data))
}
