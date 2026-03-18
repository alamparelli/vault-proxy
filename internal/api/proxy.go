package api

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/alamparelli/vault-proxy/internal/oauth2"
	"github.com/alamparelli/vault-proxy/internal/vault"
)

const (
	defaultTimeout     = 30 * time.Second
	maxRequestBodySize = 10 << 20 // 10 MB
	tokenExpiryBuffer  = 30       // seconds before expiry to trigger refresh
)

// blockedUpstreamHeaders are response headers from upstream that must not be
// forwarded to the client (prevents cookie injection, CORS hijacking, etc).
var blockedUpstreamHeaders = map[string]bool{
	"set-cookie":                       true,
	"access-control-allow-origin":      true,
	"access-control-allow-credentials": true,
	"access-control-allow-methods":     true,
	"access-control-allow-headers":     true,
	"access-control-expose-headers":    true,
	"x-frame-options":                  true,
	"content-security-policy":          true,
	"strict-transport-security":        true,
	"cross-origin-opener-policy":       true,
	"cross-origin-resource-policy":     true,
	"permissions-policy":               true,
}

// Dangerous headers that custom auth should never set.
var deniedHeaders = map[string]bool{
	"host":              true,
	"transfer-encoding": true,
	"content-length":    true,
	"connection":        true,
	"upgrade":           true,
	"te":                true,
	"trailer":           true,
}

// proxyHandler handles /proxy/{service}/{path...}
func (s *Server) proxyHandler(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/proxy/")
	parts := strings.SplitN(path, "/", 2)
	if len(parts) == 0 || parts[0] == "" {
		http.Error(w, `{"error":"missing service name"}`, http.StatusBadRequest)
		return
	}

	serviceName := parts[0]
	apiPath := ""
	if len(parts) > 1 {
		apiPath = parts[1]
	}

	svc, err := s.store.GetService(serviceName)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), http.StatusNotFound)
		return
	}

	// Build target URL
	targetURL := strings.TrimRight(svc.BaseURL, "/")
	if apiPath != "" {
		targetURL += "/" + apiPath
	}
	if r.URL.RawQuery != "" {
		targetURL += "?" + r.URL.RawQuery
	}

	// Validate target URL scheme (defense-in-depth, also validated at service creation)
	if !strings.HasPrefix(targetURL, "https://") && !svc.TLSSkipVerify {
		http.Error(w, `{"error":"service base_url must be HTTPS"}`, http.StatusBadRequest)
		return
	}

	// Build outbound request
	body := http.MaxBytesReader(w, r.Body, maxRequestBodySize)
	outReq, err := http.NewRequestWithContext(r.Context(), r.Method, targetURL, body)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), http.StatusInternalServerError)
		return
	}

	// Copy caller headers — strip auth, internal vault headers, and hop-by-hop
	for k, vv := range r.Header {
		lower := strings.ToLower(k)
		if lower == "authorization" || lower == "host" || lower == "connection" {
			continue
		}
		// Strip internal vault headers (set by middleware via context now, but defense-in-depth)
		if strings.HasPrefix(lower, "x-vault-") {
			continue
		}
		for _, v := range vv {
			outReq.Header.Add(k, v)
		}
	}

	// Inject auth (may trigger OAuth2 refresh)
	if err := s.injectAuth(r.Context(), outReq, svc); err != nil {
		http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), http.StatusInternalServerError)
		return
	}

	// Pick pre-built client (reused across requests, no per-request allocation)
	client := s.proxyClient
	if svc.TLSSkipVerify {
		client = s.proxyClientInsecure
	}
	start := time.Now()
	resp, err := client.Do(outReq)
	duration := time.Since(start)

	tok := tokenFromContext(r)
	tokenID := ""
	if tok != nil && len(tok.ID) >= 8 {
		tokenID = tok.ID[:8]
	}

	if err != nil {
		log.Printf("proxy %s %s %s -> error: %v (%s) token=%s", r.Method, serviceName, apiPath, err, duration, tokenID)
		http.Error(w, `{"error":"upstream request failed"}`, http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	log.Printf("proxy %s %s /%s -> %d (%s) token=%s", r.Method, serviceName, apiPath, resp.StatusCode, duration, tokenID)

	// Copy response headers, filtering out security-sensitive ones
	for k, vv := range resp.Header {
		if blockedUpstreamHeaders[strings.ToLower(k)] {
			continue
		}
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

// injectAuth adds authentication to the outbound request.
// For oauth2_client and service_account types, this handles lazy token refresh.
func (s *Server) injectAuth(ctx context.Context, req *http.Request, svc *vault.Service) error {
	auth := &svc.Auth
	switch auth.Type {
	case "bearer":
		req.Header.Set("Authorization", "Bearer "+auth.Token)
	case "header":
		if deniedHeaders[strings.ToLower(auth.HeaderName)] {
			return fmt.Errorf("header %q is not allowed for auth injection", auth.HeaderName)
		}
		req.Header.Set(auth.HeaderName, auth.HeaderValue)
	case "basic":
		encoded := base64.StdEncoding.EncodeToString(
			[]byte(auth.Username + ":" + auth.Password),
		)
		req.Header.Set("Authorization", "Basic "+encoded)
	case "oauth2_client":
		token, err := s.ensureOAuth2Token(ctx, svc)
		if err != nil {
			return fmt.Errorf("oauth2 refresh: %w", err)
		}
		req.Header.Set("Authorization", "Bearer "+token)
	case "service_account":
		token, err := s.ensureServiceAccountToken(ctx, svc)
		if err != nil {
			return fmt.Errorf("service account exchange: %w", err)
		}
		req.Header.Set("Authorization", "Bearer "+token)
	default:
		return fmt.Errorf("unsupported auth type: %s", auth.Type)
	}
	return nil
}

// getRefreshLock returns the per-service mutex for token refresh.
func (s *Server) getRefreshLock(serviceName string) *sync.Mutex {
	s.refreshMu.Lock()
	defer s.refreshMu.Unlock()

	mu, ok := s.refreshLocks[serviceName]
	if !ok {
		mu = &sync.Mutex{}
		s.refreshLocks[serviceName] = mu
	}
	return mu
}

// removeRefreshLock removes the per-service mutex when a service is deleted.
func (s *Server) removeRefreshLock(serviceName string) {
	s.refreshMu.Lock()
	defer s.refreshMu.Unlock()
	delete(s.refreshLocks, serviceName)
}

// ensureOAuth2Token returns a valid access token, refreshing if needed.
func (s *Server) ensureOAuth2Token(ctx context.Context, svc *vault.Service) (string, error) {
	// Fast path: token still valid
	if svc.Auth.AccessToken != "" && svc.Auth.ExpiresAt > time.Now().Unix()+tokenExpiryBuffer {
		return svc.Auth.AccessToken, nil
	}

	// Acquire per-service lock
	mu := s.getRefreshLock(svc.Name)
	mu.Lock()
	defer mu.Unlock()

	// Double-check after lock — another goroutine may have refreshed
	fresh, err := s.store.GetService(svc.Name)
	if err != nil {
		return "", err
	}
	if fresh.Auth.AccessToken != "" && fresh.Auth.ExpiresAt > time.Now().Unix()+tokenExpiryBuffer {
		return fresh.Auth.AccessToken, nil
	}

	// Refresh
	client := s.proxyClient
	if svc.TLSSkipVerify {
		client = s.proxyClientInsecure
	}
	result, err := oauth2.RefreshAccessToken(ctx, client, fresh.Auth.TokenURL, fresh.Auth.ClientID, fresh.Auth.ClientSecret, fresh.Auth.RefreshToken, fresh.Auth.Scopes)
	if err != nil {
		return "", err
	}

	// Update auth and persist
	updatedAuth := fresh.Auth
	updatedAuth.AccessToken = result.AccessToken
	updatedAuth.ExpiresAt = result.ExpiresAt
	if result.RefreshToken != "" {
		updatedAuth.RefreshToken = result.RefreshToken
	}

	if err := s.store.UpdateServiceAuth(svc.Name, updatedAuth); err != nil {
		log.Printf("warning: failed to persist refreshed token for %s: %v", svc.Name, err)
	}

	// Schedule proactive refresh for the new token.
	s.ScheduleTokenRefresh(svc.Name, updatedAuth.ExpiresAt)

	return result.AccessToken, nil
}

// ensureServiceAccountToken returns a valid SA access token, exchanging JWT if needed.
func (s *Server) ensureServiceAccountToken(ctx context.Context, svc *vault.Service) (string, error) {
	// Fast path: token still valid
	if svc.Auth.SAToken != "" && svc.Auth.SAExpiresAt > time.Now().Unix()+tokenExpiryBuffer {
		return svc.Auth.SAToken, nil
	}

	mu := s.getRefreshLock(svc.Name)
	mu.Lock()
	defer mu.Unlock()

	// Double-check after lock
	fresh, err := s.store.GetService(svc.Name)
	if err != nil {
		return "", err
	}
	if fresh.Auth.SAToken != "" && fresh.Auth.SAExpiresAt > time.Now().Unix()+tokenExpiryBuffer {
		return fresh.Auth.SAToken, nil
	}

	// Load SA JSON file from vault
	f, err := s.store.GetFile(fresh.Auth.FileRef)
	if err != nil {
		return "", fmt.Errorf("load service account file %q: %w", fresh.Auth.FileRef, err)
	}

	client := s.proxyClient
	if svc.TLSSkipVerify {
		client = s.proxyClientInsecure
	}
	result, err := oauth2.ExchangeServiceAccountJWT(ctx, client, f.Data, fresh.Auth.SAScopes, fresh.Auth.SATokenURL)
	if err != nil {
		return "", err
	}

	// Persist
	updatedAuth := fresh.Auth
	updatedAuth.SAToken = result.AccessToken
	updatedAuth.SAExpiresAt = result.ExpiresAt

	if err := s.store.UpdateServiceAuth(svc.Name, updatedAuth); err != nil {
		log.Printf("warning: failed to persist SA token for %s: %v", svc.Name, err)
	}

	// Schedule proactive refresh for the new token.
	s.ScheduleTokenRefresh(svc.Name, updatedAuth.SAExpiresAt)

	return result.AccessToken, nil
}
