package api

import (
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/alessandrolamparelli/vault-proxy/internal/vault"
)

const (
	defaultTimeout     = 30 * time.Second
	maxRequestBodySize = 10 << 20 // 10 MB
)

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

	// Validate target URL scheme
	if !strings.HasPrefix(targetURL, "https://") && !strings.HasPrefix(targetURL, "http://127.0.0.1") && !strings.HasPrefix(targetURL, "http://localhost") {
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

	// Inject auth
	if err := injectAuth(outReq, &svc.Auth); err != nil {
		http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), http.StatusInternalServerError)
		return
	}

	// Send request — disable redirects to prevent SSRF via 302
	client := &http.Client{
		Timeout: defaultTimeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return errors.New("redirects disabled for security")
		},
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
		http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	log.Printf("proxy %s %s /%s -> %d (%s) token=%s", r.Method, serviceName, apiPath, resp.StatusCode, duration, tokenID)

	// Copy response headers
	for k, vv := range resp.Header {
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

// injectAuth adds authentication to the outbound request.
func injectAuth(req *http.Request, auth *vault.Auth) error {
	switch auth.Type {
	case "bearer":
		req.Header.Set("Authorization", "Bearer "+auth.Token)
	case "header":
		// Validate header name against denylist
		if deniedHeaders[strings.ToLower(auth.HeaderName)] {
			return fmt.Errorf("header %q is not allowed for auth injection", auth.HeaderName)
		}
		req.Header.Set(auth.HeaderName, auth.HeaderValue)
	case "basic":
		encoded := base64.StdEncoding.EncodeToString(
			[]byte(auth.Username + ":" + auth.Password),
		)
		req.Header.Set("Authorization", "Basic "+encoded)
	default:
		return fmt.Errorf("unsupported auth type: %s", auth.Type)
	}
	return nil
}
