package api

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/alamparelli/vault-proxy/internal/vault"
)

// pendingOAuth2Flow holds state for an in-progress OAuth2 authorization.
type pendingOAuth2Flow struct {
	State            string
	ServiceName      string
	BaseURL          string
	TLSSkipVerify    bool
	ClientID         string
	ClientSecret     string
	TokenURL         string
	AuthURI          string
	RedirectURI      string
	Scopes           []string
	CreatedAt        time.Time
}

const (
	oauth2FlowTimeout  = 5 * time.Minute
	maxPendingFlows    = 10
)

// oauth2Authorize handles POST /auth/oauth2/authorize
// Starts an interactive OAuth2 consent flow using an uploaded client_secret file.
func (s *Server) oauth2Authorize(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		ClientSecretFile string   `json:"client_secret_file"`
		ServiceName      string   `json:"service_name"`
		BaseURL          string   `json:"base_url"`
		Scopes           []string `json:"scopes"`
		TLSSkipVerify    bool     `json:"tls_skip_verify,omitempty"`
		RedirectURI      string   `json:"redirect_uri,omitempty"` // override redirect_uri from client_secret file
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxJSONBodySize)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), http.StatusBadRequest)
		return
	}

	if req.ClientSecretFile == "" || req.ServiceName == "" || req.BaseURL == "" {
		http.Error(w, `{"error":"client_secret_file, service_name, and base_url are required"}`, http.StatusBadRequest)
		return
	}
	if len(req.ServiceName) > maxServiceNameLen || !validServiceName.MatchString(req.ServiceName) {
		http.Error(w, `{"error":"invalid service name"}`, http.StatusBadRequest)
		return
	}
	if err := validateBaseURL(req.BaseURL, req.TLSSkipVerify); err != nil {
		http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), http.StatusBadRequest)
		return
	}

	// Parse client_secret file
	creds, err := s.parseClientSecretFile(req.ClientSecretFile)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), http.StatusBadRequest)
		return
	}

	// Determine redirect URI: explicit override > file-based selection.
	var redirectURI string
	if req.RedirectURI != "" {
		// Caller-specified override — must be present in the file's redirect_uris for Google to accept it.
		redirectURI = req.RedirectURI
	} else if len(creds.RedirectURIs) == 0 {
		http.Error(w, `{"error":"client_secret file has no redirect_uris configured"}`, http.StatusBadRequest)
		return
	} else {
		// Find a localhost redirect URI, or use the first one.
		redirectURI = creds.RedirectURIs[0]
		for _, uri := range creds.RedirectURIs {
			if strings.Contains(uri, "localhost") || strings.Contains(uri, "127.0.0.1") {
				redirectURI = uri
				break
			}
		}
	}

	// Generate state parameter
	stateBytes := make([]byte, 16)
	if _, err := rand.Read(stateBytes); err != nil {
		http.Error(w, `{"error":"failed to generate state"}`, http.StatusInternalServerError)
		return
	}
	state := hex.EncodeToString(stateBytes)

	tokenURL := "https://oauth2.googleapis.com/token"
	if creds.TokenURI != "" {
		tokenURL = creds.TokenURI
	}
	authURI := "https://accounts.google.com/o/oauth2/v2/auth"
	if creds.AuthURI != "" {
		authURI = creds.AuthURI
	}

	// Store pending flow
	flow := &pendingOAuth2Flow{
		State:         state,
		ServiceName:   req.ServiceName,
		BaseURL:       req.BaseURL,
		TLSSkipVerify: req.TLSSkipVerify,
		ClientID:      creds.ClientID,
		ClientSecret:  creds.ClientSecret,
		TokenURL:      tokenURL,
		AuthURI:       authURI,
		RedirectURI:   redirectURI,
		Scopes:        req.Scopes,
		CreatedAt:     time.Now(),
	}

	s.pendingFlowsMu.Lock()
	// Clean expired flows
	for k, f := range s.pendingFlows {
		if time.Since(f.CreatedAt) > oauth2FlowTimeout {
			delete(s.pendingFlows, k)
		}
	}
	if len(s.pendingFlows) >= maxPendingFlows {
		s.pendingFlowsMu.Unlock()
		http.Error(w, `{"error":"too many pending authorization flows"}`, http.StatusTooManyRequests)
		return
	}
	s.pendingFlows[state] = flow
	s.pendingFlowsMu.Unlock()

	// Build authorization URL
	params := url.Values{
		"client_id":     {creds.ClientID},
		"redirect_uri":  {redirectURI},
		"response_type": {"code"},
		"state":         {state},
		"access_type":   {"offline"},
		"prompt":        {"consent"},
	}
	if len(req.Scopes) > 0 {
		params.Set("scope", strings.Join(req.Scopes, " "))
	}

	authURL := authURI + "?" + params.Encode()

	log.Printf("oauth2 flow started for service %q (state=%s...)", req.ServiceName, state[:8])
	writeJSON(w, http.StatusOK, map[string]string{
		"auth_url":     authURL,
		"state":        state,
		"redirect_uri": redirectURI,
		"message":      "Open auth_url in your browser to authorize. The callback will create the service automatically.",
	})
}

// oauth2Callback handles GET /auth/oauth2/callback
// Receives the authorization code from Google and exchanges it for tokens.
func (s *Server) oauth2Callback(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")
	errParam := r.URL.Query().Get("error")

	if errParam != "" {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, "<html><body><h2>Authorization failed</h2><p>%s</p><p>You can close this tab.</p></body></html>", html.EscapeString(errParam))
		return
	}

	if code == "" || state == "" {
		http.Error(w, `{"error":"missing code or state parameter"}`, http.StatusBadRequest)
		return
	}

	// Look up pending flow
	s.pendingFlowsMu.Lock()
	flow, ok := s.pendingFlows[state]
	if ok {
		delete(s.pendingFlows, state)
	}
	s.pendingFlowsMu.Unlock()

	if !ok {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(w, "<html><body><h2>Invalid or expired authorization</h2><p>The authorization link has expired. Please start a new flow.</p></body></html>")
		return
	}

	if time.Since(flow.CreatedAt) > oauth2FlowTimeout {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(w, "<html><body><h2>Authorization expired</h2><p>Please start a new flow.</p></body></html>")
		return
	}

	// Exchange code for tokens
	tokenResult, err := s.exchangeAuthCode(r.Context(), flow, code)
	if err != nil {
		log.Printf("oauth2 callback: token exchange failed for %s: %v", flow.ServiceName, err)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, "<html><body><h2>Token exchange failed</h2><p>%s</p><p>You can close this tab and try again.</p></body></html>", "Failed to exchange authorization code for tokens.")
		return
	}

	if tokenResult.RefreshToken == "" {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(w, "<html><body><h2>No refresh token received</h2><p>Google did not return a refresh token. Make sure the app has 'offline' access and try revoking access at <a href='https://myaccount.google.com/permissions'>myaccount.google.com/permissions</a> before retrying.</p></body></html>")
		return
	}

	// Create the service
	svc := &vault.Service{
		Name:          flow.ServiceName,
		BaseURL:       flow.BaseURL,
		TLSSkipVerify: flow.TLSSkipVerify,
		Auth: vault.Auth{
			Type:         "oauth2_client",
			ClientID:     flow.ClientID,
			ClientSecret: flow.ClientSecret,
			RefreshToken: tokenResult.RefreshToken,
			TokenURL:     flow.TokenURL,
			AccessToken:  tokenResult.AccessToken,
			ExpiresAt:    tokenResult.ExpiresAt,
			Scopes:       flow.Scopes,
		},
	}

	if err := s.store.AddService(svc); err != nil {
		log.Printf("oauth2 callback: failed to create service %s: %v", flow.ServiceName, err)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, "<html><body><h2>Failed to create service</h2><p>%s</p></body></html>", "Service could not be saved to the vault.")
		return
	}

	log.Printf("oauth2 flow completed: service %q created via browser authorization", flow.ServiceName)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	escapedName := html.EscapeString(flow.ServiceName)
	fmt.Fprintf(w, `<html><body>
<h2>Authorization successful</h2>
<p>Service <strong>%s</strong> has been created and is ready to use.</p>
<p>You can now proxy requests to: <code>/proxy/%s/...</code></p>
<p>You can close this tab.</p>
</body></html>`, escapedName, escapedName)
}

// exchangeAuthCode exchanges an authorization code for access and refresh tokens.
func (s *Server) exchangeAuthCode(ctx context.Context, flow *pendingOAuth2Flow, code string) (*tokenExchangeResult, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	data := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"client_id":     {flow.ClientID},
		"client_secret": {flow.ClientSecret},
		"redirect_uri":  {flow.RedirectURI},
	}

	req, err := http.NewRequestWithContext(ctx, "POST", flow.TokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("build token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := s.proxyClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("token request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("read token response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("token exchange failed (HTTP %d): %s", resp.StatusCode, body)
	}

	var tokenResp struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		ExpiresIn    int64  `json:"expires_in"`
		TokenType    string `json:"token_type"`
	}
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return nil, fmt.Errorf("parse token response: %w", err)
	}

	return &tokenExchangeResult{
		AccessToken:  tokenResp.AccessToken,
		RefreshToken: tokenResp.RefreshToken,
		ExpiresAt:    time.Now().Unix() + tokenResp.ExpiresIn,
	}, nil
}

type tokenExchangeResult struct {
	AccessToken  string
	RefreshToken string
	ExpiresAt    int64
}

// parseClientSecretFile reads and parses a Google client_secret JSON file from the vault.
func (s *Server) parseClientSecretFile(name string) (*googleClientCredentialsFull, error) {
	f, err := s.store.GetFile(name)
	if err != nil {
		return nil, fmt.Errorf("client_secret_file %q: %w", name, err)
	}

	var csJSON struct {
		Installed *googleClientCredentialsFull `json:"installed"`
		Web       *googleClientCredentialsFull `json:"web"`
	}
	if err := json.Unmarshal(f.Data, &csJSON); err != nil {
		return nil, fmt.Errorf("parse client_secret file: %w", err)
	}

	creds := csJSON.Installed
	if creds == nil {
		creds = csJSON.Web
	}
	if creds == nil || creds.ClientID == "" || creds.ClientSecret == "" {
		return nil, fmt.Errorf("client_secret file missing client_id or client_secret")
	}

	return creds, nil
}

// googleClientCredentialsFull extends googleClientCredentials with auth_uri and redirect_uris.
type googleClientCredentialsFull struct {
	ClientID     string   `json:"client_id"`
	ClientSecret string   `json:"client_secret"`
	TokenURI     string   `json:"token_uri"`
	AuthURI      string   `json:"auth_uri"`
	RedirectURIs []string `json:"redirect_uris"`
}

// initPendingFlows initializes the pending flows map (called from NewServer).
func initPendingFlows() (map[string]*pendingOAuth2Flow, *sync.Mutex) {
	return make(map[string]*pendingOAuth2Flow), &sync.Mutex{}
}
