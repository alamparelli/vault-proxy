package api

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/alamparelli/vault-proxy/internal/vault"
)

const maxServiceNameLen = 128

var validServiceName = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]*$`)

// listServicesHandler handles GET /services
func (s *Server) listServicesHandler(w http.ResponseWriter, r *http.Request) {
	services, err := s.store.ListServices()
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), http.StatusServiceUnavailable)
		return
	}
	writeJSON(w, http.StatusOK, services)
}

// getServiceHandler handles GET /services/{name}
func (s *Server) getServiceHandler(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimPrefix(r.URL.Path, "/services/")
	if name == "" {
		http.Error(w, `{"error":"missing service name"}`, http.StatusBadRequest)
		return
	}

	svc, err := s.store.GetService(name)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), http.StatusNotFound)
		return
	}
	writeJSON(w, http.StatusOK, svc.SafeInfo())
}

// addServiceHandler handles POST /services
func (s *Server) addServiceHandler(w http.ResponseWriter, r *http.Request) {
	var svc vault.Service
	r.Body = http.MaxBytesReader(w, r.Body, maxJSONBodySize)
	if err := json.NewDecoder(r.Body).Decode(&svc); err != nil {
		http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), http.StatusBadRequest)
		return
	}
	if svc.Name == "" || svc.BaseURL == "" || svc.Auth.Type == "" {
		http.Error(w, `{"error":"name, base_url, and auth.type are required"}`, http.StatusBadRequest)
		return
	}
	if len(svc.Name) > maxServiceNameLen || !validServiceName.MatchString(svc.Name) {
		http.Error(w, `{"error":"service name must be 1-128 chars, alphanumeric/hyphens/dots/underscores"}`, http.StatusBadRequest)
		return
	}

	if err := validateBaseURL(svc.BaseURL, svc.TLSSkipVerify); err != nil {
		http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), http.StatusBadRequest)
		return
	}

	if err := s.validateAuthType(&svc); err != nil {
		http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), http.StatusBadRequest)
		return
	}

	if err := s.store.AddService(&svc); err != nil {
		http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusCreated, svc.SafeInfo())
}

// deleteServiceHandler handles DELETE /services/{name}
func (s *Server) deleteServiceHandler(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimPrefix(r.URL.Path, "/services/")
	if name == "" {
		http.Error(w, `{"error":"missing service name"}`, http.StatusBadRequest)
		return
	}

	if err := s.store.RemoveService(name); err != nil {
		http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), http.StatusNotFound)
		return
	}
	// SEC-002: Clean up refresh lock to prevent unbounded map growth
	s.removeRefreshLock(name)
	s.CancelTokenRefresh(name)
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

// validateAuthType checks that auth-type-specific required fields are present.
func (s *Server) validateAuthType(svc *vault.Service) error {
	switch svc.Auth.Type {
	case "bearer":
		if svc.Auth.Token == "" {
			return fmt.Errorf("bearer auth requires token")
		}
	case "header":
		if svc.Auth.HeaderName == "" || svc.Auth.HeaderValue == "" {
			return fmt.Errorf("header auth requires header_name and header_value")
		}
	case "basic":
		if svc.Auth.Username == "" || svc.Auth.Password == "" {
			return fmt.Errorf("basic auth requires username and password")
		}
	case "oauth2_client":
		// If file refs are provided, resolve from uploaded Google files
		if svc.Auth.ClientSecretFile != "" || svc.Auth.TokenFile != "" {
			if err := s.resolveGoogleOAuth2(svc); err != nil {
				return err
			}
		}
		if svc.Auth.ClientID == "" || svc.Auth.ClientSecret == "" || svc.Auth.TokenURL == "" || svc.Auth.RefreshToken == "" {
			return fmt.Errorf("oauth2_client requires client_id, client_secret, token_url, and refresh_token (or client_secret_file + token_file)")
		}
		if err := validateBaseURL(svc.Auth.TokenURL, svc.TLSSkipVerify); err != nil {
			return fmt.Errorf("invalid token_url: %w", err)
		}
	case "service_account":
		if svc.Auth.FileRef == "" {
			return fmt.Errorf("service_account requires file_ref")
		}
		// Validate file exists in store
		if _, err := s.store.GetFile(svc.Auth.FileRef); err != nil {
			return fmt.Errorf("file_ref %q: %w", svc.Auth.FileRef, err)
		}
		if svc.Auth.SATokenURL != "" {
			if err := validateBaseURL(svc.Auth.SATokenURL, svc.TLSSkipVerify); err != nil {
				return fmt.Errorf("invalid sa_token_url: %w", err)
			}
		}
	default:
		return fmt.Errorf("unsupported auth type: %s", svc.Auth.Type)
	}
	return nil
}

// resolveGoogleOAuth2 reads the uploaded Google client_secret and token files
// and populates the oauth2_client fields (client_id, client_secret, refresh_token, token_url).
func (s *Server) resolveGoogleOAuth2(svc *vault.Service) error {
	if svc.Auth.ClientSecretFile == "" || svc.Auth.TokenFile == "" {
		return fmt.Errorf("both client_secret_file and token_file are required when using file-based setup")
	}

	// Parse client_secret file
	csFile, err := s.store.GetFile(svc.Auth.ClientSecretFile)
	if err != nil {
		return fmt.Errorf("client_secret_file %q: %w", svc.Auth.ClientSecretFile, err)
	}
	var csJSON struct {
		Installed *googleClientCredentials `json:"installed"`
		Web       *googleClientCredentials `json:"web"`
	}
	if err := json.Unmarshal(csFile.Data, &csJSON); err != nil {
		return fmt.Errorf("parse client_secret file: %w", err)
	}
	creds := csJSON.Installed
	if creds == nil {
		creds = csJSON.Web
	}
	if creds == nil || creds.ClientID == "" || creds.ClientSecret == "" {
		return fmt.Errorf("client_secret file missing client_id or client_secret (expected 'installed' or 'web' key)")
	}

	// Parse token file
	tokenFile, err := s.store.GetFile(svc.Auth.TokenFile)
	if err != nil {
		return fmt.Errorf("token_file %q: %w", svc.Auth.TokenFile, err)
	}
	var tokenJSON struct {
		RefreshToken string `json:"refresh_token"`
	}
	if err := json.Unmarshal(tokenFile.Data, &tokenJSON); err != nil {
		return fmt.Errorf("parse token file: %w", err)
	}
	if tokenJSON.RefreshToken == "" {
		return fmt.Errorf("token file missing refresh_token")
	}

	// Determine token URL
	tokenURL := "https://oauth2.googleapis.com/token"
	if len(creds.TokenURI) > 0 {
		tokenURL = creds.TokenURI
	}

	// Populate oauth2_client fields from files
	svc.Auth.ClientID = creds.ClientID
	svc.Auth.ClientSecret = creds.ClientSecret
	svc.Auth.RefreshToken = tokenJSON.RefreshToken
	svc.Auth.TokenURL = tokenURL

	return nil
}

// googleClientCredentials represents the nested credentials in a Google client_secret JSON.
type googleClientCredentials struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	TokenURI     string `json:"token_uri"`
}

// validateBaseURL ensures the URL is HTTPS and does not resolve to private/internal IPs.
// When allowPrivate is true (tls_skip_verify services), HTTP and private IPs are permitted
// (intended for internal/self-signed services).
func validateBaseURL(rawURL string, allowPrivate bool) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("invalid URL: %w", err)
	}
	if u.Host == "" {
		return fmt.Errorf("base_url must have a host")
	}

	if allowPrivate {
		if u.Scheme != "https" && u.Scheme != "http" {
			return fmt.Errorf("base_url must use HTTP or HTTPS")
		}
		// Block well-known cloud metadata hostnames
		host := u.Hostname()
		if host == "metadata.google.internal" || host == "metadata" {
			return fmt.Errorf("base_url must not target cloud metadata services")
		}
		// Still block cloud metadata endpoints even for private services
		ips, err := net.LookupIP(host)
		if err == nil {
			for _, ip := range ips {
				if ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
					return fmt.Errorf("base_url must not resolve to link-local (metadata) IPs")
				}
			}
		}
		log.Printf("WARNING: URL validated with tls_skip_verify=true (SSRF protections relaxed): %s", rawURL)
		return nil
	}

	if u.Scheme != "https" {
		return fmt.Errorf("base_url must use HTTPS")
	}

	host := u.Hostname()
	ips, err := net.LookupIP(host)
	if err != nil {
		return nil // DNS may not resolve at config time; proxy-time check is defense-in-depth
	}
	for _, ip := range ips {
		if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
			return fmt.Errorf("base_url must not resolve to a private or internal IP")
		}
	}
	return nil
}
