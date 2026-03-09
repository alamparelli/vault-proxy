package api

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"

	"github.com/alessandrolamparelli/vault-proxy/internal/vault"
)

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

	if err := validateBaseURL(svc.BaseURL, svc.TLSSkipVerify); err != nil {
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
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
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
		// Still block cloud metadata endpoints even for private services
		host := u.Hostname()
		ips, err := net.LookupIP(host)
		if err == nil {
			for _, ip := range ips {
				if ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
					return fmt.Errorf("base_url must not resolve to link-local (metadata) IPs")
				}
			}
		}
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
