package api

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/alessandrolamparelli/vault-proxy/internal/vault"
)

type contextKey string

const tokenContextKey contextKey = "vault-token"

const maxJSONBodySize = 1 << 20 // 1 MB for JSON endpoints

// Server is the vault HTTP API server.
type Server struct {
	store  *vault.Store
	tokens *TokenStore
	mux    *http.ServeMux

	// Brute-force protection
	unlockMu       sync.Mutex
	unlockFailures int
	unlockLockout  time.Time
}

// NewServer creates a new API server.
func NewServer(store *vault.Store, tokenTTL time.Duration) *Server {
	s := &Server{
		store:  store,
		tokens: NewTokenStore(tokenTTL),
		mux:    http.NewServeMux(),
	}
	s.routes()
	return s
}

func (s *Server) routes() {
	s.mux.HandleFunc("/health", s.healthHandler)
	s.mux.HandleFunc("/auth/unlock", s.unlockHandler)
	s.mux.HandleFunc("/auth/lock", s.requireAuth(ScopeProxy, s.lockHandler))

	// Token management (admin only)
	s.mux.HandleFunc("/tokens", s.requireAuth(ScopeAdmin, s.tokensHandler))
	s.mux.HandleFunc("/tokens/", s.requireAuth(ScopeAdmin, s.revokeTokenHandler))

	// Services (GET = proxy scope, mutations = admin scope)
	s.mux.HandleFunc("/services", s.servicesRouter)
	s.mux.HandleFunc("/services/", s.requireAuth(ScopeProxy, s.servicesDetailRouter))

	// Proxy (proxy scope)
	s.mux.HandleFunc("/proxy/", s.requireAuth(ScopeProxy, s.proxyHandler))
}

// ServeHTTP implements http.Handler.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mux.ServeHTTP(w, r)
}

// --- Auth handlers ---

func (s *Server) healthHandler(w http.ResponseWriter, r *http.Request) {
	status := "locked"
	if !s.store.IsLocked() {
		status = "unlocked"
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": status})
}

func (s *Server) unlockHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	// Brute-force protection
	s.unlockMu.Lock()
	if time.Now().Before(s.unlockLockout) {
		remaining := time.Until(s.unlockLockout).Seconds()
		s.unlockMu.Unlock()
		http.Error(w, fmt.Sprintf(`{"error":"too many attempts, retry in %.0fs"}`, remaining), http.StatusTooManyRequests)
		return
	}
	s.unlockMu.Unlock()

	var req struct {
		Password string `json:"password"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxJSONBodySize)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Password == "" {
		http.Error(w, `{"error":"password required"}`, http.StatusBadRequest)
		return
	}

	if err := s.store.Unlock([]byte(req.Password)); err != nil {
		s.unlockMu.Lock()
		s.unlockFailures++
		if s.unlockFailures >= 5 {
			lockoutDuration := time.Duration(1<<min(s.unlockFailures-5, 6)) * 30 * time.Second
			s.unlockLockout = time.Now().Add(lockoutDuration)
			log.Printf("unlock: %d failures, locked out for %s", s.unlockFailures, lockoutDuration)
		}
		s.unlockMu.Unlock()
		log.Printf("unlock failed: %v", err)
		http.Error(w, `{"error":"unlock failed: wrong password or corrupted vault"}`, http.StatusUnauthorized)
		return
	}

	// Reset failures on success
	s.unlockMu.Lock()
	s.unlockFailures = 0
	s.unlockLockout = time.Time{}
	s.unlockMu.Unlock()

	token, err := s.tokens.Create(ScopeAdmin)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), http.StatusInternalServerError)
		return
	}

	log.Printf("vault unlocked, admin token created")
	writeJSON(w, http.StatusOK, token)
}

func (s *Server) lockHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	s.tokens.RevokeAll()
	s.store.Lock()
	log.Printf("vault locked, all tokens revoked")
	writeJSON(w, http.StatusOK, map[string]string{"status": "locked"})
}

// --- Token handlers ---

// TokenListEntry is a safe view for token listing (masks the full ID).
type TokenListEntry struct {
	IDPrefix  string     `json:"id_prefix"`
	Scope     TokenScope `json:"scope"`
	CreatedAt time.Time  `json:"created_at"`
	ExpiresAt time.Time  `json:"expires_at"`
}

func (s *Server) tokensHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		tokens := s.tokens.List()
		entries := make([]TokenListEntry, len(tokens))
		for i, t := range tokens {
			prefix := t.ID
			if len(prefix) > 8 {
				prefix = prefix[:8] + "..."
			}
			entries[i] = TokenListEntry{
				IDPrefix:  prefix,
				Scope:     t.Scope,
				CreatedAt: t.CreatedAt,
				ExpiresAt: t.ExpiresAt,
			}
		}
		writeJSON(w, http.StatusOK, entries)
	case http.MethodPost:
		var req struct {
			Scope TokenScope `json:"scope"`
		}
		r.Body = http.MaxBytesReader(w, r.Body, maxJSONBodySize)
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, `{"error":"invalid request"}`, http.StatusBadRequest)
			return
		}
		if req.Scope != ScopeAdmin && req.Scope != ScopeProxy {
			http.Error(w, `{"error":"scope must be admin or proxy"}`, http.StatusBadRequest)
			return
		}
		token, err := s.tokens.Create(req.Scope)
		if err != nil {
			http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusCreated, token)
	default:
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
	}
}

func (s *Server) revokeTokenHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/tokens/")
	if id == "" {
		http.Error(w, `{"error":"missing token id"}`, http.StatusBadRequest)
		return
	}
	// Try exact match first, then prefix match (for UI which only has id_prefix).
	if _, err := s.tokens.Validate(id); err == nil {
		s.tokens.Revoke(id)
	} else if err := s.tokens.RevokeByPrefix(id); err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "revoked"})
}

// --- Routers for method dispatch ---

func (s *Server) servicesRouter(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.requireAuth(ScopeProxy, s.listServicesHandler)(w, r)
	case http.MethodPost:
		s.requireAuth(ScopeAdmin, s.addServiceHandler)(w, r)
	default:
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
	}
}

func (s *Server) servicesDetailRouter(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.getServiceHandler(w, r)
	case http.MethodDelete:
		tok := tokenFromContext(r)
		if tok == nil || tok.Scope != ScopeAdmin {
			http.Error(w, `{"error":"admin scope required"}`, http.StatusForbidden)
			return
		}
		s.deleteServiceHandler(w, r)
	default:
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
	}
}

// --- Middleware ---

func (s *Server) requireAuth(minScope TokenScope, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if !strings.HasPrefix(auth, "Bearer ") {
			http.Error(w, `{"error":"authorization required"}`, http.StatusUnauthorized)
			return
		}

		tokenID := strings.TrimPrefix(auth, "Bearer ")
		token, err := s.tokens.Validate(tokenID)
		if err != nil {
			http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), http.StatusUnauthorized)
			return
		}

		if minScope == ScopeAdmin && token.Scope != ScopeAdmin {
			http.Error(w, `{"error":"admin scope required"}`, http.StatusForbidden)
			return
		}

		// Store token in request context (not headers — prevents spoofing)
		ctx := context.WithValue(r.Context(), tokenContextKey, token)
		next(w, r.WithContext(ctx))
	}
}

// tokenFromContext extracts the authenticated token from request context.
func tokenFromContext(r *http.Request) *Token {
	tok, _ := r.Context().Value(tokenContextKey).(*Token)
	return tok
}

// --- Helpers ---

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

// limitedBody wraps the request body with MaxBytesReader.
func limitedBody(w http.ResponseWriter, r *http.Request) io.ReadCloser {
	return http.MaxBytesReader(w, r.Body, maxJSONBodySize)
}
