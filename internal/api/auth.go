package api

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"sync"
	"time"
)

// tokenHash returns a SHA-256 hash of the token ID for use as a map key.
// This prevents timing side-channels in map lookups.
func tokenHash(id string) string {
	h := sha256.Sum256([]byte(id))
	return hex.EncodeToString(h[:])
}

// TokenScope defines what a token can do.
type TokenScope string

const (
	ScopeAdmin TokenScope = "admin"
	ScopeProxy TokenScope = "proxy"
)

// Token represents an active session token.
type Token struct {
	ID        string     `json:"id"`
	Scope     TokenScope `json:"scope"`
	CreatedAt time.Time  `json:"created_at"`
	ExpiresAt time.Time  `json:"expires_at"`
}

// TokenStore manages session tokens in memory.
type TokenStore struct {
	mu     sync.RWMutex
	tokens map[string]*Token
	ttl    time.Duration
}

// NewTokenStore creates a token store with the given TTL.
func NewTokenStore(ttl time.Duration) *TokenStore {
	return &TokenStore{
		tokens: make(map[string]*Token),
		ttl:    ttl,
	}
}

// StartCleanup runs a background goroutine that periodically purges expired tokens.
func (ts *TokenStore) StartCleanup(interval time.Duration) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for range ticker.C {
			ts.List() // List already purges expired tokens
		}
	}()
}

// Create generates a new token with the given scope.
func (ts *TokenStore) Create(scope TokenScope) (*Token, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return nil, fmt.Errorf("generate token: %w", err)
	}

	id := hex.EncodeToString(raw)
	now := time.Now()
	t := &Token{
		ID:        id,
		Scope:     scope,
		CreatedAt: now,
		ExpiresAt: now.Add(ts.ttl),
	}

	ts.mu.Lock()
	ts.tokens[tokenHash(id)] = t
	ts.mu.Unlock()

	return t, nil
}

// Validate checks a token and returns it if valid.
func (ts *TokenStore) Validate(id string) (*Token, error) {
	ts.mu.RLock()
	t, ok := ts.tokens[tokenHash(id)]
	ts.mu.RUnlock()

	if !ok {
		return nil, fmt.Errorf("invalid token")
	}
	if time.Now().After(t.ExpiresAt) {
		ts.Revoke(id)
		return nil, fmt.Errorf("token expired")
	}
	return t, nil
}

// Revoke removes a token.
func (ts *TokenStore) Revoke(id string) {
	ts.mu.Lock()
	delete(ts.tokens, tokenHash(id))
	ts.mu.Unlock()
}

// List returns all active (non-expired) tokens.
func (ts *TokenStore) List() []*Token {
	ts.mu.Lock()
	defer ts.mu.Unlock()

	now := time.Now()
	out := make([]*Token, 0, len(ts.tokens))
	for key, t := range ts.tokens {
		if now.After(t.ExpiresAt) {
			delete(ts.tokens, key)
			continue
		}
		out = append(out, t)
	}
	return out
}

// RevokeByPrefix revokes a token matching the given prefix.
// Returns an error if no match or ambiguous (multiple matches).
func (ts *TokenStore) RevokeByPrefix(prefix string) error {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	var matchKey string
	for key, t := range ts.tokens {
		if len(t.ID) >= len(prefix) &&
			subtle.ConstantTimeCompare([]byte(t.ID[:len(prefix)]), []byte(prefix)) == 1 {
			if matchKey != "" {
				return fmt.Errorf("ambiguous prefix: matches multiple tokens")
			}
			matchKey = key
		}
	}
	if matchKey == "" {
		return fmt.Errorf("no token found")
	}
	delete(ts.tokens, matchKey)
	return nil
}

// RevokeAll clears all tokens (used on lock).
func (ts *TokenStore) RevokeAll() {
	ts.mu.Lock()
	ts.tokens = make(map[string]*Token)
	ts.mu.Unlock()
}
