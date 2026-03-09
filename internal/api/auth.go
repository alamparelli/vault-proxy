package api

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sync"
	"time"
)

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
	ts.tokens[id] = t
	ts.mu.Unlock()

	return t, nil
}

// Validate checks a token and returns it if valid.
func (ts *TokenStore) Validate(id string) (*Token, error) {
	ts.mu.RLock()
	t, ok := ts.tokens[id]
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
	delete(ts.tokens, id)
	ts.mu.Unlock()
}

// List returns all active (non-expired) tokens.
func (ts *TokenStore) List() []*Token {
	ts.mu.Lock()
	defer ts.mu.Unlock()

	now := time.Now()
	out := make([]*Token, 0, len(ts.tokens))
	for id, t := range ts.tokens {
		if now.After(t.ExpiresAt) {
			delete(ts.tokens, id)
			continue
		}
		out = append(out, t)
	}
	return out
}

// RevokeByPrefix revokes the first token matching the given prefix.
// Returns true if a token was found and revoked.
func (ts *TokenStore) RevokeByPrefix(prefix string) bool {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	for id := range ts.tokens {
		if len(id) >= len(prefix) && id[:len(prefix)] == prefix {
			delete(ts.tokens, id)
			return true
		}
	}
	return false
}

// RevokeAll clears all tokens (used on lock).
func (ts *TokenStore) RevokeAll() {
	ts.mu.Lock()
	ts.tokens = make(map[string]*Token)
	ts.mu.Unlock()
}
