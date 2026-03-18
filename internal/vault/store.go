package vault

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/alamparelli/vault-proxy/internal/crypto"
)

const vaultFile = "vault.enc"
const backupFile = "vault.enc.bak"

// Store manages the in-memory vault with encrypted file persistence.
type Store struct {
	mu       sync.RWMutex
	vault    *Vault
	password []byte
	dataDir  string
	locked   bool
}

// NewStore creates a new vault store. Call Unlock to load or create the vault.
func NewStore(dataDir string) *Store {
	return &Store{
		dataDir: dataDir,
		locked:  true,
	}
}

// Unlock decrypts the vault file with the given password.
// If no vault file exists, creates a new empty vault.
func (s *Store) Unlock(password []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	path := filepath.Join(s.dataDir, vaultFile)
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		// First run: enforce minimum password strength
		if len(password) < 8 {
			return fmt.Errorf("master password must be at least 8 characters")
		}
		s.vault = &Vault{
			Services: make(map[string]*Service),
			Files:    make(map[string]*File),
		}
		s.password = append([]byte{}, password...)
		s.locked = false
		return s.saveLocked()
	}
	if err != nil {
		return fmt.Errorf("read vault file: %w", err)
	}

	plaintext, err := crypto.Decrypt(data, password)
	if err != nil {
		return err
	}
	defer wipeBytes(plaintext)

	var v Vault
	if err := json.Unmarshal(plaintext, &v); err != nil {
		return fmt.Errorf("parse vault: %w", err)
	}
	if v.Services == nil {
		v.Services = make(map[string]*Service)
	}
	if v.Files == nil {
		v.Files = make(map[string]*File)
	}

	s.vault = &v
	s.password = append([]byte{}, password...)
	s.locked = false
	return nil
}

// Lock clears secrets from memory and locks the vault.
func (s *Store) Lock() {
	s.mu.Lock()
	defer s.mu.Unlock()

	// SEC-005: Zero credential data before releasing to GC
	if s.vault != nil {
		for _, svc := range s.vault.Services {
			wipeAuth(&svc.Auth)
		}
		for _, f := range s.vault.Files {
			wipeBytes(f.Data)
		}
	}
	s.vault = nil
	// zero password
	for i := range s.password {
		s.password[i] = 0
	}
	s.password = nil
	s.locked = true
}

// wipeBytes zeroes a byte slice in place.
func wipeBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// wipeString overwrites a string's backing memory via unsafe conversion.
// Since Go strings are immutable, we overwrite the underlying bytes.
func wipeAuth(a *Auth) {
	// Zero all sensitive string fields by overwriting with empty
	// Note: Go strings are immutable; we can only nil the struct fields.
	// The old string values remain in heap until GC, but this limits
	// the window by dropping all references immediately.
	*a = Auth{}
}

// IsLocked returns whether the vault is locked.
func (s *Store) IsLocked() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.locked
}

// ListServices returns safe info for all services.
func (s *Store) ListServices() ([]ServiceInfo, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.locked {
		return nil, fmt.Errorf("vault is locked")
	}

	out := make([]ServiceInfo, 0, len(s.vault.Services))
	for _, svc := range s.vault.Services {
		out = append(out, svc.SafeInfo())
	}
	return out, nil
}

// GetService returns a service by name (with credentials).
func (s *Store) GetService(name string) (*Service, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.locked {
		return nil, fmt.Errorf("vault is locked")
	}

	svc, ok := s.vault.Services[name]
	if !ok {
		return nil, fmt.Errorf("service %q not found", name)
	}
	return svc, nil
}

// AddService adds or updates a service and persists.
func (s *Store) AddService(svc *Service) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.locked {
		return fmt.Errorf("vault is locked")
	}

	s.vault.Services[svc.Name] = svc
	return s.saveLocked()
}

// RemoveService deletes a service and persists.
func (s *Store) RemoveService(name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.locked {
		return fmt.Errorf("vault is locked")
	}

	if _, ok := s.vault.Services[name]; !ok {
		return fmt.Errorf("service %q not found", name)
	}
	delete(s.vault.Services, name)
	return s.saveLocked()
}

// ListFiles returns info for all stored files.
func (s *Store) ListFiles() ([]FileInfo, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.locked {
		return nil, fmt.Errorf("vault is locked")
	}

	out := make([]FileInfo, 0, len(s.vault.Files))
	for _, f := range s.vault.Files {
		out = append(out, f.Info())
	}
	return out, nil
}

// GetFile returns a file by name (with data).
func (s *Store) GetFile(name string) (*File, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.locked {
		return nil, fmt.Errorf("vault is locked")
	}

	f, ok := s.vault.Files[name]
	if !ok {
		return nil, fmt.Errorf("file %q not found", name)
	}
	return f, nil
}

// AddFile adds or updates a file and persists (upsert).
func (s *Store) AddFile(f *File) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.locked {
		return fmt.Errorf("vault is locked")
	}

	s.vault.Files[f.Name] = f
	return s.saveLocked()
}

// RemoveFile deletes a file and persists.
func (s *Store) RemoveFile(name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.locked {
		return fmt.Errorf("vault is locked")
	}

	if _, ok := s.vault.Files[name]; !ok {
		return fmt.Errorf("file %q not found", name)
	}
	delete(s.vault.Files, name)
	return s.saveLocked()
}

// UpdateServiceAuth updates only the auth field of a service and persists.
// Used to persist refreshed OAuth2 tokens without replacing the full service.
func (s *Store) UpdateServiceAuth(name string, auth Auth) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.locked {
		return fmt.Errorf("vault is locked")
	}

	svc, ok := s.vault.Services[name]
	if !ok {
		return fmt.Errorf("service %q not found", name)
	}
	svc.Auth = auth
	return s.saveLocked()
}

// saveLocked encrypts and writes the vault to disk. Must hold mu.
func (s *Store) saveLocked() error {
	plaintext, err := json.Marshal(s.vault)
	if err != nil {
		return fmt.Errorf("marshal vault: %w", err)
	}
	defer wipeBytes(plaintext)

	encrypted, err := crypto.Encrypt(plaintext, s.password)
	if err != nil {
		return fmt.Errorf("encrypt vault: %w", err)
	}

	path := filepath.Join(s.dataDir, vaultFile)
	backupPath := filepath.Join(s.dataDir, backupFile)

	// backup existing file
	if _, err := os.Stat(path); err == nil {
		_ = os.Rename(path, backupPath)
	}

	// atomic write: write to temp file, then rename into place
	tmpPath := path + ".tmp"
	if err := os.WriteFile(tmpPath, encrypted, 0600); err != nil {
		return fmt.Errorf("write vault file: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("rename vault file: %w", err)
	}
	return nil
}
