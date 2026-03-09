package vault

import (
	"os"
	"testing"
)

func TestStoreUnlockCreateNew(t *testing.T) {
	dir := t.TempDir()
	s := NewStore(dir)

	if err := s.Unlock([]byte("master")); err != nil {
		t.Fatalf("unlock new vault: %v", err)
	}
	if s.IsLocked() {
		t.Fatal("vault should be unlocked")
	}

	// Vault file should exist
	if _, err := os.Stat(dir + "/vault.enc"); err != nil {
		t.Fatalf("vault file not created: %v", err)
	}
}

func TestStoreServiceCRUD(t *testing.T) {
	dir := t.TempDir()
	s := NewStore(dir)
	s.Unlock([]byte("master"))

	// Add
	svc := &Service{
		Name:    "openrouter",
		BaseURL: "https://openrouter.ai/api",
		Auth:    Auth{Type: "bearer", Token: "sk-test-123"},
	}
	if err := s.AddService(svc); err != nil {
		t.Fatalf("add service: %v", err)
	}

	// List
	list, _ := s.ListServices()
	if len(list) != 1 || list[0].Name != "openrouter" {
		t.Fatalf("expected 1 service, got %v", list)
	}
	if list[0].AuthType != "bearer" {
		t.Fatalf("expected bearer auth, got %s", list[0].AuthType)
	}

	// Get (with credentials)
	got, err := s.GetService("openrouter")
	if err != nil {
		t.Fatalf("get service: %v", err)
	}
	if got.Auth.Token != "sk-test-123" {
		t.Fatalf("expected token sk-test-123, got %s", got.Auth.Token)
	}

	// Remove
	if err := s.RemoveService("openrouter"); err != nil {
		t.Fatalf("remove service: %v", err)
	}
	list, _ = s.ListServices()
	if len(list) != 0 {
		t.Fatal("expected 0 services after remove")
	}
}

func TestStorePersistence(t *testing.T) {
	dir := t.TempDir()

	// Create and populate
	s1 := NewStore(dir)
	s1.Unlock([]byte("pass"))
	s1.AddService(&Service{
		Name: "test", BaseURL: "https://example.com",
		Auth: Auth{Type: "bearer", Token: "secret"},
	})
	s1.Lock()

	// Reopen
	s2 := NewStore(dir)
	if err := s2.Unlock([]byte("pass")); err != nil {
		t.Fatalf("reopen: %v", err)
	}

	got, err := s2.GetService("test")
	if err != nil {
		t.Fatalf("get after reopen: %v", err)
	}
	if got.Auth.Token != "secret" {
		t.Fatalf("token lost after reopen: got %q", got.Auth.Token)
	}
}

func TestStorePersistenceWrongPassword(t *testing.T) {
	dir := t.TempDir()

	s1 := NewStore(dir)
	s1.Unlock([]byte("correct"))
	s1.AddService(&Service{Name: "x", BaseURL: "https://x.com", Auth: Auth{Type: "bearer", Token: "t"}})
	s1.Lock()

	s2 := NewStore(dir)
	if err := s2.Unlock([]byte("wrong")); err == nil {
		t.Fatal("expected error with wrong password")
	}
}

func TestStoreLockedOperations(t *testing.T) {
	s := NewStore(t.TempDir())

	// All ops should fail when locked
	if _, err := s.ListServices(); err == nil {
		t.Fatal("expected error on locked list")
	}
	if _, err := s.GetService("x"); err == nil {
		t.Fatal("expected error on locked get")
	}
	if err := s.AddService(&Service{Name: "x"}); err == nil {
		t.Fatal("expected error on locked add")
	}
}
