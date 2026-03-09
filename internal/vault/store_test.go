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

func TestStoreFileCRUD(t *testing.T) {
	dir := t.TempDir()
	s := NewStore(dir)
	s.Unlock([]byte("master"))

	// Add
	f := &File{
		Name:     "config.yaml",
		MimeType: "text/yaml",
		Data:     []byte("key: value"),
	}
	if err := s.AddFile(f); err != nil {
		t.Fatalf("add file: %v", err)
	}

	// List
	list, err := s.ListFiles()
	if err != nil {
		t.Fatalf("list files: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("expected 1 file, got %d", len(list))
	}
	if list[0].Name != "config.yaml" {
		t.Fatalf("expected name config.yaml, got %s", list[0].Name)
	}
	if list[0].MimeType != "text/yaml" {
		t.Fatalf("expected mime text/yaml, got %s", list[0].MimeType)
	}
	if list[0].Size != len([]byte("key: value")) {
		t.Fatalf("expected size %d, got %d", len([]byte("key: value")), list[0].Size)
	}

	// Get (with data)
	got, err := s.GetFile("config.yaml")
	if err != nil {
		t.Fatalf("get file: %v", err)
	}
	if string(got.Data) != "key: value" {
		t.Fatalf("expected data %q, got %q", "key: value", string(got.Data))
	}

	// Get not found
	if _, err := s.GetFile("nonexistent"); err == nil {
		t.Fatal("expected error on get nonexistent file")
	}

	// Add second file
	if err := s.AddFile(&File{Name: "cert.pem", MimeType: "application/x-pem-file", Data: []byte("CERT")}); err != nil {
		t.Fatalf("add second file: %v", err)
	}
	list, _ = s.ListFiles()
	if len(list) != 2 {
		t.Fatalf("expected 2 files, got %d", len(list))
	}

	// Upsert (overwrite existing)
	if err := s.AddFile(&File{Name: "config.yaml", MimeType: "text/yaml", Data: []byte("updated")}); err != nil {
		t.Fatalf("upsert file: %v", err)
	}
	got, _ = s.GetFile("config.yaml")
	if string(got.Data) != "updated" {
		t.Fatalf("expected updated data, got %q", string(got.Data))
	}
	list, _ = s.ListFiles()
	if len(list) != 2 {
		t.Fatalf("expected 2 files after upsert, got %d", len(list))
	}

	// Remove
	if err := s.RemoveFile("config.yaml"); err != nil {
		t.Fatalf("remove file: %v", err)
	}
	list, _ = s.ListFiles()
	if len(list) != 1 {
		t.Fatalf("expected 1 file after remove, got %d", len(list))
	}

	// Remove not found
	if err := s.RemoveFile("config.yaml"); err == nil {
		t.Fatal("expected error on remove nonexistent file")
	}
}

func TestStoreFilePersistence(t *testing.T) {
	dir := t.TempDir()

	// Create and populate
	s1 := NewStore(dir)
	s1.Unlock([]byte("master"))
	s1.AddFile(&File{
		Name:     "secret.key",
		MimeType: "application/octet-stream",
		Data:     []byte("super-secret-key-data"),
	})
	s1.Lock()

	// Reopen
	s2 := NewStore(dir)
	if err := s2.Unlock([]byte("master")); err != nil {
		t.Fatalf("reopen: %v", err)
	}

	got, err := s2.GetFile("secret.key")
	if err != nil {
		t.Fatalf("get file after reopen: %v", err)
	}
	if string(got.Data) != "super-secret-key-data" {
		t.Fatalf("file data lost after reopen: got %q", string(got.Data))
	}
	if got.MimeType != "application/octet-stream" {
		t.Fatalf("mime type lost after reopen: got %q", got.MimeType)
	}
}

func TestStoreFileLockedOperations(t *testing.T) {
	s := NewStore(t.TempDir())

	if _, err := s.ListFiles(); err == nil {
		t.Fatal("expected error on locked list files")
	}
	if _, err := s.GetFile("x"); err == nil {
		t.Fatal("expected error on locked get file")
	}
	if err := s.AddFile(&File{Name: "x"}); err == nil {
		t.Fatal("expected error on locked add file")
	}
	if err := s.RemoveFile("x"); err == nil {
		t.Fatal("expected error on locked remove file")
	}
}

func TestStoreUpdateServiceAuth(t *testing.T) {
	dir := t.TempDir()
	s := NewStore(dir)
	s.Unlock([]byte("master"))

	// Setup: add a service with initial auth
	svc := &Service{
		Name:    "github",
		BaseURL: "https://api.github.com",
		Auth:    Auth{Type: "bearer", Token: "old-token"},
	}
	if err := s.AddService(svc); err != nil {
		t.Fatalf("add service: %v", err)
	}

	// Update auth
	newAuth := Auth{Type: "bearer", Token: "new-token"}
	if err := s.UpdateServiceAuth("github", newAuth); err != nil {
		t.Fatalf("update service auth: %v", err)
	}

	// Verify auth updated, BaseURL unchanged
	got, err := s.GetService("github")
	if err != nil {
		t.Fatalf("get service: %v", err)
	}
	if got.Auth.Token != "new-token" {
		t.Fatalf("expected token new-token, got %s", got.Auth.Token)
	}
	if got.BaseURL != "https://api.github.com" {
		t.Fatalf("base URL mutated: got %s", got.BaseURL)
	}

	// Update nonexistent service
	if err := s.UpdateServiceAuth("nonexistent", newAuth); err == nil {
		t.Fatal("expected error updating nonexistent service")
	}

	// Persists through lock/unlock
	s.Lock()
	s2 := NewStore(dir)
	if err := s2.Unlock([]byte("master")); err != nil {
		t.Fatalf("reopen: %v", err)
	}
	got, err = s2.GetService("github")
	if err != nil {
		t.Fatalf("get service after reopen: %v", err)
	}
	if got.Auth.Token != "new-token" {
		t.Fatalf("auth update lost after reopen: got %q", got.Auth.Token)
	}
	if got.Auth.Type != "bearer" {
		t.Fatalf("auth type lost after reopen: got %q", got.Auth.Type)
	}

	// UpdateServiceAuth fails when locked
	s3 := NewStore(t.TempDir())
	if err := s3.UpdateServiceAuth("github", newAuth); err == nil {
		t.Fatal("expected error on locked update service auth")
	}
}
