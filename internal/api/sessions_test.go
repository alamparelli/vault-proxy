package api

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/alamparelli/vault-proxy/internal/vault"
)

// TestValidateAuthType_NewProtocols covers the imap/smtp/redis/postgres cases
// added to validateAuthType. Relies on the zero-value Server; validation does
// not access the store except for file refs, which none of these auth types
// use.
func TestValidateAuthType_NewProtocols(t *testing.T) {
	s := &Server{}

	t.Run("imap ok, defaults applied", func(t *testing.T) {
		svc := &vault.Service{
			Name: "m",
			Auth: vault.Auth{
				Type:         "imap",
				IMAPHost:     "imap.example.com",
				IMAPUser:     "a@b",
				IMAPPassword: "p",
			},
		}
		if err := s.validateAuthType(svc); err != nil {
			t.Fatal(err)
		}
		if svc.Auth.IMAPPort != 993 || svc.Auth.IMAPTLS != "implicit" {
			t.Fatalf("defaults not applied: port=%d tls=%q", svc.Auth.IMAPPort, svc.Auth.IMAPTLS)
		}
	})

	t.Run("imap missing password", func(t *testing.T) {
		svc := &vault.Service{Auth: vault.Auth{Type: "imap", IMAPHost: "h", IMAPUser: "u"}}
		if err := s.validateAuthType(svc); err == nil {
			t.Fatal("expected error")
		}
	})

	t.Run("smtp defaults to starttls/587", func(t *testing.T) {
		svc := &vault.Service{Auth: vault.Auth{
			Type: "smtp", SMTPHost: "smtp.example", SMTPUser: "u", SMTPPassword: "p",
		}}
		if err := s.validateAuthType(svc); err != nil {
			t.Fatal(err)
		}
		if svc.Auth.SMTPPort != 587 || svc.Auth.SMTPTLS != "starttls" {
			t.Fatalf("defaults wrong: port=%d tls=%q", svc.Auth.SMTPPort, svc.Auth.SMTPTLS)
		}
	})

	t.Run("smtp implicit → 465", func(t *testing.T) {
		svc := &vault.Service{Auth: vault.Auth{
			Type: "smtp", SMTPHost: "h", SMTPUser: "u", SMTPPassword: "p", SMTPTLS: "implicit",
		}}
		if err := s.validateAuthType(svc); err != nil {
			t.Fatal(err)
		}
		if svc.Auth.SMTPPort != 465 {
			t.Fatalf("expected 465, got %d", svc.Auth.SMTPPort)
		}
	})

	t.Run("redis minimal", func(t *testing.T) {
		svc := &vault.Service{Auth: vault.Auth{Type: "redis", RedisHost: "cache.example"}}
		if err := s.validateAuthType(svc); err != nil {
			t.Fatal(err)
		}
		if svc.Auth.RedisPort != 6379 {
			t.Fatalf("expected 6379, got %d", svc.Auth.RedisPort)
		}
	})

	t.Run("postgres complete", func(t *testing.T) {
		svc := &vault.Service{Auth: vault.Auth{
			Type: "postgres", PostgresHost: "db", PostgresUser: "u", PostgresPassword: "p", PostgresDB: "app",
		}}
		if err := s.validateAuthType(svc); err != nil {
			t.Fatal(err)
		}
		if svc.Auth.PostgresPort != 5432 || svc.Auth.PostgresTLS != "require" {
			t.Fatalf("defaults wrong: port=%d tls=%q", svc.Auth.PostgresPort, svc.Auth.PostgresTLS)
		}
	})

	t.Run("postgres missing db", func(t *testing.T) {
		svc := &vault.Service{Auth: vault.Auth{
			Type: "postgres", PostgresHost: "db", PostgresUser: "u", PostgresPassword: "p",
		}}
		if err := s.validateAuthType(svc); err == nil {
			t.Fatal("expected error for missing postgres_db")
		}
	})

	t.Run("rejects unknown tls mode", func(t *testing.T) {
		svc := &vault.Service{Auth: vault.Auth{
			Type: "imap", IMAPHost: "h", IMAPUser: "u", IMAPPassword: "p", IMAPTLS: "bogus",
		}}
		if err := s.validateAuthType(svc); err == nil {
			t.Fatal("expected error")
		}
	})

	t.Run("rejects blocked host", func(t *testing.T) {
		svc := &vault.Service{Auth: vault.Auth{
			Type: "imap", IMAPHost: "169.254.169.254", IMAPUser: "u", IMAPPassword: "p",
		}}
		if err := s.validateAuthType(svc); err == nil {
			t.Fatal("expected error for metadata endpoint")
		}
	})
}

// TestSafeInfo_HidesPasswords ensures the non-secret view never leaks the
// stored credentials for the new auth types.
func TestSafeInfo_HidesPasswords(t *testing.T) {
	cases := []vault.Service{
		{Name: "a", Auth: vault.Auth{Type: "imap", IMAPPassword: "secret"}},
		{Name: "b", Auth: vault.Auth{Type: "smtp", SMTPPassword: "secret"}},
		{Name: "c", Auth: vault.Auth{Type: "redis", RedisPassword: "secret"}},
		{Name: "d", Auth: vault.Auth{Type: "postgres", PostgresPassword: "secret"}},
	}
	for _, svc := range cases {
		info := svc.SafeInfo()
		buf, err := json.Marshal(info)
		if err != nil {
			t.Fatalf("%s: marshal: %v", svc.Name, err)
		}
		if strings.Contains(string(buf), "secret") {
			t.Fatalf("%s: SafeInfo leaks password: %s", svc.Name, buf)
		}
	}
}
