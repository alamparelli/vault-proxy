package api

import (
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/alamparelli/vault-proxy/internal/imap"
	"github.com/alamparelli/vault-proxy/internal/netproxy"
	"github.com/alamparelli/vault-proxy/internal/postgres"
	"github.com/alamparelli/vault-proxy/internal/redis"
	"github.com/alamparelli/vault-proxy/internal/smtp"
	"github.com/alamparelli/vault-proxy/internal/vault"
)

// sessionResponse is the JSON body returned by /{proto}/{svc}/session.
type sessionResponse struct {
	Addr      string    `json:"addr"`
	ExpiresAt time.Time `json:"expires_at"`
}

// imapRouter dispatches POST /imap/{service}/session.
func (s *Server) imapRouter(w http.ResponseWriter, r *http.Request) {
	s.tcpSessionRouter(w, r, "/imap/", "imap", s.imapSessionHandler)
}

// smtpRouter dispatches POST /smtp/{service}/session.
func (s *Server) smtpRouter(w http.ResponseWriter, r *http.Request) {
	s.tcpSessionRouter(w, r, "/smtp/", "smtp", s.smtpSessionHandler)
}

// redisRouter dispatches POST /redis/{service}/session.
func (s *Server) redisRouter(w http.ResponseWriter, r *http.Request) {
	s.tcpSessionRouter(w, r, "/redis/", "redis", s.redisSessionHandler)
}

// postgresRouter dispatches POST /postgres/{service}/session.
func (s *Server) postgresRouter(w http.ResponseWriter, r *http.Request) {
	s.tcpSessionRouter(w, r, "/postgres/", "postgres", s.postgresSessionHandler)
}

// tcpSessionRouter is the shared shape for {proto}/{svc}/session routing.
func (s *Server) tcpSessionRouter(
	w http.ResponseWriter, r *http.Request,
	prefix, authType string,
	handler func(http.ResponseWriter, *http.Request, *vault.Service),
) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}
	path := strings.TrimPrefix(r.URL.Path, prefix)
	parts := strings.Split(path, "/")
	if len(parts) != 2 || parts[0] == "" || parts[1] != "session" {
		http.Error(w, `{"error":"expected path `+prefix+`{service}/session"}`, http.StatusBadRequest)
		return
	}
	svc, err := s.store.GetService(parts[0])
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), http.StatusNotFound)
		return
	}
	if svc.Auth.Type != authType {
		http.Error(w, fmt.Sprintf(`{"error":"service %q is not a %s service"}`, parts[0], authType), http.StatusBadRequest)
		return
	}
	handler(w, r, svc)
}

// parseTimeout reads ?timeout=N (seconds), clamped by netproxy.
func parseTimeout(r *http.Request) time.Duration {
	q := r.URL.Query().Get("timeout")
	if q == "" {
		return 0
	}
	n, err := strconv.Atoi(q)
	if err != nil || n <= 0 {
		return 0
	}
	return time.Duration(n) * time.Second
}

func (s *Server) imapSessionHandler(w http.ResponseWriter, r *http.Request, svc *vault.Service) {
	pw := make([]byte, len(svc.Auth.IMAPPassword))
	copy(pw, svc.Auth.IMAPPassword)
	driver := imap.New(&imap.Config{
		Host:          svc.Auth.IMAPHost,
		Port:          svc.Auth.IMAPPort,
		User:          svc.Auth.IMAPUser,
		Password:      pw,
		TLSMode:       svc.Auth.IMAPTLS,
		TLSSkipVerify: svc.TLSSkipVerify,
	})
	s.startSession(w, r, svc.Name, driver, driver.Wipe)
}

func (s *Server) smtpSessionHandler(w http.ResponseWriter, r *http.Request, svc *vault.Service) {
	pw := make([]byte, len(svc.Auth.SMTPPassword))
	copy(pw, svc.Auth.SMTPPassword)
	driver := smtp.New(&smtp.Config{
		Host:          svc.Auth.SMTPHost,
		Port:          svc.Auth.SMTPPort,
		User:          svc.Auth.SMTPUser,
		Password:      pw,
		TLSMode:       svc.Auth.SMTPTLS,
		TLSSkipVerify: svc.TLSSkipVerify,
	})
	s.startSession(w, r, svc.Name, driver, driver.Wipe)
}

func (s *Server) redisSessionHandler(w http.ResponseWriter, r *http.Request, svc *vault.Service) {
	pw := make([]byte, len(svc.Auth.RedisPassword))
	copy(pw, svc.Auth.RedisPassword)
	driver := redis.New(&redis.Config{
		Host:          svc.Auth.RedisHost,
		Port:          svc.Auth.RedisPort,
		Username:      svc.Auth.RedisUsername,
		Password:      pw,
		DB:            svc.Auth.RedisDB,
		TLS:           svc.Auth.RedisTLS,
		TLSSkipVerify: svc.TLSSkipVerify,
	})
	s.startSession(w, r, svc.Name, driver, driver.Wipe)
}

func (s *Server) postgresSessionHandler(w http.ResponseWriter, r *http.Request, svc *vault.Service) {
	pw := make([]byte, len(svc.Auth.PostgresPassword))
	copy(pw, svc.Auth.PostgresPassword)
	driver := postgres.New(&postgres.Config{
		Host:          svc.Auth.PostgresHost,
		Port:          svc.Auth.PostgresPort,
		User:          svc.Auth.PostgresUser,
		Password:      pw,
		Database:      svc.Auth.PostgresDB,
		TLSMode:       svc.Auth.PostgresTLS,
		TLSSkipVerify: svc.TLSSkipVerify,
	})
	s.startSession(w, r, svc.Name, driver, driver.Wipe)
}

// startSession registers a one-shot listener and returns the JSON addr.
// The wipe callback is fired once the session is fully torn down so
// password bytes do not linger in driver memory beyond their useful life.
func (s *Server) startSession(
	w http.ResponseWriter, r *http.Request,
	name string, driver netproxy.ProtocolDriver, wipe func(),
) {
	sess, err := s.netSessions.Start(driver, parseTimeout(r))
	if err != nil {
		wipe()
		http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), http.StatusInternalServerError)
		return
	}
	tok := tokenFromContext(r)
	tokPrefix := ""
	if tok != nil && len(tok.ID) > 8 {
		tokPrefix = tok.ID[:8]
	}
	log.Printf("%s session opened: service=%s addr=%s token=%s…", driver.Name(), name, sess.Addr, tokPrefix)

	// Wipe the driver's password copy once the session is fully done,
	// regardless of whether the client ever connected.
	go func() {
		<-sess.Done()
		wipe()
	}()

	writeJSON(w, http.StatusOK, sessionResponse{Addr: sess.Addr, ExpiresAt: sess.ExpiresAt})
}
