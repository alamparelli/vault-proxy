package api

import (
	"context"
	"log"
	"sync"
	"time"
)

const (
	// refreshBeforeExpiry is how long before token expiry to trigger a proactive refresh.
	refreshBeforeExpiry = 30 * time.Minute
	// minRefreshInterval prevents scheduling a timer less than this duration from now.
	minRefreshInterval = 30 * time.Second
)

// tokenRefreshScheduler manages per-service timers for proactive token refresh.
type tokenRefreshScheduler struct {
	server *Server
	timers map[string]*time.Timer
	mu     sync.Mutex
	onFail func(service string, err error) // callback when refresh fails (for alerts)
}

// newTokenRefreshScheduler creates and starts the scheduler.
func newTokenRefreshScheduler(server *Server, onFail func(string, error)) *tokenRefreshScheduler {
	return &tokenRefreshScheduler{
		server: server,
		timers: make(map[string]*time.Timer),
		onFail: onFail,
	}
}

// ScheduleAll scans all services and schedules timers for OAuth2/SA tokens.
func (s *tokenRefreshScheduler) ScheduleAll() {
	services, err := s.server.store.ListServices()
	if err != nil {
		log.Printf("[token-refresh] failed to list services: %v", err)
		return
	}
	for _, svc := range services {
		var expiresAt int64
		switch svc.AuthType {
		case "oauth2_client":
			full, err := s.server.store.GetService(svc.Name)
			if err != nil {
				continue
			}
			expiresAt = full.Auth.ExpiresAt
		case "service_account":
			full, err := s.server.store.GetService(svc.Name)
			if err != nil {
				continue
			}
			expiresAt = full.Auth.SAExpiresAt
		default:
			continue
		}
		if expiresAt > 0 {
			s.Schedule(svc.Name, expiresAt)
		}
	}
}

// Schedule sets a timer to refresh the token 30 min before expiry.
func (s *tokenRefreshScheduler) Schedule(serviceName string, expiresAt int64) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Cancel existing timer if any.
	if t, ok := s.timers[serviceName]; ok {
		t.Stop()
		delete(s.timers, serviceName)
	}

	expiry := time.Unix(expiresAt, 0)
	refreshAt := expiry.Add(-refreshBeforeExpiry)
	delay := time.Until(refreshAt)
	if delay < minRefreshInterval {
		// Token expires within refreshBeforeExpiry window. Schedule at 80% of remaining lifetime
		// to avoid a 30s refresh loop when the provider returns the same expiry.
		remaining := time.Until(expiry)
		delay = time.Duration(float64(remaining) * 0.8)
		if delay < minRefreshInterval {
			delay = minRefreshInterval
		}
	}

	log.Printf("[token-refresh] scheduled %s refresh in %s (expires %s)",
		serviceName, delay.Round(time.Second), time.Unix(expiresAt, 0).Format("15:04:05"))

	s.timers[serviceName] = time.AfterFunc(delay, func() {
		s.doRefresh(serviceName)
	})
}

// Cancel removes the timer for a service (e.g., when service is deleted).
func (s *tokenRefreshScheduler) Cancel(serviceName string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if t, ok := s.timers[serviceName]; ok {
		t.Stop()
		delete(s.timers, serviceName)
	}
}

// Stop cancels all timers.
func (s *tokenRefreshScheduler) Stop() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for name, t := range s.timers {
		t.Stop()
		delete(s.timers, name)
	}
}

func (s *tokenRefreshScheduler) doRefresh(serviceName string) {
	log.Printf("[token-refresh] proactive refresh for %s", serviceName)

	svc, err := s.server.store.GetService(serviceName)
	if err != nil {
		log.Printf("[token-refresh] service %s not found: %v", serviceName, err)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	var newExpiresAt int64

	switch svc.Auth.Type {
	case "oauth2_client":
		_, err = s.server.ensureOAuth2Token(ctx, svc)
		if err == nil {
			// Re-read to get updated expiry.
			if fresh, err2 := s.server.store.GetService(serviceName); err2 == nil {
				newExpiresAt = fresh.Auth.ExpiresAt
			}
		}
	case "service_account":
		_, err = s.server.ensureServiceAccountToken(ctx, svc)
		if err == nil {
			if fresh, err2 := s.server.store.GetService(serviceName); err2 == nil {
				newExpiresAt = fresh.Auth.SAExpiresAt
			}
		}
	default:
		return
	}

	if err != nil {
		log.Printf("[token-refresh] ✗ refresh failed for %s: %v", serviceName, err)
		if s.onFail != nil {
			s.onFail(serviceName, err)
		}
		// Retry in 5 minutes.
		s.mu.Lock()
		s.timers[serviceName] = time.AfterFunc(5*time.Minute, func() {
			s.doRefresh(serviceName)
		})
		s.mu.Unlock()
		return
	}

	log.Printf("[token-refresh] ✓ refreshed %s (new expiry: %s)",
		serviceName, time.Unix(newExpiresAt, 0).Format("15:04:05"))

	// Schedule next refresh.
	if newExpiresAt > 0 {
		s.Schedule(serviceName, newExpiresAt)
	}
}
