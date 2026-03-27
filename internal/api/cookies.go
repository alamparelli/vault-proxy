package api

import (
	"net/http"
	"sync"
	"time"
)

// maxCookiesPerJar limits the number of cookies stored per service to prevent
// memory exhaustion from a misbehaving upstream (SEC-001).
const maxCookiesPerJar = 50

// sessionCookieJar is a thread-safe in-memory cookie store for a single service.
// It captures Set-Cookie headers from upstream responses and re-injects them
// on subsequent outbound requests. Used for sticky sessions, CSRF tokens, etc.
//
// Note: this is a simple name-keyed store that ignores cookie Domain and Path
// attributes. This is acceptable for the intended use case (single-host sticky
// sessions like AWSALB) but does not implement full RFC 6265 scoping.
type sessionCookieJar struct {
	mu      sync.Mutex
	cookies map[string]*http.Cookie // keyed by cookie name
}

func newSessionCookieJar() *sessionCookieJar {
	return &sessionCookieJar{cookies: make(map[string]*http.Cookie)}
}

// injectCookies adds stored cookies to an outbound request.
// Expired cookies are skipped and evicted.
func (j *sessionCookieJar) injectCookies(req *http.Request) {
	j.mu.Lock()
	defer j.mu.Unlock()
	now := time.Now()
	for name, c := range j.cookies {
		if !c.Expires.IsZero() && c.Expires.Before(now) {
			delete(j.cookies, name)
			continue
		}
		req.AddCookie(c)
	}
}

// captureCookies extracts Set-Cookie headers from an upstream response
// and stores them in the jar. Honors Max-Age=0 and expired Expires as
// deletion signals per RFC 6265.
func (j *sessionCookieJar) captureCookies(resp *http.Response) {
	cookies := resp.Cookies()
	if len(cookies) == 0 {
		return
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	for _, c := range cookies {
		// Honor deletion signals (RFC 6265: Max-Age=0 or negative means delete)
		if c.MaxAge < 0 || (c.MaxAge == 0 && c.RawExpires != "") {
			delete(j.cookies, c.Name)
			continue
		}
		if !c.Expires.IsZero() && c.Expires.Before(time.Now()) {
			delete(j.cookies, c.Name)
			continue
		}
		// SEC-001: Cap on cookies per jar to prevent memory exhaustion.
		if _, exists := j.cookies[c.Name]; !exists && len(j.cookies) >= maxCookiesPerJar {
			continue
		}
		j.cookies[c.Name] = c
	}
}

// getJar returns (or creates) the cookie jar for a service.
func (s *Server) getJar(serviceName string) *sessionCookieJar {
	s.cookieJarsMu.Lock()
	defer s.cookieJarsMu.Unlock()
	jar, ok := s.cookieJars[serviceName]
	if !ok {
		jar = newSessionCookieJar()
		s.cookieJars[serviceName] = jar
	}
	return jar
}

// removeJar deletes the cookie jar for a service (on service deletion).
func (s *Server) removeJar(serviceName string) {
	s.cookieJarsMu.Lock()
	defer s.cookieJarsMu.Unlock()
	delete(s.cookieJars, serviceName)
}

// clearCookieJars removes all cookie jars (on vault lock).
func (s *Server) clearCookieJars() {
	s.cookieJarsMu.Lock()
	defer s.cookieJarsMu.Unlock()
	s.cookieJars = make(map[string]*sessionCookieJar)
}

// cookieCount returns the number of cookies stored for a service (for testing/debug).
func (j *sessionCookieJar) cookieCount() int {
	j.mu.Lock()
	defer j.mu.Unlock()
	return len(j.cookies)
}

// allCookies returns all stored cookies (for testing).
func (j *sessionCookieJar) allCookies() []*http.Cookie {
	j.mu.Lock()
	defer j.mu.Unlock()
	result := make([]*http.Cookie, 0, len(j.cookies))
	for _, c := range j.cookies {
		result = append(result, c)
	}
	return result
}
