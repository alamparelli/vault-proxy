package api

import (
	"net/http"
	"sync"
)

// sessionCookieJar is a thread-safe in-memory cookie store for a single service.
// It captures Set-Cookie headers from upstream responses and re-injects them
// on subsequent outbound requests. Used for sticky sessions (e.g. AWSALB).
type sessionCookieJar struct {
	mu      sync.Mutex
	cookies map[string]*http.Cookie // keyed by cookie name
}

func newSessionCookieJar() *sessionCookieJar {
	return &sessionCookieJar{cookies: make(map[string]*http.Cookie)}
}

// injectCookies adds stored cookies to an outbound request.
func (j *sessionCookieJar) injectCookies(req *http.Request) {
	j.mu.Lock()
	defer j.mu.Unlock()
	for _, c := range j.cookies {
		req.AddCookie(c)
	}
}

// captureCookies extracts Set-Cookie headers from an upstream response
// and stores them in the jar. targetURL is needed to parse the cookies
// correctly via http.Response.Cookies().
func (j *sessionCookieJar) captureCookies(resp *http.Response) {
	cookies := resp.Cookies()
	if len(cookies) == 0 {
		return
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	for _, c := range cookies {
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

