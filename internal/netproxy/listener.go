package netproxy

import (
	"context"
	"fmt"
	"log"
	"net"
	"sync"
	"time"
)

// DefaultSessionTimeout is the grace period to wait for a local client to
// connect before the listener is torn down.
const DefaultSessionTimeout = 30 * time.Second

// MaxSessionTimeout caps the timeout callers can request.
const MaxSessionTimeout = 300 * time.Second

// Session is a single one-shot authenticated session. Vault binds a local
// listener, accepts exactly one client, runs the protocol handshake, then
// splices bytes to the upstream.
type Session struct {
	Addr      string    // e.g. "127.0.0.1:54321"
	ExpiresAt time.Time // when the listener will be torn down if unused

	driver   ProtocolDriver
	listener net.Listener
	cancel   context.CancelFunc
	done     chan struct{}
	closed   bool
	mu       sync.Mutex
}

// Registry tracks all live sessions so they can be closed en masse when the
// vault is locked.
type Registry struct {
	mu       sync.Mutex
	sessions map[*Session]struct{}
}

// NewRegistry returns an empty session registry.
func NewRegistry() *Registry {
	return &Registry{sessions: make(map[*Session]struct{})}
}

// Start binds 127.0.0.1:0, begins accepting one connection in the background,
// and returns a Session describing the listener. The supplied timeout is
// clamped to [0, MaxSessionTimeout]; 0 means DefaultSessionTimeout.
func (r *Registry) Start(driver ProtocolDriver, timeout time.Duration) (*Session, error) {
	if timeout <= 0 {
		timeout = DefaultSessionTimeout
	}
	if timeout > MaxSessionTimeout {
		timeout = MaxSessionTimeout
	}

	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("bind loopback: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	sess := &Session{
		Addr:      ln.Addr().String(),
		ExpiresAt: time.Now().Add(timeout),
		driver:    driver,
		listener:  ln,
		cancel:    cancel,
		done:      make(chan struct{}),
	}

	r.mu.Lock()
	r.sessions[sess] = struct{}{}
	r.mu.Unlock()

	go sess.run(ctx, r, timeout)
	return sess, nil
}

// CloseAll tears down every live session. Called on vault lock.
func (r *Registry) CloseAll() {
	r.mu.Lock()
	sessions := make([]*Session, 0, len(r.sessions))
	for s := range r.sessions {
		sessions = append(sessions, s)
	}
	r.mu.Unlock()

	for _, s := range sessions {
		s.Close()
	}
}

// Done returns a channel that is closed when the session has fully finished
// (either after the splice terminates or after the listener is torn down
// without an accept). Callers can wait on this to perform cleanup such as
// wiping stored credentials.
func (s *Session) Done() <-chan struct{} { return s.done }

// Close tears down the session immediately.
func (s *Session) Close() {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.closed = true
	s.mu.Unlock()

	s.cancel()
	s.listener.Close()
	<-s.done
}

func (s *Session) markClosed() {
	s.mu.Lock()
	s.closed = true
	s.mu.Unlock()
}

func (s *Session) run(ctx context.Context, r *Registry, timeout time.Duration) {
	defer close(s.done)
	defer func() {
		r.mu.Lock()
		delete(r.sessions, s)
		r.mu.Unlock()
	}()
	defer s.listener.Close()

	// Close the listener when timeout expires or ctx is cancelled.
	timer := time.AfterFunc(timeout, func() {
		s.markClosed()
		s.listener.Close()
	})
	defer timer.Stop()

	local, err := s.listener.Accept()
	if err != nil {
		// Listener closed (timeout or explicit close).
		return
	}
	// Only one accept per session — close the listener so no one else can
	// attach to this authenticated upstream.
	s.listener.Close()

	start := time.Now()
	log.Printf("%s session: accepted from %s upstream=%s", s.driver.Name(), local.RemoteAddr(), sessionHostFor(s.driver))

	// Dial + authenticate upstream.
	dialCtx, dialCancel := context.WithTimeout(ctx, 20*time.Second)
	upstream, err := s.driver.DialAndAuthenticate(dialCtx)
	dialCancel()
	if err != nil {
		log.Printf("%s session: upstream auth failed: %v", s.driver.Name(), err)
		local.Close()
		return
	}

	// Run the local-side handshake up to post-auth state.
	if err := s.driver.ServeLocal(local, upstream); err != nil {
		log.Printf("%s session: local handshake failed: %v", s.driver.Name(), err)
		local.Close()
		upstream.Close()
		return
	}

	// Splice until either side closes.
	splice(local, upstream)
	log.Printf("%s session: closed after %s", s.driver.Name(), time.Since(start).Round(time.Millisecond))
}

// sessionHostFor extracts an optional upstream label for logging. Drivers
// may implement Hoster to expose host:port; if not, returns "-".
func sessionHostFor(d ProtocolDriver) string {
	if h, ok := d.(Hoster); ok {
		return h.UpstreamHost()
	}
	return "-"
}

// Hoster is implemented by drivers that expose their upstream for logging.
type Hoster interface {
	UpstreamHost() string
}
