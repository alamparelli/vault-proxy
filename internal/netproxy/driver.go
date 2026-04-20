// Package netproxy provides the shared skeleton for auth-only TCP adapters
// (IMAP, SMTP, Redis, Postgres). A ProtocolDriver dials upstream, performs
// the credential handshake with stored secrets, synthesises the client-facing
// side of the protocol for a local dummy auth, then hands off to a raw
// bidirectional byte pipe.
package netproxy

import (
	"context"
	"net"
)

// ProtocolDriver authenticates an upstream connection and mediates the
// local-side handshake so a standard client library can connect to vault's
// ephemeral listener without knowing the real credentials.
type ProtocolDriver interface {
	// Name returns the protocol label used in logs (e.g. "imap").
	Name() string

	// DialAndAuthenticate opens a TCP connection to the upstream service,
	// negotiates TLS if required, and completes the authentication
	// handshake using the driver's stored credentials. The returned conn
	// is ready for post-auth protocol commands.
	DialAndAuthenticate(ctx context.Context) (net.Conn, error)

	// ServeLocal speaks the local-side handshake with the client until
	// the client reaches the equivalent post-auth state, then returns.
	// After this call the listener splices local<->upstream as raw bytes.
	ServeLocal(local, upstream net.Conn) error
}
