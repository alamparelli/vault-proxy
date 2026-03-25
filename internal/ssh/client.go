package ssh

import (
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"strconv"
	"time"

	gossh "golang.org/x/crypto/ssh"
)

const defaultTimeout = 10 * time.Second

// Config holds the parameters for establishing an SSH connection.
type Config struct {
	Host       string
	Port       int
	User       string
	PrivateKey []byte // PEM-encoded private key
	Passphrase []byte // optional passphrase for encrypted keys
	HostKey    string // stored host key fingerprint for TOFU verification
	Timeout    time.Duration
}

// DialResult contains the SSH client and host key information.
type DialResult struct {
	Client     *gossh.Client
	HostKey    string // base64-encoded public key of the server
	HostKeyNew bool   // true if this is the first connection (no stored key)
}

// Dial establishes an authenticated SSH connection with TOFU host key verification.
func Dial(ctx context.Context, cfg Config) (*DialResult, error) {
	if cfg.Port == 0 {
		cfg.Port = 22
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = defaultTimeout
	}

	signer, err := parseKey(cfg.PrivateKey, cfg.Passphrase)
	if err != nil {
		return nil, fmt.Errorf("parse private key: %w", err)
	}

	var serverKey gossh.PublicKey
	hostKeyCallback := func(hostname string, remote net.Addr, key gossh.PublicKey) error {
		serverKey = key
		if cfg.HostKey == "" {
			// First connection — accept (TOFU)
			return nil
		}
		// Verify against stored key
		actual := marshalPublicKey(key)
		if actual != cfg.HostKey {
			return fmt.Errorf("host key mismatch for %s (TOFU violation): stored=%s got=%s",
				hostname, cfg.HostKey, actual)
		}
		return nil
	}

	clientCfg := &gossh.ClientConfig{
		User:            cfg.User,
		Auth:            []gossh.AuthMethod{gossh.PublicKeys(signer)},
		HostKeyCallback: hostKeyCallback,
		Timeout:         cfg.Timeout,
	}

	addr := net.JoinHostPort(cfg.Host, strconv.Itoa(cfg.Port))

	var client *gossh.Client
	if deadline, ok := ctx.Deadline(); ok {
		clientCfg.Timeout = time.Until(deadline)
	}

	dialer := net.Dialer{Timeout: cfg.Timeout}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", addr, err)
	}

	sshConn, chans, reqs, err := gossh.NewClientConn(conn, addr, clientCfg)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("ssh handshake: %w", err)
	}
	client = gossh.NewClient(sshConn, chans, reqs)

	result := &DialResult{
		Client:     client,
		HostKeyNew: cfg.HostKey == "",
	}
	if serverKey != nil {
		result.HostKey = marshalPublicKey(serverKey)
	}
	return result, nil
}

// parseKey parses a PEM-encoded private key, optionally with a passphrase.
func parseKey(pemBytes, passphrase []byte) (gossh.Signer, error) {
	if len(passphrase) > 0 {
		return gossh.ParsePrivateKeyWithPassphrase(pemBytes, passphrase)
	}
	return gossh.ParsePrivateKey(pemBytes)
}

// marshalPublicKey returns a base64-encoded representation of the public key
// suitable for storage and comparison.
func marshalPublicKey(key gossh.PublicKey) string {
	return key.Type() + " " + base64.StdEncoding.EncodeToString(key.Marshal())
}
