package ssh

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"net"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// testServer starts an in-memory SSH server that accepts public key auth.
// Returns the server address and a cleanup function.
func testServer(t *testing.T, authorizedKey ssh.PublicKey) (string, func()) {
	t.Helper()

	_, hostPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	hostSigner, err := ssh.NewSignerFromKey(hostPriv)
	if err != nil {
		t.Fatal(err)
	}

	config := &ssh.ServerConfig{
		PublicKeyCallback: func(c ssh.ConnMetadata, pubKey ssh.PublicKey) (*ssh.Permissions, error) {
			if authorizedKey != nil && bytes.Equal(pubKey.Marshal(), authorizedKey.Marshal()) {
				return &ssh.Permissions{}, nil
			}
			return nil, fmt.Errorf("unauthorized key")
		},
	}
	config.AddHostKey(hostSigner)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go handleTestConn(conn, config)
		}
	}()

	cleanup := func() {
		listener.Close()
		<-done
	}
	return listener.Addr().String(), cleanup
}

func handleTestConn(conn net.Conn, config *ssh.ServerConfig) {
	defer conn.Close()
	sshConn, chans, reqs, err := ssh.NewServerConn(conn, config)
	if err != nil {
		return
	}
	defer sshConn.Close()
	go ssh.DiscardRequests(reqs)

	for newCh := range chans {
		if newCh.ChannelType() != "session" {
			newCh.Reject(ssh.UnknownChannelType, "unsupported")
			continue
		}
		ch, requests, err := newCh.Accept()
		if err != nil {
			continue
		}
		go func() {
			defer ch.Close()
			for req := range requests {
				switch req.Type {
				case "exec":
					ch.Write([]byte("ok\n"))
					ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{0}))
					req.Reply(true, nil)
					return
				case "shell":
					req.Reply(true, nil)
					ch.Write([]byte("shell-ready\n"))
					return
				case "pty-req":
					req.Reply(true, nil)
				case "window-change":
					req.Reply(true, nil)
				default:
					req.Reply(false, nil)
				}
			}
		}()
	}
}

// generateTestKey creates an ed25519 key pair and returns PEM bytes + public key.
func generateTestKey(t *testing.T) ([]byte, ssh.PublicKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pemBlock, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatal(err)
	}
	pemBytes := pem.EncodeToMemory(pemBlock)

	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return pemBytes, sshPub
}

func TestDial_Success(t *testing.T) {
	keyPEM, pubKey := generateTestKey(t)
	addr, cleanup := testServer(t, pubKey)
	defer cleanup()

	host, portStr, _ := net.SplitHostPort(addr)
	port := 0
	fmt.Sscanf(portStr, "%d", &port)

	result, err := Dial(context.Background(), Config{
		Host:       host,
		Port:       port,
		User:       "test",
		PrivateKey: keyPEM,
		Timeout:    5 * time.Second,
	})
	if err != nil {
		t.Fatalf("Dial failed: %v", err)
	}
	defer result.Client.Close()

	if !result.HostKeyNew {
		t.Error("expected HostKeyNew=true on first connection")
	}
	if result.HostKey == "" {
		t.Error("expected non-empty HostKey")
	}
}

func TestDial_WrongKey(t *testing.T) {
	_, authorizedPub := generateTestKey(t)
	addr, cleanup := testServer(t, authorizedPub)
	defer cleanup()

	wrongKeyPEM, _ := generateTestKey(t)

	host, portStr, _ := net.SplitHostPort(addr)
	port := 0
	fmt.Sscanf(portStr, "%d", &port)

	_, err := Dial(context.Background(), Config{
		Host:       host,
		Port:       port,
		User:       "test",
		PrivateKey: wrongKeyPEM,
		Timeout:    5 * time.Second,
	})
	if err == nil {
		t.Fatal("expected error for wrong key")
	}
}

func TestDial_TOFU_Accept(t *testing.T) {
	keyPEM, pubKey := generateTestKey(t)
	addr, cleanup := testServer(t, pubKey)
	defer cleanup()

	host, portStr, _ := net.SplitHostPort(addr)
	port := 0
	fmt.Sscanf(portStr, "%d", &port)

	// First connection: no stored host key (TOFU accept)
	result, err := Dial(context.Background(), Config{
		Host:       host,
		Port:       port,
		User:       "test",
		PrivateKey: keyPEM,
	})
	if err != nil {
		t.Fatalf("first dial failed: %v", err)
	}
	result.Client.Close()

	if !result.HostKeyNew {
		t.Error("expected HostKeyNew=true")
	}
	savedKey := result.HostKey

	// Second connection: use stored host key (should succeed)
	result2, err := Dial(context.Background(), Config{
		Host:       host,
		Port:       port,
		User:       "test",
		PrivateKey: keyPEM,
		HostKey:    savedKey,
	})
	if err != nil {
		t.Fatalf("second dial failed: %v", err)
	}
	result2.Client.Close()

	if result2.HostKeyNew {
		t.Error("expected HostKeyNew=false on second connection")
	}
}

func TestDial_TOFU_Reject(t *testing.T) {
	keyPEM, pubKey := generateTestKey(t)
	addr, cleanup := testServer(t, pubKey)
	defer cleanup()

	host, portStr, _ := net.SplitHostPort(addr)
	port := 0
	fmt.Sscanf(portStr, "%d", &port)

	_, err := Dial(context.Background(), Config{
		Host:       host,
		Port:       port,
		User:       "test",
		PrivateKey: keyPEM,
		HostKey:    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakeKeyThatDoesNotMatch",
	})
	if err == nil {
		t.Fatal("expected error for host key mismatch")
	}
}

func TestDial_ContextCanceled(t *testing.T) {
	keyPEM, pubKey := generateTestKey(t)
	addr, cleanup := testServer(t, pubKey)
	defer cleanup()

	host, portStr, _ := net.SplitHostPort(addr)
	port := 0
	fmt.Sscanf(portStr, "%d", &port)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	_, err := Dial(ctx, Config{
		Host:       host,
		Port:       port,
		User:       "test",
		PrivateKey: keyPEM,
	})
	if err == nil {
		t.Fatal("expected error for canceled context")
	}
}

func TestDial_InvalidKey(t *testing.T) {
	_, err := Dial(context.Background(), Config{
		Host:       "127.0.0.1",
		Port:       22,
		User:       "test",
		PrivateKey: []byte("not a valid key"),
	})
	if err == nil {
		t.Fatal("expected error for invalid key")
	}
}
