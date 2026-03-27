package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"mime/multipart"
	"net/http"
	"os"
	"path"
	"strconv"
	"strings"
	"sync"
	"time"

	internalssh "github.com/alamparelli/vault-proxy/internal/ssh"
	"github.com/alamparelli/vault-proxy/internal/vault"
	"github.com/pkg/sftp"
	gossh "golang.org/x/crypto/ssh"
	"nhooyr.io/websocket"
)

const (
	defaultExecTimeout = 30 * time.Second
	maxExecTimeout     = 300 * time.Second
	maxSFTPFileSize    = 50 << 20 // 50 MB
	maxExecOutput      = 10 << 20 // 10 MB per stream
)

// sshRouter dispatches /ssh/{service}/{action} requests.
func (s *Server) sshRouter(w http.ResponseWriter, r *http.Request) {
	// Parse: /ssh/{service}/{action}
	trimmed := strings.TrimPrefix(r.URL.Path, "/ssh/")
	parts := strings.SplitN(trimmed, "/", 2)
	if len(parts) < 2 || parts[0] == "" || parts[1] == "" {
		http.Error(w, `{"error":"expected /ssh/{service}/{action}"}`, http.StatusBadRequest)
		return
	}
	service, action := parts[0], parts[1]

	switch action {
	case "exec":
		s.sshExecHandler(w, r, service)
	case "upload":
		s.sshUploadHandler(w, r, service)
	case "download":
		s.sshDownloadHandler(w, r, service)
	case "session":
		s.sshSessionHandler(w, r, service)
	default:
		http.Error(w, `{"error":"unknown SSH action"}`, http.StatusBadRequest)
	}
}

// sshExecHandler handles POST /ssh/{service}/exec
func (s *Server) sshExecHandler(w http.ResponseWriter, r *http.Request, service string) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Command string `json:"command"`
		Timeout int    `json:"timeout"` // seconds, default 30, max 300
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxJSONBodySize)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), http.StatusBadRequest)
		return
	}
	if req.Command == "" {
		http.Error(w, `{"error":"command is required"}`, http.StatusBadRequest)
		return
	}

	timeout := defaultExecTimeout
	if req.Timeout > 0 {
		timeout = time.Duration(req.Timeout) * time.Second
		if timeout > maxExecTimeout {
			timeout = maxExecTimeout
		}
	}

	svc, cfg, err := s.sshConfig(service)
	if err != nil {
		status := http.StatusNotFound
		if strings.Contains(err.Error(), "not an ssh_key service") {
			status = http.StatusBadRequest
		}
		http.Error(w, `{"error":"SSH service not available"}`, status)
		return
	}
	defer wipeSSHConfig(cfg)

	// SEC-001: Enforce per-service command allowlist if configured.
	if len(svc.Auth.SSHAllowedCmds) > 0 {
		if !isCommandAllowed(req.Command, svc.Auth.SSHAllowedCmds) {
			http.Error(w, `{"error":"command not in allowed list for this service"}`, http.StatusForbidden)
			return
		}
	}

	ctx, cancel := context.WithTimeout(r.Context(), timeout)
	defer cancel()

	start := time.Now()
	result, err := internalssh.Dial(ctx, *cfg)
	if err != nil {
		log.Printf("ssh exec: dial failed for %q: %v", service, err)
		http.Error(w, `{"error":"failed to connect to remote host"}`, http.StatusBadGateway)
		return
	}
	defer result.Client.Close()
	s.persistHostKey(svc.Name, result)

	session, err := result.Client.NewSession()
	if err != nil {
		log.Printf("ssh exec: session failed for %q: %v", service, err)
		http.Error(w, `{"error":"SSH session setup failed"}`, http.StatusBadGateway)
		return
	}
	defer session.Close()

	// SEC: Bound output buffers to prevent memory exhaustion from large command output.
	stdout := &limitedWriter{max: maxExecOutput}
	stderr := &limitedWriter{max: maxExecOutput}
	session.Stdout = stdout
	session.Stderr = stderr

	exitCode := 0
	if err := session.Run(req.Command); err != nil {
		if exitErr, ok := err.(*gossh.ExitError); ok {
			exitCode = exitErr.ExitStatus()
		} else {
			log.Printf("ssh exec: command error for %q: %v", service, err)
			http.Error(w, `{"error":"command execution failed"}`, http.StatusBadGateway)
			return
		}
	}
	duration := time.Since(start)

	// Audit log
	cmdLog := req.Command
	if len(cmdLog) > 200 {
		cmdLog = cmdLog[:200] + "..."
	}
	tok := tokenFromContext(r)
	tokenPrefix := ""
	if tok != nil && len(tok.ID) >= 8 {
		tokenPrefix = tok.ID[:8]
	}
	log.Printf("ssh exec: service=%s cmd=%q exit=%d duration=%s token=%s...",
		service, cmdLog, exitCode, duration.Round(time.Millisecond), tokenPrefix)

	writeJSON(w, http.StatusOK, map[string]any{
		"stdout":      stdout.String(),
		"stderr":      stderr.String(),
		"exit_code":   exitCode,
		"duration_ms": duration.Milliseconds(),
	})
}

// sshUploadHandler handles POST /ssh/{service}/upload (multipart: remote_path + file + mode)
func (s *Server) sshUploadHandler(w http.ResponseWriter, r *http.Request, service string) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxSFTPFileSize+1<<20) // file + form overhead
	if err := r.ParseMultipartForm(maxSFTPFileSize); err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"parse form: %s"}`, err), http.StatusBadRequest)
		return
	}

	remotePath := r.FormValue("remote_path")
	if remotePath == "" {
		http.Error(w, `{"error":"remote_path is required"}`, http.StatusBadRequest)
		return
	}
	// SEC-002: Validate remote path to prevent writes to sensitive directories.
	if err := validateRemotePath(remotePath); err != nil {
		http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), http.StatusBadRequest)
		return
	}
	modeStr := r.FormValue("mode")
	if modeStr == "" {
		modeStr = "0644"
	}
	mode, err := strconv.ParseUint(modeStr, 8, 32)
	if err != nil {
		http.Error(w, `{"error":"invalid mode (use octal, e.g. 0644)"}`, http.StatusBadRequest)
		return
	}

	var fileReader io.Reader
	var fileSize int64
	file, _, err := r.FormFile("file")
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"file field required: %s"}`, err), http.StatusBadRequest)
		return
	}
	defer file.Close()
	fileReader = file
	if sizer, ok := file.(interface{ Size() int64 }); ok {
		fileSize = sizer.Size()
	}

	svc, cfg, err := s.sshConfig(service)
	if err != nil {
		http.Error(w, `{"error":"SSH service not found"}`, http.StatusNotFound)
		return
	}
	defer wipeSSHConfig(cfg)

	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Minute)
	defer cancel()

	result, err := internalssh.Dial(ctx, *cfg)
	if err != nil {
		log.Printf("ssh upload: dial failed for %q: %v", service, err)
		http.Error(w, `{"error":"failed to connect to remote host"}`, http.StatusBadGateway)
		return
	}
	defer result.Client.Close()
	s.persistHostKey(svc.Name, result)

	sftpClient, err := sftp.NewClient(result.Client)
	if err != nil {
		http.Error(w, `{"error":"SFTP connection failed"}`, http.StatusBadGateway)
		return
	}
	defer sftpClient.Close()

	// Create parent directories
	dir := path.Dir(remotePath)
	if dir != "." && dir != "/" {
		sftpClient.MkdirAll(dir) // best-effort
	}

	remoteFile, err := sftpClient.Create(remotePath)
	if err != nil {
		http.Error(w, `{"error":"failed to create remote file"}`, http.StatusBadGateway)
		return
	}

	written, err := io.Copy(remoteFile, fileReader)
	remoteFile.Close()
	if err != nil {
		http.Error(w, `{"error":"failed to write remote file"}`, http.StatusBadGateway)
		return
	}

	if err := sftpClient.Chmod(remotePath, os.FileMode(mode)); err != nil {
		log.Printf("ssh upload: chmod failed (non-fatal): %v", err)
	}

	log.Printf("ssh upload: service=%s path=%s bytes=%d", service, remotePath, written)

	_ = fileSize // may be used for validation in future
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":          true,
		"bytes":       written,
		"remote_path": remotePath,
	})
}

// sshDownloadHandler handles POST /ssh/{service}/download
func (s *Server) sshDownloadHandler(w http.ResponseWriter, r *http.Request, service string) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		RemotePath string `json:"remote_path"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxJSONBodySize)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), http.StatusBadRequest)
		return
	}
	if req.RemotePath == "" {
		http.Error(w, `{"error":"remote_path is required"}`, http.StatusBadRequest)
		return
	}
	// SEC-002: Validate remote path to prevent reads from sensitive directories.
	if err := validateRemotePath(req.RemotePath); err != nil {
		http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), http.StatusBadRequest)
		return
	}

	_, cfg, err := s.sshConfig(service)
	if err != nil {
		http.Error(w, `{"error":"SSH service not found"}`, http.StatusNotFound)
		return
	}
	defer wipeSSHConfig(cfg)

	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Minute)
	defer cancel()

	result, err := internalssh.Dial(ctx, *cfg)
	if err != nil {
		log.Printf("ssh download: dial failed for %q: %v", service, err)
		http.Error(w, `{"error":"failed to connect to remote host"}`, http.StatusBadGateway)
		return
	}
	defer result.Client.Close()

	sftpClient, err := sftp.NewClient(result.Client)
	if err != nil {
		http.Error(w, `{"error":"SFTP connection failed"}`, http.StatusBadGateway)
		return
	}
	defer sftpClient.Close()

	info, err := sftpClient.Stat(req.RemotePath)
	if err != nil {
		http.Error(w, `{"error":"remote file not found"}`, http.StatusNotFound)
		return
	}
	if info.Size() > maxSFTPFileSize {
		http.Error(w, fmt.Sprintf(`{"error":"file too large: %d bytes (max %d)"}`, info.Size(), maxSFTPFileSize), http.StatusBadRequest)
		return
	}

	remoteFile, err := sftpClient.Open(req.RemotePath)
	if err != nil {
		http.Error(w, `{"error":"failed to open remote file"}`, http.StatusBadGateway)
		return
	}
	defer remoteFile.Close()

	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", path.Base(req.RemotePath)))
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", strconv.FormatInt(info.Size(), 10))
	io.Copy(w, remoteFile)

	log.Printf("ssh download: service=%s path=%s bytes=%d", service, req.RemotePath, info.Size())
}

// sshConfig loads and validates an SSH service, returning the service and dial config.
func (s *Server) sshConfig(serviceName string) (*vault.Service, *internalssh.Config, error) {
	svc, err := s.store.GetService(serviceName)
	if err != nil {
		return nil, nil, fmt.Errorf("service %q: %w", serviceName, err)
	}
	if svc.Auth.Type != "ssh_key" {
		return nil, nil, fmt.Errorf("service %q is not an ssh_key service", serviceName)
	}

	keyFile, err := s.store.GetFile(svc.Auth.SSHKeyFileRef)
	if err != nil {
		return nil, nil, fmt.Errorf("ssh key file %q: %w", svc.Auth.SSHKeyFileRef, err)
	}

	cfg := &internalssh.Config{
		Host:       svc.Auth.SSHHost,
		Port:       svc.Auth.SSHPort,
		User:       svc.Auth.SSHUser,
		PrivateKey: keyFile.Data,
		HostKey:    svc.Auth.SSHHostKey,
	}
	if svc.Auth.SSHKeyPassphrase != "" {
		cfg.Passphrase = []byte(svc.Auth.SSHKeyPassphrase)
	}
	return svc, cfg, nil
}

// wipeSSHConfig zeros sensitive material in the SSH config after use.
func wipeSSHConfig(cfg *internalssh.Config) {
	for i := range cfg.Passphrase {
		cfg.Passphrase[i] = 0
	}
	for i := range cfg.PrivateKey {
		cfg.PrivateKey[i] = 0
	}
}

// persistHostKey saves the host key on first connection (TOFU).
// SEC: Uses compare-and-swap to prevent race conditions on concurrent first connections.
func (s *Server) persistHostKey(serviceName string, result *internalssh.DialResult) {
	if !result.HostKeyNew || result.HostKey == "" {
		return
	}
	// Re-read the service to check if another goroutine already set the host key.
	svc, err := s.store.GetService(serviceName)
	if err != nil {
		log.Printf("ssh TOFU: failed to get service %q for host key save: %v", serviceName, err)
		return
	}
	if svc.Auth.SSHHostKey != "" {
		// Another connection already saved a host key — don't overwrite.
		log.Printf("ssh TOFU: host key for %q already set by concurrent connection, skipping", serviceName)
		return
	}
	svc.Auth.SSHHostKey = result.HostKey
	if err := s.store.UpdateServiceAuth(serviceName, svc.Auth); err != nil {
		log.Printf("ssh TOFU: failed to save host key for %q: %v", serviceName, err)
		return
	}
	log.Printf("ssh TOFU: saved host key for %q", serviceName)
}

// isCommandAllowed checks if cmd starts with any of the allowed prefixes.
func isCommandAllowed(cmd string, allowed []string) bool {
	for _, prefix := range allowed {
		if cmd == prefix || strings.HasPrefix(cmd, prefix+" ") {
			return true
		}
	}
	return false
}

// SEC-002: blockedRemotePaths are directories that SFTP must never write to.
var blockedRemotePaths = []string{
	"/etc/",
	"/root/.ssh/",
	"/proc/",
	"/sys/",
	"/dev/",
	"/boot/",
	"/lib/",
	"/lib64/",
	"/sbin/",
	"/usr/sbin/",
}

// validateRemotePath checks that a remote SFTP path is absolute and not targeting
// sensitive system directories.
func validateRemotePath(p string) error {
	cleaned := path.Clean(p)
	if !path.IsAbs(cleaned) {
		return fmt.Errorf("remote_path must be absolute")
	}
	// Ensure cleaned path ends with / for prefix matching against directories
	withSlash := cleaned + "/"
	for _, blocked := range blockedRemotePaths {
		if strings.HasPrefix(withSlash, blocked) {
			return fmt.Errorf("remote_path targets a restricted directory")
		}
	}
	return nil
}

// multipartFile wraps multipart.File to check size.
func sizeFromMultipartFile(f multipart.File) int64 {
	if seeker, ok := f.(io.Seeker); ok {
		cur, _ := seeker.Seek(0, io.SeekCurrent)
		size, err := seeker.Seek(0, io.SeekEnd)
		if err == nil {
			seeker.Seek(cur, io.SeekStart)
			return size
		}
	}
	return -1
}

// limitedWriter is a bytes.Buffer that stops accepting writes after max bytes.
type limitedWriter struct {
	buf bytes.Buffer
	max int
}

func (w *limitedWriter) Write(p []byte) (int, error) {
	remaining := w.max - w.buf.Len()
	if remaining <= 0 {
		return len(p), nil // silently discard excess (don't kill the SSH session)
	}
	if len(p) > remaining {
		p = p[:remaining]
	}
	return w.buf.Write(p)
}

func (w *limitedWriter) String() string { return w.buf.String() }

// sshSessionHandler handles WS /ssh/{service}/session — interactive SSH shell via WebSocket.
func (s *Server) sshSessionHandler(w http.ResponseWriter, r *http.Request, service string) {
	svc, cfg, err := s.sshConfig(service)
	if err != nil {
		http.Error(w, `{"error":"SSH service not found"}`, http.StatusNotFound)
		return
	}
	defer wipeSSHConfig(cfg)

	// Parse initial terminal size from query params
	cols := 80
	rows := 24
	if c := r.URL.Query().Get("cols"); c != "" {
		if v, err := strconv.Atoi(c); err == nil && v > 0 && v < 500 {
			cols = v
		}
	}
	if ro := r.URL.Query().Get("rows"); ro != "" {
		if v, err := strconv.Atoi(ro); err == nil && v > 0 && v < 500 {
			rows = v
		}
	}

	// Dial SSH
	result, err := internalssh.Dial(r.Context(), *cfg)
	if err != nil {
		log.Printf("ssh session: dial failed for %q: %v", service, err)
		http.Error(w, `{"error":"failed to connect to remote host"}`, http.StatusBadGateway)
		return
	}
	s.persistHostKey(svc.Name, result)

	sshSession, err := result.Client.NewSession()
	if err != nil {
		result.Client.Close()
		log.Printf("ssh session: new session failed for %q: %v", service, err)
		http.Error(w, `{"error":"SSH session setup failed"}`, http.StatusBadGateway)
		return
	}

	// Request PTY
	modes := gossh.TerminalModes{
		gossh.ECHO:          1,
		gossh.TTY_OP_ISPEED: 14400,
		gossh.TTY_OP_OSPEED: 14400,
	}
	if err := sshSession.RequestPty("xterm-256color", rows, cols, modes); err != nil {
		sshSession.Close()
		result.Client.Close()
		log.Printf("ssh session: PTY request failed for %q: %v", service, err)
		http.Error(w, `{"error":"SSH session setup failed"}`, http.StatusBadGateway)
		return
	}

	stdin, err := sshSession.StdinPipe()
	if err != nil {
		sshSession.Close()
		result.Client.Close()
		http.Error(w, `{"error":"SSH session setup failed"}`, http.StatusBadGateway)
		return
	}

	stdout, err := sshSession.StdoutPipe()
	if err != nil {
		sshSession.Close()
		result.Client.Close()
		http.Error(w, `{"error":"SSH session setup failed"}`, http.StatusBadGateway)
		return
	}

	if err := sshSession.Shell(); err != nil {
		sshSession.Close()
		result.Client.Close()
		log.Printf("ssh session: shell start failed for %q: %v", service, err)
		http.Error(w, `{"error":"SSH session setup failed"}`, http.StatusBadGateway)
		return
	}

	// SEC: Only accept connections from localhost (vault-proxy is internal).
	conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		OriginPatterns: []string{"localhost:*", "127.0.0.1:*"},
	})
	if err != nil {
		sshSession.Close()
		result.Client.Close()
		log.Printf("ssh session: websocket accept failed: %v", err)
		return
	}

	log.Printf("ssh session: connected to %s@%s:%d via service %s",
		cfg.User, cfg.Host, cfg.Port, service)

	// SEC: Max session duration to prevent resource exhaustion.
	ctx, cancel := context.WithTimeout(r.Context(), 4*time.Hour)
	defer cancel()

	// Use a single cleanup to close everything
	var once sync.Once
	cleanup := func() {
		once.Do(func() {
			cancel()
			conn.Close(websocket.StatusNormalClosure, "session ended")
			stdin.Close()
			sshSession.Close()
			result.Client.Close()
		})
	}
	defer cleanup()

	// SSH stdout → WebSocket (binary messages)
	go func() {
		defer cleanup()
		buf := make([]byte, 4096)
		for {
			n, err := stdout.Read(buf)
			if err != nil {
				return
			}
			if err := conn.Write(ctx, websocket.MessageBinary, buf[:n]); err != nil {
				return
			}
		}
	}()

	// WebSocket → SSH stdin (text = input, binary [0x01,...] = resize)
	// SEC: Read directly from conn (no CloseRead — that conflicts with Read).
	for {
		typ, data, err := conn.Read(ctx)
		if err != nil {
			return
		}
		if typ == websocket.MessageBinary && len(data) >= 5 && data[0] == 0x01 {
			// Resize: [0x01, cols_hi, cols_lo, rows_hi, rows_lo]
			newCols := int(data[1])<<8 | int(data[2])
			newRows := int(data[3])<<8 | int(data[4])
			if newCols > 0 && newCols < 500 && newRows > 0 && newRows < 500 {
				sshSession.WindowChange(newRows, newCols)
			}
			continue
		}
		// Text message = user input
		if _, err := stdin.Write(data); err != nil {
			return
		}
	}
}
