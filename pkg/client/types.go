package client

// ServiceInfo is a safe view of a service (no secrets exposed).
// Matches the JSON shape returned by vault-server's GET /services endpoint.
type ServiceInfo struct {
	Name           string   `json:"name"`
	BaseURL        string   `json:"base_url"`
	AuthType       string   `json:"auth_type"`
	TLSSkipVerify  bool     `json:"tls_skip_verify,omitempty"`
	SessionCookies bool     `json:"session_cookies,omitempty"`
	Scopes         []string `json:"scopes,omitempty"`
	ExpiresAt      int64    `json:"expires_at,omitempty"`
	TokenStatus    string   `json:"token_status,omitempty"`
	SSHHost        string   `json:"ssh_host,omitempty"`
	SSHPort        int      `json:"ssh_port,omitempty"`
	SSHUser        string   `json:"ssh_user,omitempty"`
	SSHConnected   bool     `json:"ssh_connected,omitempty"`
	HeaderName     string   `json:"header_name,omitempty"`
	Username       string   `json:"username,omitempty"`
}

// TokenInfo describes an active token (no secret material).
// The server returns id_prefix (first 8 chars) — full IDs are never listed.
type TokenInfo struct {
	IDPrefix  string `json:"id_prefix"`
	Scope     string `json:"scope"`
	CreatedAt string `json:"created_at,omitempty"`
	ExpiresAt string `json:"expires_at,omitempty"`
}

// FileInfo is a safe view of a stored file (no data).
type FileInfo struct {
	Name     string `json:"name"`
	MimeType string `json:"mime_type"`
	Size     int    `json:"size"`
}

// SSHExecResult is the response from executing a command via SSH proxy.
type SSHExecResult struct {
	Stdout     string `json:"stdout"`
	Stderr     string `json:"stderr"`
	ExitCode   int    `json:"exit_code"`
	DurationMs int    `json:"duration_ms"`
}
