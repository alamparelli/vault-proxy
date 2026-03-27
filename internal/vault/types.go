package vault

import "time"

// Vault holds all secrets in memory.
type Vault struct {
	Services map[string]*Service `json:"services"`
	Files    map[string]*File    `json:"files"`
}

// Service represents a configured API service.
type Service struct {
	Name           string `json:"name"`
	BaseURL        string `json:"base_url"`
	Auth           Auth   `json:"auth"`
	TLSSkipVerify  bool   `json:"tls_skip_verify,omitempty"`
	SessionCookies bool   `json:"session_cookies,omitempty"` // persist upstream cookies between proxy calls (sticky sessions, CSRF, etc.)
}

// Auth holds credentials for a service.
type Auth struct {
	Type string `json:"type"` // bearer, header, basic, oauth2_client, service_account, ssh_key, url

	// bearer
	Token string `json:"token,omitempty"`

	// header
	HeaderName  string `json:"header_name,omitempty"`
	HeaderValue string `json:"header_value,omitempty"`

	// basic
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`

	// oauth2_client
	ClientID     string   `json:"client_id,omitempty"`
	ClientSecret string   `json:"client_secret,omitempty"`
	RefreshToken string   `json:"refresh_token,omitempty"`
	TokenURL     string   `json:"token_url,omitempty"`
	AccessToken  string   `json:"access_token,omitempty"`
	ExpiresAt    int64    `json:"expires_at,omitempty"` // unix timestamp
	Scopes       []string `json:"scopes,omitempty"`

	// google_oauth2 (file-based setup, resolved to oauth2_client fields)
	ClientSecretFile string `json:"client_secret_file,omitempty"` // references Files entry
	TokenFile        string `json:"token_file,omitempty"`         // references Files entry

	// service_account
	FileRef     string   `json:"file_ref,omitempty"`        // references Files entry
	SAScopes    []string `json:"sa_scopes,omitempty"`
	SATokenURL  string   `json:"sa_token_url,omitempty"`    // defaults to Google's
	SAToken     string   `json:"sa_access_token,omitempty"`
	SAExpiresAt int64    `json:"sa_expires_at,omitempty"`

	// ssh_key
	SSHHost          string `json:"ssh_host,omitempty"`           // hostname or IP
	SSHPort          int    `json:"ssh_port,omitempty"`           // default 22
	SSHUser          string `json:"ssh_user,omitempty"`
	SSHKeyFileRef    string `json:"ssh_key_file_ref,omitempty"`   // references Files entry (PEM private key)
	SSHKeyPassphrase string `json:"ssh_key_passphrase,omitempty"` // optional, encrypted at rest
	SSHHostKey       string   `json:"ssh_host_key,omitempty"`         // auto-saved on first connect (TOFU)
	SSHAllowedCmds   []string `json:"ssh_allowed_commands,omitempty"` // if set, only these command prefixes are allowed
}

// File holds an encrypted credential file.
type File struct {
	Name     string `json:"name"`
	MimeType string `json:"mime_type"`
	Data     []byte `json:"data"`
}

// FileInfo is a safe view of a file (no data).
type FileInfo struct {
	Name     string `json:"name"`
	MimeType string `json:"mime_type"`
	Size     int    `json:"size"`
}

// Info returns a data-free view of the file.
func (f *File) Info() FileInfo {
	return FileInfo{
		Name:     f.Name,
		MimeType: f.MimeType,
		Size:     len(f.Data),
	}
}

// ServiceInfo is a safe view of a service (no secrets).
type ServiceInfo struct {
	Name          string   `json:"name"`
	BaseURL       string   `json:"base_url"`
	AuthType      string   `json:"auth_type"`
	TLSSkipVerify bool     `json:"tls_skip_verify,omitempty"`
	ExpiresAt     int64    `json:"expires_at,omitempty"`    // unix timestamp for oauth2/sa tokens
	TokenStatus   string   `json:"token_status,omitempty"`  // "valid", "expiring", "expired", ""
	Scopes        []string `json:"scopes,omitempty"`        // oauth2/sa scopes (not secret)
	SSHHost       string   `json:"ssh_host,omitempty"`      // hostname or IP (ssh_key only)
	SSHPort       int      `json:"ssh_port,omitempty"`      // port (ssh_key only)
	SSHUser       string   `json:"ssh_user,omitempty"`      // username (ssh_key only)
	SSHConnected   bool     `json:"ssh_connected,omitempty"`   // true if TOFU host key is set
	SessionCookies bool     `json:"session_cookies,omitempty"` // true if session cookie jar is enabled
	HeaderName     string   `json:"header_name,omitempty"`     // header auth: header key name (not secret)
	Username       string   `json:"username,omitempty"`        // basic auth: username (not secret)
}

// SafeInfo returns a secret-free view of the service.
func (s *Service) SafeInfo() ServiceInfo {
	info := ServiceInfo{
		Name:           s.Name,
		BaseURL:        s.BaseURL,
		AuthType:       s.Auth.Type,
		TLSSkipVerify:  s.TLSSkipVerify,
		SessionCookies: s.SessionCookies,
	}
	// Include token expiry and scopes for OAuth2 and service account types.
	switch s.Auth.Type {
	case "oauth2_client":
		info.ExpiresAt = s.Auth.ExpiresAt
		info.Scopes = s.Auth.Scopes
	case "service_account":
		info.ExpiresAt = s.Auth.SAExpiresAt
		info.Scopes = s.Auth.SAScopes
	case "header":
		info.HeaderName = s.Auth.HeaderName
	case "basic":
		info.Username = s.Auth.Username
	case "ssh_key":
		info.SSHHost = s.Auth.SSHHost
		info.SSHPort = s.Auth.SSHPort
		info.SSHUser = s.Auth.SSHUser
		info.SSHConnected = s.Auth.SSHHostKey != ""
	}
	if info.ExpiresAt > 0 {
		info.TokenStatus = TokenStatus(info.ExpiresAt)
	}
	return info
}

// TokenStatus returns the status of a token based on its expiry.
func TokenStatus(expiresAt int64) string {
	now := time.Now().Unix()
	if expiresAt <= now {
		return "expired"
	}
	if expiresAt <= now+1800 { // 30 minutes
		return "expiring"
	}
	return "valid"
}
