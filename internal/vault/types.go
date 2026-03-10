package vault

// Vault holds all secrets in memory.
type Vault struct {
	Services map[string]*Service `json:"services"`
	Files    map[string]*File    `json:"files"`
}

// Service represents a configured API service.
type Service struct {
	Name          string `json:"name"`
	BaseURL       string `json:"base_url"`
	Auth          Auth   `json:"auth"`
	TLSSkipVerify bool   `json:"tls_skip_verify,omitempty"`
}

// Auth holds credentials for a service.
type Auth struct {
	Type string `json:"type"` // bearer, header, basic, oauth2_client, service_account

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
	Name          string `json:"name"`
	BaseURL       string `json:"base_url"`
	AuthType      string `json:"auth_type"`
	TLSSkipVerify bool   `json:"tls_skip_verify,omitempty"`
}

// SafeInfo returns a secret-free view of the service.
func (s *Service) SafeInfo() ServiceInfo {
	return ServiceInfo{
		Name:          s.Name,
		BaseURL:       s.BaseURL,
		AuthType:      s.Auth.Type,
		TLSSkipVerify: s.TLSSkipVerify,
	}
}
