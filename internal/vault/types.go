package vault

// Vault holds all secrets in memory.
type Vault struct {
	Services map[string]*Service `json:"services"`
	Files    map[string]*File    `json:"files"`
}

// Service represents a configured API service.
type Service struct {
	Name    string `json:"name"`
	BaseURL string `json:"base_url"`
	Auth    Auth   `json:"auth"`
}

// Auth holds credentials for a service.
type Auth struct {
	Type string `json:"type"` // bearer, header, basic

	// bearer
	Token string `json:"token,omitempty"`

	// header
	HeaderName  string `json:"header_name,omitempty"`
	HeaderValue string `json:"header_value,omitempty"`

	// basic
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
}

// File holds an encrypted credential file.
type File struct {
	Name     string `json:"name"`
	MimeType string `json:"mime_type"`
	Data     []byte `json:"data"`
}

// ServiceInfo is a safe view of a service (no secrets).
type ServiceInfo struct {
	Name     string `json:"name"`
	BaseURL  string `json:"base_url"`
	AuthType string `json:"auth_type"`
}

// SafeInfo returns a secret-free view of the service.
func (s *Service) SafeInfo() ServiceInfo {
	return ServiceInfo{
		Name:     s.Name,
		BaseURL:  s.BaseURL,
		AuthType: s.Auth.Type,
	}
}
