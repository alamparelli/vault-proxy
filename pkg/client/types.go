package client

// ServiceInfo is a safe view of a service (no secrets exposed).
// Matches the JSON shape returned by vault-server's GET /services endpoint.
type ServiceInfo struct {
	Name     string `json:"name"`
	BaseURL  string `json:"base_url"`
	AuthType string `json:"auth_type"`
}

// TokenInfo describes an active token (no secret material).
type TokenInfo struct {
	ID    string `json:"id"`
	Scope string `json:"scope"`
}
