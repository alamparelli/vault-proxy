package api

import (
	"strings"
	"testing"
)

func TestValidateBaseURL(t *testing.T) {
	tests := []struct {
		name         string
		url          string
		allowPrivate bool
		wantErr      bool
		errContains  string
	}{
		{
			name:         "HTTPS with allowPrivate=false is ok",
			url:          "https://api.example.com/v1",
			allowPrivate: false,
			wantErr:      false,
		},
		{
			name:         "HTTP with allowPrivate=false is rejected",
			url:          "http://api.example.com/v1",
			allowPrivate: false,
			wantErr:      true,
			errContains:  "must use HTTPS",
		},
		{
			name:         "HTTP with allowPrivate=true is allowed",
			url:          "http://192.168.1.100:8080/api",
			allowPrivate: true,
			wantErr:      false,
		},
		{
			name:         "HTTPS with allowPrivate=true is allowed",
			url:          "https://internal.local:443",
			allowPrivate: true,
			wantErr:      false,
		},
		{
			name:         "empty scheme is rejected (no host parsed)",
			url:          "noscheme.example.com",
			allowPrivate: false,
			wantErr:      true,
			errContains:  "must have a host",
		},
		{
			name:         "ftp scheme with allowPrivate=false is rejected",
			url:          "ftp://files.example.com",
			allowPrivate: false,
			wantErr:      true,
			errContains:  "must use HTTPS",
		},
		{
			name:         "ftp scheme with allowPrivate=true is rejected",
			url:          "ftp://files.example.com",
			allowPrivate: true,
			wantErr:      true,
			errContains:  "must use HTTP or HTTPS",
		},
		{
			name:         "empty URL is rejected",
			url:          "",
			allowPrivate: false,
			wantErr:      true,
			errContains:  "must have a host",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateBaseURL(tt.url, tt.allowPrivate)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tt.errContains)
				}
				if !strings.Contains(err.Error(), tt.errContains) {
					t.Errorf("expected error containing %q, got %q", tt.errContains, err.Error())
				}
			} else {
				if err != nil {
					t.Fatalf("expected no error, got: %v", err)
				}
			}
		})
	}
}
