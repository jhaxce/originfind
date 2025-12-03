package ip

import (
	"net"
	"testing"
)

func TestValidateDomain(t *testing.T) {
	tests := []struct {
		name    string
		domain  string
		wantErr bool
	}{
		{
			name:    "Valid domain",
			domain:  "example.com",
			wantErr: false,
		},
		{
			name:    "Valid subdomain",
			domain:  "www.example.com",
			wantErr: false,
		},
		{
			name:    "Valid deep subdomain",
			domain:  "api.staging.example.com",
			wantErr: false,
		},
		{
			name:    "Invalid - empty",
			domain:  "",
			wantErr: true,
		},
		{
			name:    "Invalid - starts with dot",
			domain:  ".example.com",
			wantErr: true,
		},
		{
			name:    "Invalid - has space",
			domain:  "example .com",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateDomain(tt.domain)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateDomain(%q) error = %v, wantErr %v", tt.domain, err, tt.wantErr)
			}
		})
	}
}

func TestSanitizeDomain(t *testing.T) {
	tests := []struct {
		name   string
		domain string
		want   string
	}{
		{
			name:   "Clean domain",
			domain: "example.com",
			want:   "example.com",
		},
		{
			name:   "With http://",
			domain: "http://example.com",
			want:   "example.com",
		},
		{
			name:   "With https://",
			domain: "https://example.com",
			want:   "example.com",
		},
		{
			name:   "With www prefix",
			domain: "www.example.com",
			want:   "example.com",
		},
		{
			name:   "With trailing slash",
			domain: "example.com/",
			want:   "example.com",
		},
		{
			name:   "With https and www",
			domain: "https://www.example.com/",
			want:   "example.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := SanitizeDomain(tt.domain); got != tt.want {
				t.Errorf("SanitizeDomain(%q) = %v, want %v", tt.domain, got, tt.want)
			}
		})
	}
}

func TestIsPrivateIP(t *testing.T) {
	tests := []struct {
		name string
		ip   string
		want bool
	}{
		{
			name: "Private 10.x",
			ip:   "10.0.0.1",
			want: true,
		},
		{
			name: "Private 192.168.x",
			ip:   "192.168.1.1",
			want: true,
		},
		{
			name: "Private 172.16.x",
			ip:   "172.16.0.1",
			want: true,
		},
		{
			name: "Localhost",
			ip:   "127.0.0.1",
			want: true,
		},
		{
			name: "Public IP",
			ip:   "8.8.8.8",
			want: false,
		},
		{
			name: "Public IP 2",
			ip:   "1.1.1.1",
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip := net.ParseIP(tt.ip)
			if got := IsPrivateIP(ip); got != tt.want {
				t.Errorf("IsPrivateIP(%q) = %v, want %v", tt.ip, got, tt.want)
			}
		})
	}
}
