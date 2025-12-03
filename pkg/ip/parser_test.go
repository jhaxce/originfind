package ip

import (
	"net"
	"testing"
)

func TestToUint32(t *testing.T) {
	tests := []struct {
		name    string
		ip      string
		want    uint32
		wantErr bool
	}{
		{
			name:    "Valid IPv4",
			ip:      "192.168.1.1",
			want:    3232235777,
			wantErr: false,
		},
		{
			name:    "Zero IP",
			ip:      "0.0.0.0",
			want:    0,
			wantErr: false,
		},
		{
			name:    "Max IP",
			ip:      "255.255.255.255",
			want:    4294967295,
			wantErr: false,
		},
		{
			name:    "Invalid IPv6",
			ip:      "::1",
			want:    0,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip := net.ParseIP(tt.ip)
			got, err := ToUint32(ip)
			if (err != nil) != tt.wantErr {
				t.Errorf("ToUint32() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("ToUint32() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestFromUint32(t *testing.T) {
	tests := []struct {
		name string
		num  uint32
		want string
	}{
		{
			name: "Standard IP",
			num:  3232235777,
			want: "192.168.1.1",
		},
		{
			name: "Zero",
			num:  0,
			want: "0.0.0.0",
		},
		{
			name: "Max",
			num:  4294967295,
			want: "255.255.255.255",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := FromUint32(tt.num)
			if got.String() != tt.want {
				t.Errorf("FromUint32() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParseCIDR(t *testing.T) {
	tests := []struct {
		name    string
		cidr    string
		wantErr bool
	}{
		{
			name:    "Valid /24",
			cidr:    "192.168.1.0/24",
			wantErr: false,
		},
		{
			name:    "Valid /32",
			cidr:    "192.168.1.1/32",
			wantErr: false,
		},
		{
			name:    "Valid /31",
			cidr:    "192.168.1.0/31",
			wantErr: false,
		},
		{
			name:    "Invalid CIDR",
			cidr:    "192.168.1.0/33",
			wantErr: true,
		},
		{
			name:    "Invalid format",
			cidr:    "not-a-cidr",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := ParseCIDR(tt.cidr)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseCIDR() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestParseIPRange(t *testing.T) {
	tests := []struct {
		name      string
		startIP   string
		endIP     string
		wantCount uint64
		wantErr   bool
	}{
		{
			name:      "Valid range",
			startIP:   "192.168.1.1",
			endIP:     "192.168.1.10",
			wantCount: 10,
			wantErr:   false,
		},
		{
			name:      "Single IP",
			startIP:   "192.168.1.1",
			endIP:     "192.168.1.1",
			wantCount: 1,
			wantErr:   false,
		},
		{
			name:      "Reverse range",
			startIP:   "192.168.1.10",
			endIP:     "192.168.1.1",
			wantCount: 0,
			wantErr:   true,
		},
		{
			name:      "Invalid start IP",
			startIP:   "invalid",
			endIP:     "192.168.1.10",
			wantCount: 0,
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseIPRange(tt.startIP, tt.endIP)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseIPRange() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && got.Count() != tt.wantCount {
				t.Errorf("ParseIPRange() count = %v, want %v", got.Count(), tt.wantCount)
			}
		})
	}
}
