// Package ip provides IP address validation utilities
package ip

import (
	"fmt"
	"net"
	"strings"
)

// ValidateDomain performs basic validation on a domain string
func ValidateDomain(domain string) error {
	if domain == "" {
		return fmt.Errorf("domain is empty")
	}

	// Remove protocol if present
	domain = strings.TrimPrefix(domain, "http://")
	domain = strings.TrimPrefix(domain, "https://")

	// Remove trailing slash
	domain = strings.TrimSuffix(domain, "/")

	// Reject domains with invalid characters
	if strings.ContainsAny(domain, " /:") {
		return fmt.Errorf("domain contains invalid characters")
	}

	// Domain shouldn't start or end with hyphen or dot
	if strings.HasPrefix(domain, "-") || strings.HasSuffix(domain, "-") {
		return fmt.Errorf("domain cannot start or end with hyphen")
	}

	if strings.HasPrefix(domain, ".") || strings.HasSuffix(domain, ".") {
		return fmt.Errorf("domain cannot start or end with dot")
	}

	// Basic length check
	if len(domain) > 253 {
		return fmt.Errorf("domain exceeds maximum length (253)")
	}

	return nil
}

// ValidateIPRange validates that a start and end IP form a valid range
func ValidateIPRange(startIP, endIP net.IP) error {
	if startIP == nil || endIP == nil {
		return fmt.Errorf("IP addresses cannot be nil")
	}

	if !IsIPv4(startIP) || !IsIPv4(endIP) {
		return fmt.Errorf("only IPv4 ranges are supported")
	}

	startInt, _ := ToUint32(startIP)
	endInt, _ := ToUint32(endIP)

	if startInt > endInt {
		return fmt.Errorf("start IP (%s) is greater than end IP (%s)", startIP, endIP)
	}

	return nil
}

// ValidateCIDR validates a CIDR notation
func ValidateCIDR(cidr string) error {
	_, network, err := net.ParseCIDR(cidr)
	if err != nil {
		return fmt.Errorf("invalid CIDR: %w", err)
	}

	// Check if it's IPv4
	if network.IP.To4() == nil {
		return fmt.Errorf("only IPv4 CIDR is supported")
	}

	ones, bits := network.Mask.Size()
	if bits != 32 {
		return fmt.Errorf("invalid network mask")
	}

	// Warn about very large ranges
	if ones < 16 {
		ipCount := uint64(1) << uint(32-ones)
		return fmt.Errorf("CIDR /%d is very large (%d IPs), use with caution", ones, ipCount)
	}

	return nil
}

// IsPrivateIP checks if an IP is in a private range
func IsPrivateIP(ip net.IP) bool {
	if !IsIPv4(ip) {
		return false
	}

	// Private ranges: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
	privateRanges := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"127.0.0.0/8",    // Loopback
		"169.254.0.0/16", // Link-local
	}

	for _, cidr := range privateRanges {
		_, network, _ := net.ParseCIDR(cidr)
		if network.Contains(ip) {
			return true
		}
	}

	return false
}

// IsReservedIP checks if an IP is in a reserved range
func IsReservedIP(ip net.IP) bool {
	if !IsIPv4(ip) {
		return false
	}

	// Reserved ranges
	reservedRanges := []string{
		"0.0.0.0/8",          // Current network
		"127.0.0.0/8",        // Loopback
		"169.254.0.0/16",     // Link-local
		"192.0.0.0/24",       // IETF Protocol Assignments
		"192.0.2.0/24",       // TEST-NET-1
		"198.51.100.0/24",    // TEST-NET-2
		"203.0.113.0/24",     // TEST-NET-3
		"224.0.0.0/4",        // Multicast
		"240.0.0.0/4",        // Reserved for future use
		"255.255.255.255/32", // Broadcast
	}

	for _, cidr := range reservedRanges {
		_, network, _ := net.ParseCIDR(cidr)
		if network.Contains(ip) {
			return true
		}
	}

	return false
}

// SanitizeDomain removes common prefixes and suffixes from domain input
func SanitizeDomain(domain string) string {
	domain = strings.TrimSpace(domain)
	domain = strings.TrimPrefix(domain, "http://")
	domain = strings.TrimPrefix(domain, "https://")
	domain = strings.TrimPrefix(domain, "www.")
	domain = strings.TrimSuffix(domain, "/")
	return strings.ToLower(domain)
}
