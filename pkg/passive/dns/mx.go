// Package dns provides DNS-based origin IP discovery
package dns

import (
	"context"
	"fmt"
	"net"
	"time"
)

// MXRecord represents an MX record with resolved IPs
type MXRecord struct {
	Host     string
	Priority uint16
	IPs      []string
}

// LookupMX queries MX records and resolves them to IPs
func LookupMX(ctx context.Context, domain string, timeout time.Duration) ([]MXRecord, error) {
	resolver := &net.Resolver{
		PreferGo: true,
	}

	mxCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// Lookup MX records
	mxRecords, err := resolver.LookupMX(mxCtx, domain)
	if err != nil {
		return nil, fmt.Errorf("MX lookup failed: %w", err)
	}

	if len(mxRecords) == 0 {
		return nil, fmt.Errorf("no MX records found")
	}

	// Resolve each MX host to IPs
	var results []MXRecord
	for _, mx := range mxRecords {
		ips, err := resolveHost(ctx, mx.Host, timeout)
		if err != nil {
			// Continue even if one MX fails
			continue
		}

		results = append(results, MXRecord{
			Host:     mx.Host,
			Priority: mx.Pref,
			IPs:      ips,
		})
	}

	return results, nil
}

// resolveHost resolves a hostname to IPv4 addresses
func resolveHost(ctx context.Context, host string, timeout time.Duration) ([]string, error) {
	resolver := &net.Resolver{
		PreferGo: true,
	}

	hostCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	ips, err := resolver.LookupHost(hostCtx, host)
	if err != nil {
		return nil, err
	}

	// Filter IPv4 only
	var ipv4s []string
	for _, ip := range ips {
		if net.ParseIP(ip).To4() != nil {
			ipv4s = append(ipv4s, ip)
		}
	}

	return ipv4s, nil
}

// GetAllMXIPs extracts all unique IPs from MX records
func GetAllMXIPs(mxRecords []MXRecord) []string {
	seen := make(map[string]bool)
	var ips []string

	for _, mx := range mxRecords {
		for _, ip := range mx.IPs {
			if !seen[ip] {
				seen[ip] = true
				ips = append(ips, ip)
			}
		}
	}

	return ips
}
