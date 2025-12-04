// Package securitytrails provides SecurityTrails API integration for passive reconnaissance
package securitytrails

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// SubdomainResponse represents the JSON response from SecurityTrails subdomains API
type SubdomainResponse struct {
	Subdomains []string `json:"subdomains"`
	Meta       struct {
		LimitReached bool `json:"limit_reached"`
	} `json:"meta"`
	Message string `json:"message,omitempty"` // Error message
}

// HistoryResponse represents the JSON response from SecurityTrails history API
type HistoryResponse struct {
	Records []HistoryRecord `json:"records"`
	Pages   int             `json:"pages"`
	Message string          `json:"message,omitempty"` // Error message
}

// HistoryRecord represents a historical DNS record
type HistoryRecord struct {
	Type          string   `json:"type"`
	Values        []Value  `json:"values"`
	FirstSeen     string   `json:"first_seen"`
	LastSeen      string   `json:"last_seen"`
	Organizations []string `json:"organizations"`
}

// Value represents a DNS record value
type Value struct {
	IP              string `json:"ip"`
	IPCount         int    `json:"ip_count"`
	ASNOrganization string `json:"asn_organization"`
}

// SearchSubdomainsAndHistory queries SecurityTrails for subdomains and historical IPs
func SearchSubdomainsAndHistory(ctx context.Context, domain string, apiKeys []string, timeout time.Duration) ([]string, error) {
	if len(apiKeys) == 0 {
		return []string{}, fmt.Errorf("no SecurityTrails API keys provided")
	}

	// Try each API key until one works
	var lastErr error
	for i, apiKey := range apiKeys {
		apiKey = strings.TrimSpace(apiKey)
		if apiKey == "" {
			continue
		}

		ips, err := searchWithKey(ctx, domain, apiKey, timeout)
		if err == nil {
			return ips, nil
		}

		// Check for rate limit errors
		if strings.Contains(err.Error(), "rate limit") || strings.Contains(err.Error(), "429") {
			lastErr = fmt.Errorf("key %d/%d rate limited: %w", i+1, len(apiKeys), err)
			continue // Try next key
		}

		// For other errors, return immediately
		return []string{}, fmt.Errorf("key %d/%d failed: %w", i+1, len(apiKeys), err)
	}

	if lastErr != nil {
		return []string{}, fmt.Errorf("all %d API keys exhausted: %w", len(apiKeys), lastErr)
	}

	return []string{}, fmt.Errorf("no valid API keys found")
}

// searchWithKey performs the search with a single API key
func searchWithKey(ctx context.Context, domain, apiKey string, timeout time.Duration) ([]string, error) {
	ipSet := make(map[string]bool)

	// Step 1: Get subdomains
	subdomains, err := getSubdomains(ctx, domain, apiKey, timeout)
	if err != nil {
		return nil, fmt.Errorf("failed to get subdomains: %w", err)
	}

	// Step 2: Get historical IPs for main domain
	histIPs, err := getHistoricalIPs(ctx, domain, apiKey, timeout)
	if err != nil {
		// Non-fatal: log but continue
		// Some domains may not have history
	} else {
		for _, ip := range histIPs {
			ipSet[ip] = true
		}
	}

	// Step 3: Resolve subdomains to IPs (limit to first 50 to avoid rate limits)
	resolveCount := 0
	maxResolve := 50
	for _, subdomain := range subdomains {
		if resolveCount >= maxResolve {
			break
		}

		fullDomain := subdomain + "." + domain
		ips, err := resolveToIPv4(ctx, fullDomain, 5*time.Second)
		if err != nil {
			continue // Skip failed resolutions
		}

		for _, ip := range ips {
			ipSet[ip] = true
		}
		resolveCount++
	}

	// Convert to slice
	ips := make([]string, 0, len(ipSet))
	for ip := range ipSet {
		ips = append(ips, ip)
	}

	return ips, nil
}

// getSubdomains fetches subdomains from SecurityTrails API
func getSubdomains(ctx context.Context, domain, apiKey string, timeout time.Duration) ([]string, error) {
	url := fmt.Sprintf("https://api.securitytrails.com/v1/domain/%s/subdomains", domain)

	client := &http.Client{Timeout: timeout}

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("APIKEY", apiKey)
	req.Header.Set("User-Agent", "origindive/3.1.0")
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("SecurityTrails request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		var errResp SubdomainResponse
		if json.Unmarshal(body, &errResp) == nil && errResp.Message != "" {
			return nil, fmt.Errorf("SecurityTrails API error (HTTP %d): %s", resp.StatusCode, errResp.Message)
		}
		return nil, fmt.Errorf("SecurityTrails returned status %d", resp.StatusCode)
	}

	var subResp SubdomainResponse
	if err := json.Unmarshal(body, &subResp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	if subResp.Message != "" {
		return nil, fmt.Errorf("SecurityTrails API error: %s", subResp.Message)
	}

	return subResp.Subdomains, nil
}

// getHistoricalIPs fetches historical A records from SecurityTrails API
func getHistoricalIPs(ctx context.Context, domain, apiKey string, timeout time.Duration) ([]string, error) {
	url := fmt.Sprintf("https://api.securitytrails.com/v1/history/%s/dns/a", domain)

	client := &http.Client{Timeout: timeout}

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("APIKEY", apiKey)
	req.Header.Set("User-Agent", "origindive/3.1.0")
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("SecurityTrails request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return []string{}, nil // Non-fatal: no history available
	}

	var histResp HistoryResponse
	if err := json.Unmarshal(body, &histResp); err != nil {
		return []string{}, nil // Non-fatal: parsing error
	}

	// Extract IPs from history records
	ipSet := make(map[string]bool)
	for _, record := range histResp.Records {
		for _, value := range record.Values {
			ip := strings.TrimSpace(value.IP)
			if ip != "" {
				// Validate IPv4
				parsedIP := net.ParseIP(ip)
				if parsedIP != nil && parsedIP.To4() != nil {
					ipSet[ip] = true
				}
			}
		}
	}

	ips := make([]string, 0, len(ipSet))
	for ip := range ipSet {
		ips = append(ips, ip)
	}

	return ips, nil
}

// resolveToIPv4 resolves a domain to IPv4 addresses
func resolveToIPv4(ctx context.Context, domain string, timeout time.Duration) ([]string, error) {
	resolver := &net.Resolver{}

	ctxWithTimeout, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	addrs, err := resolver.LookupHost(ctxWithTimeout, domain)
	if err != nil {
		return nil, err
	}

	// Filter IPv4 only
	var ipv4s []string
	for _, addr := range addrs {
		ip := net.ParseIP(addr)
		if ip != nil && ip.To4() != nil {
			ipv4s = append(ipv4s, addr)
		}
	}

	return ipv4s, nil
}
