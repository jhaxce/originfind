// Package shodan provides Shodan API integration for passive reconnaissance
package shodan

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

// ShodanResponse represents the JSON response from Shodan API
type ShodanResponse struct {
	Total   int           `json:"total"`
	Matches []ShodanMatch `json:"matches"`
	Error   string        `json:"error,omitempty"`
}

// ShodanMatch represents a single host result
type ShodanMatch struct {
	IPStr     string   `json:"ip_str"`
	Hostnames []string `json:"hostnames"`
	Domains   []string `json:"domains"`
	Port      int      `json:"port"`
	Transport string   `json:"transport"`
}

// SearchHostname queries Shodan for hosts matching the domain using hostname filter
func SearchHostname(ctx context.Context, domain string, apiKeys []string, timeout time.Duration) ([]string, error) {
	if len(apiKeys) == 0 {
		return []string{}, fmt.Errorf("no Shodan API keys provided")
	}

	// Try each API key until one works (rotation for rate limits)
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

		// For other errors, return immediately (invalid key, network issue, etc.)
		return []string{}, fmt.Errorf("key %d/%d failed: %w", i+1, len(apiKeys), err)
	}

	if lastErr != nil {
		return []string{}, fmt.Errorf("all %d API keys exhausted: %w", len(apiKeys), lastErr)
	}

	return []string{}, fmt.Errorf("no valid API keys found")
}

// searchWithKey performs the search with a single API key
func searchWithKey(ctx context.Context, domain, apiKey string, timeout time.Duration) ([]string, error) {
	// Build query: hostname:domain.com
	query := fmt.Sprintf("hostname:%s", domain)
	url := fmt.Sprintf("https://api.shodan.io/shodan/host/search?query=%s&key=%s", query, apiKey)

	client := &http.Client{
		Timeout: timeout,
	}

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("User-Agent", "origindive/1.0")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("Shodan request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	// Check for HTTP errors
	if resp.StatusCode != http.StatusOK {
		// Try to parse error message from JSON
		var errResp ShodanResponse
		if json.Unmarshal(body, &errResp) == nil && errResp.Error != "" {
			return nil, fmt.Errorf("Shodan API error (HTTP %d): %s", resp.StatusCode, errResp.Error)
		}
		return nil, fmt.Errorf("Shodan returned status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	// Parse successful response
	var shodanResp ShodanResponse
	if err := json.Unmarshal(body, &shodanResp); err != nil {
		return nil, fmt.Errorf("failed to parse Shodan response: %w", err)
	}

	// Check for API error in JSON (even with 200 OK)
	if shodanResp.Error != "" {
		return nil, fmt.Errorf("Shodan API error: %s", shodanResp.Error)
	}

	// Extract unique IPv4 addresses
	ipSet := make(map[string]bool)
	for _, match := range shodanResp.Matches {
		ip := strings.TrimSpace(match.IPStr)
		if ip == "" {
			continue
		}

		// Validate and filter IPv4 only
		parsedIP := net.ParseIP(ip)
		if parsedIP == nil {
			continue
		}

		// Check if IPv4 (To4() returns nil for IPv6)
		if parsedIP.To4() != nil {
			ipSet[ip] = true
		}
	}

	// Convert to slice
	ips := make([]string, 0, len(ipSet))
	for ip := range ipSet {
		ips = append(ips, ip)
	}

	return ips, nil
}
