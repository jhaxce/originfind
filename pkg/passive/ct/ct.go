// Package ct provides Certificate Transparency log searching
package ct

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

// CTEntry represents a certificate transparency log entry
type CTEntry struct {
	IssuerCAID     int    `json:"issuer_ca_id"`
	IssuerName     string `json:"issuer_name"`
	CommonName     string `json:"common_name"`
	NameValue      string `json:"name_value"`
	ID             int64  `json:"id"`
	EntryTimestamp string `json:"entry_timestamp"`
	NotBefore      string `json:"not_before"`
	NotAfter       string `json:"not_after"`
}

// SearchCrtSh queries crt.sh for certificates matching the domain
func SearchCrtSh(ctx context.Context, domain string, timeout time.Duration) ([]string, error) {
	// Use JSON API endpoint (not HTML)
	url := fmt.Sprintf("https://crt.sh/json?q=%s", domain)

	ips, err := searchCrtShURL(ctx, url, domain, timeout)
	if err != nil {
		// Check if crt.sh is down (502/503/504)
		if strings.Contains(err.Error(), "502") || strings.Contains(err.Error(), "503") || strings.Contains(err.Error(), "504") {
			return []string{}, fmt.Errorf("crt.sh appears to be down (gateway error). Please try again later: %w", err)
		}
		return []string{}, err
	}

	return ips, nil
}

// searchCrtShURL performs the actual HTTP request and parsing
func searchCrtShURL(ctx context.Context, url, domain string, timeout time.Duration) ([]string, error) {
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
		return nil, fmt.Errorf("crt.sh request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		// Read error body but don't include HTML content in error message
		body, _ := io.ReadAll(resp.Body)
		bodyStr := string(body)

		// If it's HTML (starts with <), give a clean error message
		if strings.HasPrefix(strings.TrimSpace(bodyStr), "<") {
			return nil, fmt.Errorf("crt.sh returned status %d (gateway error - service may be down)", resp.StatusCode)
		}

		// For non-HTML errors, include truncated message
		if len(bodyStr) > 200 {
			bodyStr = bodyStr[:200] + "..."
		}
		return nil, fmt.Errorf("crt.sh returned status %d: %s", resp.StatusCode, strings.TrimSpace(bodyStr))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	var entries []CTEntry
	if err := json.Unmarshal(body, &entries); err != nil {
		return nil, fmt.Errorf("failed to parse CT logs: %w", err)
	}

	// Extract unique subdomains
	subdomainSet := make(map[string]bool)
	for _, entry := range entries {
		// Parse name_value field which contains SANs (Subject Alternative Names)
		names := strings.Split(entry.NameValue, "\n")
		for _, name := range names {
			name = strings.TrimSpace(strings.ToLower(name))
			// Skip wildcards and add valid subdomains
			if name != "" && !strings.HasPrefix(name, "*") && strings.HasSuffix(name, domain) {
				subdomainSet[name] = true
			}
		}
	}

	// Convert to slice
	subdomains := make([]string, 0, len(subdomainSet))
	for subdomain := range subdomainSet {
		subdomains = append(subdomains, subdomain)
	}

	// Resolve subdomains to IPs
	return resolveSubdomainsToIPs(ctx, subdomains, timeout)
}

// resolveSubdomainsToIPs resolves a list of subdomains to their IP addresses
func resolveSubdomainsToIPs(ctx context.Context, subdomains []string, timeout time.Duration) ([]string, error) {
	ipSet := make(map[string]bool)
	resolver := &net.Resolver{}

	for _, subdomain := range subdomains {
		// Create context with timeout for each lookup
		lookupCtx, cancel := context.WithTimeout(ctx, timeout)

		ips, err := resolver.LookupIP(lookupCtx, "ip4", subdomain)
		cancel()

		if err != nil {
			continue // Skip failed resolutions
		}

		for _, ip := range ips {
			if ip.To4() != nil {
				ipSet[ip.String()] = true
			}
		}
	}

	// Convert to slice
	result := make([]string, 0, len(ipSet))
	for ip := range ipSet {
		result = append(result, ip)
	}

	return result, nil
}
