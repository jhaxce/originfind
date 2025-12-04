// Package api provides API client validation and failover for passive sources
package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// ShodanValidator validates Shodan API key
func ShodanValidator(apiKey string) func(context.Context) error {
	return func(ctx context.Context) error {
		if apiKey == "" {
			return fmt.Errorf("shodan API key not configured")
		}

		// Test API key with account info endpoint
		url := fmt.Sprintf("https://api.shodan.io/account/profile?key=%s", apiKey)

		req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
		if err != nil {
			return fmt.Errorf("failed to create request: %w", err)
		}

		client := &http.Client{Timeout: 10 * time.Second}
		resp, err := client.Do(req)
		if err != nil {
			return fmt.Errorf("shodan API request failed: %w", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode == 401 {
			return fmt.Errorf("shodan API key is invalid")
		}
		if resp.StatusCode == 429 {
			return fmt.Errorf("shodan rate limit exceeded")
		}
		if resp.StatusCode != 200 {
			return fmt.Errorf("shodan API returned status %d", resp.StatusCode)
		}

		return nil
	}
}

// CensysValidator validates Censys API credentials
func CensysValidator(apiID, apiSecret string) func(context.Context) error {
	return func(ctx context.Context) error {
		if apiID == "" || apiSecret == "" {
			return fmt.Errorf("censys API credentials not configured")
		}

		// Test credentials with account endpoint
		url := "https://search.censys.io/api/v2/account"

		req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
		if err != nil {
			return fmt.Errorf("failed to create request: %w", err)
		}

		req.SetBasicAuth(apiID, apiSecret)
		req.Header.Set("Accept", "application/json")

		client := &http.Client{Timeout: 10 * time.Second}
		resp, err := client.Do(req)
		if err != nil {
			return fmt.Errorf("censys API request failed: %w", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode == 401 || resp.StatusCode == 403 {
			return fmt.Errorf("censys API credentials are invalid")
		}
		if resp.StatusCode == 429 {
			return fmt.Errorf("censys rate limit exceeded")
		}
		if resp.StatusCode != 200 {
			return fmt.Errorf("censys API returned status %d", resp.StatusCode)
		}

		return nil
	}
}

// CTValidator validates Certificate Transparency access (no API key needed)
func CTValidator() func(context.Context) error {
	return func(ctx context.Context) error {
		// Test crt.sh availability
		url := "https://crt.sh/?output=json&q=example.com"

		req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
		if err != nil {
			return fmt.Errorf("failed to create request: %w", err)
		}

		client := &http.Client{Timeout: 10 * time.Second}
		resp, err := client.Do(req)
		if err != nil {
			return fmt.Errorf("certificate transparency service unavailable: %w", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode == 429 {
			return fmt.Errorf("certificate transparency rate limit exceeded")
		}
		if resp.StatusCode != 200 {
			return fmt.Errorf("certificate transparency returned status %d", resp.StatusCode)
		}

		// Check if response is valid JSON
		var result []map[string]interface{}
		if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
			return fmt.Errorf("certificate transparency returned invalid response: %w", err)
		}

		return nil
	}
}

// DNSValidator validates DNS resolution capability (no API key needed)
func DNSValidator() func(context.Context) error {
	return func(ctx context.Context) error {
		// DNS is always available unless there's a network issue
		// We could test a DNS query here, but that's usually not necessary
		return nil
	}
}

// GetValidator returns the appropriate validator for a source
func GetValidator(source Source, shodanKey, censysID, censysSecret string) func(context.Context) error {
	switch source {
	case SourceShodan:
		return ShodanValidator(shodanKey)
	case SourceCensys:
		return CensysValidator(censysID, censysSecret)
	case SourceCT:
		return CTValidator()
	case SourceDNS:
		return DNSValidator()
	default:
		return func(ctx context.Context) error {
			return fmt.Errorf("unknown source: %s", source)
		}
	}
}
