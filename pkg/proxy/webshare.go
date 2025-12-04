// Package proxy - Webshare.io premium proxy integration
package proxy

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// WebshareConfig represents Webshare.io API configuration
type WebshareConfig struct {
	APIKey string // API key for authentication
	PlanID string // Plan ID (optional, for download endpoint)
}

// WebshareProxy represents a proxy from Webshare.io API
type WebshareProxy struct {
	ID               string    `json:"id"`
	Username         string    `json:"username"`
	Password         string    `json:"password"`
	ProxyAddress     string    `json:"proxy_address"`
	Port             int       `json:"port"`
	Valid            bool      `json:"valid"`
	LastVerification string    `json:"last_verification"`
	CountryCode      string    `json:"country_code"`
	CityName         string    `json:"city_name"`
	CreatedAt        time.Time `json:"created_at"`
}

// WebshareResponse represents the API response structure
type WebshareResponse struct {
	Count    int             `json:"count"`
	Next     string          `json:"next"`
	Previous string          `json:"previous"`
	Results  []WebshareProxy `json:"results"`
}

// WebshareProfile represents user profile information
type WebshareProfile struct {
	ID                  int       `json:"id"`
	Email               string    `json:"email"`
	BandwidthGB         float64   `json:"bandwidth_gb"`
	BandwidthGBUsed     float64   `json:"bandwidth_gb_used"`
	ProxyCount          int       `json:"proxy_count"`
	SubscriptionEndDate string    `json:"subscription_end_date"`
	CreatedAt           time.Time `json:"created_at"`
}

// FetchWebshareProxies fetches proxies from Webshare.io API
func FetchWebshareProxies(ctx context.Context, config *WebshareConfig) ([]*Proxy, error) {
	if config == nil || config.APIKey == "" {
		return nil, fmt.Errorf("webshare API key is required")
	}

	client := &http.Client{Timeout: 30 * time.Second}
	url := "https://proxy.webshare.io/api/v2/proxy/list/?mode=direct&page=1&page_size=100"

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Set authorization header
	req.Header.Set("Authorization", fmt.Sprintf("Token %s", config.APIKey))

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("API request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("API returned status %d: %s", resp.StatusCode, string(body))
	}

	var wsResp WebshareResponse
	if err := json.NewDecoder(resp.Body).Decode(&wsResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	// Convert Webshare proxies to our Proxy format
	proxies := make([]*Proxy, 0, len(wsResp.Results))
	for _, wsProxy := range wsResp.Results {
		if !wsProxy.Valid {
			continue // Skip invalid proxies
		}

		// Format: http://username:password@host:port
		proxyURL := fmt.Sprintf("http://%s:%s@%s:%d",
			wsProxy.Username,
			wsProxy.Password,
			wsProxy.ProxyAddress,
			wsProxy.Port,
		)

		proxy, err := ParseProxy(proxyURL)
		if err != nil {
			continue // Skip invalid entries
		}

		proxies = append(proxies, proxy)
	}

	if len(proxies) == 0 {
		return nil, fmt.Errorf("no valid proxies found in Webshare response")
	}

	return proxies, nil
}

// FetchWebshareProxiesFromDownload fetches proxies from the download endpoint
// This endpoint provides a pre-formatted list without authentication info in response
func FetchWebshareProxiesFromDownload(ctx context.Context, downloadURL string) ([]*Proxy, error) {
	if downloadURL == "" {
		return nil, fmt.Errorf("download URL is required")
	}

	// Example URL format:
	// https://proxy.webshare.io/api/v2/proxy/list/download/{token}/-/any/username/direct/-/

	client := &http.Client{Timeout: 30 * time.Second}

	req, err := http.NewRequestWithContext(ctx, "GET", downloadURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("download request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("download returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	// Parse line-by-line (format: username:password@host:port)
	lines := strings.Split(string(body), "\n")
	proxies := make([]*Proxy, 0, len(lines))

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// Add protocol if missing
		if !strings.HasPrefix(line, "http://") && !strings.HasPrefix(line, "socks5://") {
			line = "http://" + line
		}

		proxy, err := ParseProxy(line)
		if err != nil {
			continue // Skip invalid entries
		}

		proxies = append(proxies, proxy)
	}

	return proxies, nil
}

// GetWebshareProfile fetches user profile information
func GetWebshareProfile(ctx context.Context, apiKey string) (*WebshareProfile, error) {
	if apiKey == "" {
		return nil, fmt.Errorf("API key is required")
	}

	client := &http.Client{Timeout: 10 * time.Second}
	url := "https://proxy.webshare.io/api/v2/profile/"

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", fmt.Sprintf("Token %s", apiKey))

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("profile request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("API returned status %d: %s", resp.StatusCode, string(body))
	}

	var profile WebshareProfile
	if err := json.NewDecoder(resp.Body).Decode(&profile); err != nil {
		return nil, fmt.Errorf("failed to decode profile: %w", err)
	}

	return &profile, nil
}

// TestWebshareProxy tests a Webshare proxy
// Uses the general ValidateProxy function from proxy.go
func TestWebshareProxy(proxyURL string, timeout time.Duration) error {
	_, err := ValidateProxy(proxyURL, timeout)
	return err
}
