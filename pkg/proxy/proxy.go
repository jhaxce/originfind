// Package proxy provides HTTP/SOCKS5 proxy support with automatic proxy list fetching
package proxy

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/net/proxy"
)

// ProxyType represents the proxy protocol
type ProxyType string

const (
	ProxyTypeHTTP   ProxyType = "http"
	ProxyTypeHTTPS  ProxyType = "https"
	ProxyTypeSOCKS5 ProxyType = "socks5"
)

// Proxy represents a proxy server
type Proxy struct {
	URL      string // Full proxy URL (e.g., http://1.2.3.4:8080, socks5://5.6.7.8:1080)
	Type     ProxyType
	Host     string
	Port     string
	Username string
	Password string
}

// DetectCountryCode detects the user's country from Cloudflare CDN trace
func DetectCountryCode() string {
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get("https://cloudflare.com/cdn-cgi/trace")
	if err != nil {
		return "all" // Fallback to all countries
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "all"
	}

	// Parse loc=XX from trace
	for _, line := range strings.Split(string(body), "\n") {
		if strings.HasPrefix(line, "loc=") {
			country := strings.ToLower(strings.TrimPrefix(line, "loc="))
			if len(country) == 2 {
				return country
			}
		}
	}

	return "all" // Fallback
}

// PublicProxySource represents sources for free proxy listsected country
// Sources are checked in priority order with automatic failover
func GetPublicProxySources() []string {
	country := DetectCountryCode()
	fmt.Printf("[*] Detected country: %s\n", strings.ToUpper(country))

	// Convert country code to uppercase for GeoNode (requires uppercase)
	countryUpper := strings.ToUpper(country)
	if countryUpper == "ALL" {
		countryUpper = "" // GeoNode: empty = all countries
	}

	// Build GeoNode URL with country filter
	geoNodeURL := "https://proxylist.geonode.com/api/proxy-list?filterUpTime=90&limit=500&page=1&sort_by=lastChecked&sort_type=desc&protocols=http%2Chttps"
	if countryUpper != "" {
		geoNodeURL = fmt.Sprintf("https://proxylist.geonode.com/api/proxy-list?country=%s&filterUpTime=90&limit=500&page=1&sort_by=lastChecked&sort_type=desc&protocols=http%%2Chttps", countryUpper)
	}

	return []string{
		// ProxyScrape API v4 - Country-specific, fast timeout filter
		// Format: {"proxies": [{"proxy": "http://ip:port", "protocol": "http"}]}
		// timeout=1000ms filter for faster proxies only
		fmt.Sprintf("https://api.proxyscrape.com/v4/free-proxy-list/get?request=display_proxies&country=%s&proxy_format=protocolipport&format=json&timeout=1000", country),

		// GeoNode API - Country-specific, high uptime (90%), sorted by last checked
		// Format: {"data": [{"ip": "...", "port": "80", "protocols": ["http"]}]}
		// filterUpTime=90 ensures only reliable proxies (90%+ uptime)
		geoNodeURL,
	}
}

// ParseProxy parses a proxy URL string into a Proxy struct
func ParseProxy(proxyURL string) (*Proxy, error) {
	if proxyURL == "" {
		return nil, fmt.Errorf("proxy URL cannot be empty")
	}

	// Add scheme if missing
	if !strings.Contains(proxyURL, "://") {
		proxyURL = "http://" + proxyURL
	}

	u, err := url.Parse(proxyURL)
	if err != nil {
		return nil, fmt.Errorf("invalid proxy URL: %w", err)
	}

	host, port, err := net.SplitHostPort(u.Host)
	if err != nil {
		// No port specified, use default
		host = u.Host
		switch u.Scheme {
		case "http", "https":
			port = "8080"
		case "socks4", "socks5":
			port = "1080"
		default:
			return nil, fmt.Errorf("unknown proxy scheme: %s", u.Scheme)
		}
	}

	p := &Proxy{
		URL:  proxyURL,
		Type: ProxyType(u.Scheme),
		Host: host,
		Port: port,
	}

	if u.User != nil {
		p.Username = u.User.Username()
		p.Password, _ = u.User.Password()
	}

	return p, nil
}

// GetHTTPClient returns an *http.Client configured to use the proxy
func (p *Proxy) GetHTTPClient(timeout time.Duration) (*http.Client, error) {
	var transport *http.Transport

	switch p.Type {
	case ProxyTypeHTTP, ProxyTypeHTTPS:
		proxyURL, err := url.Parse(p.URL)
		if err != nil {
			return nil, fmt.Errorf("failed to parse proxy URL: %w", err)
		}

		transport = &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
			DialContext: (&net.Dialer{
				Timeout: timeout,
			}).DialContext,
		}

	case ProxyTypeSOCKS5:
		// SOCKS5 proxy using golang.org/x/net/proxy
		var auth *proxy.Auth
		if p.Username != "" {
			auth = &proxy.Auth{
				User:     p.Username,
				Password: p.Password,
			}
		}

		dialer, err := proxy.SOCKS5("tcp", net.JoinHostPort(p.Host, p.Port), auth, proxy.Direct)
		if err != nil {
			return nil, fmt.Errorf("failed to create SOCKS5 dialer: %w", err)
		}

		transport = &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return dialer.Dial(network, addr)
			},
		}

	case "socks4": // SOCKS4 support (treat as SOCKS5 without auth)
		// Note: SOCKS4 doesn't support authentication
		dialer, err := proxy.SOCKS5("tcp", net.JoinHostPort(p.Host, p.Port), nil, proxy.Direct)
		if err != nil {
			return nil, fmt.Errorf("failed to create SOCKS4 dialer: %w", err)
		}

		transport = &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return dialer.Dial(network, addr)
			},
		}

	default:
		return nil, fmt.Errorf("unsupported proxy type: %s", p.Type)
	}

	return &http.Client{
		Transport: transport,
		Timeout:   timeout,
	}, nil
}

// IPCheckEndpoints are reliable services that return your public IP address
// Ordered by reliability, with automatic fallback support
// Used for validating ALL proxies (free public, Webshare premium, etc.)
var IPCheckEndpoints = []string{
	"https://api.ipify.org/",               // Simple, fast, plain IP response
	"https://checkip.amazonaws.com/",       // AWS CloudFront, highly reliable
	"https://icanhazip.com/",               // Classic, plain IP response
	"https://ipv4.webshare.io/",            // Webshare.io test endpoint
	"http://checkip.dyndns.org/",           // Legacy but working (HTML response)
	"https://cloudflare.com/cdn-cgi/trace", // Cloudflare trace (multi-field response)
}

// ValidateProxy tests a proxy by trying to fetch IP from check endpoints
// Returns the detected IP address and any error
// Used for ALL proxy types (public free proxies, Webshare premium, etc.)
func ValidateProxy(proxyURL string, timeout time.Duration) (string, error) {
	proxy, err := ParseProxy(proxyURL)
	if err != nil {
		return "", fmt.Errorf("invalid proxy URL: %w", err)
	}

	client, err := proxy.GetHTTPClient(timeout)
	if err != nil {
		return "", err
	}

	// Try each endpoint until one succeeds
	var lastErr error
	for _, endpoint := range IPCheckEndpoints {
		resp, err := client.Get(endpoint)
		if err != nil {
			lastErr = err
			continue
		}

		if resp.StatusCode != 200 {
			resp.Body.Close()
			lastErr = fmt.Errorf("endpoint returned status %d", resp.StatusCode)
			continue
		}

		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			lastErr = err
			continue
		}

		// Extract IP from response
		ip := extractIP(string(body))
		if ip != "" {
			return ip, nil
		}

		lastErr = fmt.Errorf("no IP found in response")
	}

	if lastErr != nil {
		return "", fmt.Errorf("all endpoints failed: %w", lastErr)
	}
	return "", fmt.Errorf("no working endpoints")
}

// extractIP extracts an IP address from various response formats
func extractIP(response string) string {
	response = strings.TrimSpace(response)

	// Plain IP response (api.ipify.org, checkip.amazonaws.com, icanhazip.com)
	if isValidIP(response) {
		return response
	}

	// HTML response from checkip.dyndns.org
	// Format: <html><head><title>Current IP Check</title></head><body>Current IP Address: 1.2.3.4</body></html>
	if strings.Contains(response, "Current IP Address:") {
		parts := strings.Split(response, "Current IP Address:")
		if len(parts) > 1 {
			ip := strings.TrimSpace(strings.Split(parts[1], "<")[0])
			if isValidIP(ip) {
				return ip
			}
		}
	}

	// Cloudflare trace format
	// Format: fl=975f69\nh=cloudflare.com\nip=1.2.3.4\nts=1764856572.267\n...
	if strings.Contains(response, "ip=") {
		for _, line := range strings.Split(response, "\n") {
			if strings.HasPrefix(line, "ip=") {
				ip := strings.TrimPrefix(line, "ip=")
				if isValidIP(ip) {
					return ip
				}
			}
		}
	}

	return ""
}

// isValidIP checks if a string is a valid IPv4 address
func isValidIP(s string) bool {
	ip := net.ParseIP(s)
	return ip != nil && ip.To4() != nil
}

// TestProxy tests if the proxy is working by making a request to test endpoints
// Uses multiple fallback endpoints for reliability
func (p *Proxy) TestProxy(timeout time.Duration) error {
	_, err := ValidateProxy(p.URL, timeout)
	return err
}

// FetchProxyList fetches a list of proxies from public sources
func FetchProxyList(ctx context.Context, sources []string, webshareConfig *WebshareConfig) ([]*Proxy, error) {
	if len(sources) == 0 {
		sources = GetPublicProxySources()
	}

	var allProxies []*Proxy
	var webshareProxies []*Proxy
	client := &http.Client{Timeout: 10 * time.Second}

	// Fetch from Webshare.io if configured
	if webshareConfig != nil && webshareConfig.APIKey != "" {
		proxies, err := FetchWebshareProxies(ctx, webshareConfig)
		if err == nil && len(proxies) > 0 {
			webshareProxies = proxies
			allProxies = append(allProxies, proxies...)
			fmt.Printf("[+] Fetched %d proxies from Webshare.io (premium)\n", len(proxies))
		} else if err != nil {
			fmt.Printf("[!] Webshare.io fetch failed: %v\n", err)
		}
		// Continue even if Webshare fails, fall back to public sources
	}

	var failedSources []string
	for _, source := range sources {
		proxies, err := fetchFromSource(ctx, client, source)
		if err != nil {
			// Log error but continue with other sources
			failedSources = append(failedSources, source)
			if len(sources) <= 3 {
				// Show detailed error for small source lists
				fmt.Printf("[!] Failed to fetch from %s: %v\n", source, err)
			}
			continue
		}
		allProxies = append(allProxies, proxies...)
	}

	// Warn if some sources failed but we got proxies from others
	if len(failedSources) > 0 && len(allProxies) > 0 {
		fmt.Printf("[!] Warning: %d/%d proxy sources failed (continuing with %d proxies)\n",
			len(failedSources), len(sources), len(allProxies))
	}

	if len(allProxies) == 0 {
		return nil, fmt.Errorf("no proxies fetched from any source (tried %d sources)", len(sources))
	}

	// IMPORTANT: Return Webshare proxies first (if any) so they're prioritized in sampling
	// This prevents premium proxies from getting lost in thousands of free ones
	if len(webshareProxies) > 0 {
		// Put Webshare at the front of the list
		result := make([]*Proxy, 0, len(allProxies))
		result = append(result, webshareProxies...)
		// Add non-Webshare proxies after
		for _, p := range allProxies {
			isWebshare := false
			for _, wp := range webshareProxies {
				if p.URL == wp.URL {
					isWebshare = true
					break
				}
			}
			if !isWebshare {
				result = append(result, p)
			}
		}
		return result, nil
	}

	return allProxies, nil
}

// fetchFromSource fetches proxies from a single source
func fetchFromSource(ctx context.Context, client *http.Client, source string) ([]*Proxy, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", source, nil)
	if err != nil {
		return nil, err
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("source returned status %d", resp.StatusCode)
	}

	return parseProxyList(resp.Body)
}

// ProxyScrapeResponse represents the JSON response from ProxyScrape API v4
type ProxyScrapeResponse struct {
	Proxies []struct {
		Proxy string `json:"proxy"`
	} `json:"proxies"`
}

// GeoNodeResponse represents the JSON response from GeoNode API
type GeoNodeResponse struct {
	Data []struct {
		IP        string   `json:"ip"`
		Port      string   `json:"port"`
		Protocols []string `json:"protocols"`
	} `json:"data"`
}

// parseProxyList parses proxy list from reader (JSON or text format)
func parseProxyList(r io.Reader) ([]*Proxy, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}

	// Try ProxyScrape JSON format first
	var proxyScrape ProxyScrapeResponse
	if err := json.Unmarshal(data, &proxyScrape); err == nil && len(proxyScrape.Proxies) > 0 {
		var proxies []*Proxy
		for _, p := range proxyScrape.Proxies {
			if proxy, err := ParseProxy(p.Proxy); err == nil {
				proxies = append(proxies, proxy)
			}
		}
		if len(proxies) > 0 {
			return proxies, nil
		}
	}

	// Try GeoNode JSON format
	var geoNode GeoNodeResponse
	if err := json.Unmarshal(data, &geoNode); err == nil && len(geoNode.Data) > 0 {
		var proxies []*Proxy
		for _, p := range geoNode.Data {
			if len(p.Protocols) > 0 {
				// Use first protocol
				proxyURL := fmt.Sprintf("%s://%s:%s", p.Protocols[0], p.IP, p.Port)
				if proxy, err := ParseProxy(proxyURL); err == nil {
					proxies = append(proxies, proxy)
				}
			}
		}
		if len(proxies) > 0 {
			return proxies, nil
		}
	}

	// Fallback to plain text format (one proxy per line)
	var proxies []*Proxy
	scanner := bufio.NewScanner(strings.NewReader(string(data)))

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Try to parse as proxy (format: IP:PORT or protocol://IP:PORT)
		proxy, err := ParseProxy(line)
		if err != nil {
			continue // Skip invalid entries
		}

		proxies = append(proxies, proxy)
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return proxies, nil
}

// GetRandomProxy returns a random proxy from the list
func GetRandomProxy(proxies []*Proxy) *Proxy {
	if len(proxies) == 0 {
		return nil
	}
	return proxies[rand.Intn(len(proxies))]
}

// ValidateProxies tests a list of proxies and returns only working ones
func ValidateProxies(ctx context.Context, proxies []*Proxy, timeout time.Duration, maxWorkers int) []*Proxy {
	if maxWorkers == 0 {
		maxWorkers = 10
	}

	jobs := make(chan *Proxy, len(proxies))
	results := make(chan *Proxy, len(proxies))

	// Worker pool for testing proxies
	for i := 0; i < maxWorkers; i++ {
		go func() {
			for proxy := range jobs {
				select {
				case <-ctx.Done():
					return
				default:
					if err := proxy.TestProxy(timeout); err == nil {
						results <- proxy
					}
				}
			}
		}()
	}

	// Send jobs
	for _, proxy := range proxies {
		jobs <- proxy
	}
	close(jobs)

	// Collect results (with timeout)
	var validated []*Proxy
	validationTimeout := time.After(60 * time.Second) // Increased from 30s

	// Collect results with adaptive timeout
collectLoop:
	for i := 0; i < len(proxies); i++ {
		select {
		case proxy := <-results:
			validated = append(validated, proxy)
			// Early exit if we have enough working proxies (>100)
			if len(validated) >= 100 && i > len(proxies)/2 {
				break collectLoop
			}
		case <-validationTimeout:
			break collectLoop
		case <-ctx.Done():
			break collectLoop
		}
	}

	return validated
}
