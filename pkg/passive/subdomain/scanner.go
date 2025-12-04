// Package subdomain provides subdomain enumeration for origin IP discovery
package subdomain

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"
)

// CommonSubdomains is a list of frequently used subdomains
var CommonSubdomains = []string{
	// Mail & Communication
	"mail", "smtp", "pop", "imap", "webmail", "mail2", "mx", "email",

	// Infrastructure
	"ftp", "sftp", "ssh", "vpn", "remote", "direct", "origin", "source",

	// Development
	"dev", "staging", "test", "uat", "qa", "demo", "sandbox", "preview",

	// Content & APIs
	"api", "cdn", "static", "assets", "images", "files", "media", "upload",
	"download", "backup", "storage", "fileserver", "webdav",

	// Admin & Management
	"admin", "portal", "dashboard", "panel", "control", "management", "cpanel",

	// Application
	"blog", "shop", "store", "forum", "wiki", "docs", "support", "help",
	"status", "monitor", "health", "account", "users", "auth", "login",

	// Services
	"pay", "payment", "checkout", "secure", "vault", "chat", "meet", "conference",

	// DevOps & Infrastructure
	"git", "gitlab", "github", "ci", "cd", "jenkins", "devops", "cloud",
	"k8s", "docker", "registry", "build", "deploy",

	// Legacy/Old
	"old", "legacy", "archive", "v1", "v2", "beta", "alpha",

	// Regional
	"us", "eu", "asia", "ap", "na", "sa", "au",

	// Other
	"www", "web", "app", "mobile", "m", "wap", "public", "internal",
}

// Scanner performs subdomain enumeration
type Scanner struct {
	domain     string
	workers    int
	timeout    time.Duration
	dnsServers []string
	mu         sync.Mutex
	discovered map[string][]string // subdomain -> IPs
}

// NewScanner creates a new subdomain scanner
func NewScanner(domain string, workers int, timeout time.Duration) *Scanner {
	return &Scanner{
		domain:     domain,
		workers:    workers,
		timeout:    timeout,
		dnsServers: []string{"8.8.8.8:53", "1.1.1.1:53"}, // Google, Cloudflare DNS
		discovered: make(map[string][]string),
	}
}

// Result represents a subdomain scan result
type Result struct {
	Subdomain string
	IPs       []string
	Error     error
}

// Scan performs subdomain enumeration
func (s *Scanner) Scan(ctx context.Context, subdomains []string) (map[string][]string, error) {
	if len(subdomains) == 0 {
		subdomains = CommonSubdomains
	}

	// Create work channel
	jobs := make(chan string, len(subdomains))
	results := make(chan Result, len(subdomains))

	// Start workers
	var wg sync.WaitGroup
	for i := 0; i < s.workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for subdomain := range jobs {
				select {
				case <-ctx.Done():
					return
				default:
					ips, err := s.resolveSubdomain(subdomain)
					results <- Result{
						Subdomain: subdomain,
						IPs:       ips,
						Error:     err,
					}
				}
			}
		}()
	}

	// Send jobs
	for _, subdomain := range subdomains {
		jobs <- subdomain
	}
	close(jobs)

	// Wait and close results
	go func() {
		wg.Wait()
		close(results)
	}()

	// Collect results
	for result := range results {
		if result.Error == nil && len(result.IPs) > 0 {
			s.mu.Lock()
			s.discovered[result.Subdomain] = result.IPs
			s.mu.Unlock()
		}
	}

	return s.discovered, nil
}

// resolveSubdomain resolves a subdomain to IP addresses
func (s *Scanner) resolveSubdomain(subdomain string) ([]string, error) {
	target := fmt.Sprintf("%s.%s", subdomain, s.domain)

	// Create custom resolver with timeout
	resolver := &net.Resolver{
		PreferGo: true,
	}

	ctx, cancel := context.WithTimeout(context.Background(), s.timeout)
	defer cancel()

	// Resolve A records
	ips, err := resolver.LookupHost(ctx, target)
	if err != nil {
		return nil, err
	}

	// Filter out IPv6 for now (focus on IPv4)
	var ipv4s []string
	for _, ip := range ips {
		if net.ParseIP(ip).To4() != nil {
			ipv4s = append(ipv4s, ip)
		}
	}

	return ipv4s, nil
}

// GetAllIPs returns all unique IPs from discovered subdomains
func (s *Scanner) GetAllIPs() []string {
	s.mu.Lock()
	defer s.mu.Unlock()

	seen := make(map[string]bool)
	var ips []string

	for _, subIPs := range s.discovered {
		for _, ip := range subIPs {
			if !seen[ip] {
				seen[ip] = true
				ips = append(ips, ip)
			}
		}
	}

	return ips
}

// GetResults returns the full subdomain -> IPs mapping
func (s *Scanner) GetResults() map[string][]string {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Return a copy to avoid concurrent access issues
	results := make(map[string][]string)
	for k, v := range s.discovered {
		results[k] = append([]string{}, v...)
	}

	return results
}
