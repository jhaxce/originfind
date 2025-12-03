// Package waf provides IP range management and parsing
package waf

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"
)

// IPRange represents a parsed IP range for efficient lookup
type IPRange struct {
	Network  *net.IPNet
	Provider string
	CIDR     string
}

// RangeSet represents a collection of IP ranges for efficient lookup
type RangeSet struct {
	ranges    []IPRange
	providers map[string]bool // Set of active provider IDs
}

// NewRangeSet creates a new empty range set
func NewRangeSet() *RangeSet {
	return &RangeSet{
		ranges:    make([]IPRange, 0),
		providers: make(map[string]bool),
	}
}

// AddProvider adds all ranges from a provider to the set
func (rs *RangeSet) AddProvider(provider *Provider) error {
	if provider == nil {
		return fmt.Errorf("provider is nil")
	}

	for _, cidr := range provider.Ranges {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			return fmt.Errorf("invalid CIDR %s for provider %s: %w", cidr, provider.ID, err)
		}

		rs.ranges = append(rs.ranges, IPRange{
			Network:  network,
			Provider: provider.ID,
			CIDR:     cidr,
		})
	}

	rs.providers[provider.ID] = true
	return nil
}

// AddProviders adds multiple providers to the range set
func (rs *RangeSet) AddProviders(providers []*Provider) error {
	for _, p := range providers {
		if err := rs.AddProvider(p); err != nil {
			return err
		}
	}
	return nil
}

// Contains checks if an IP is in any of the ranges
func (rs *RangeSet) Contains(ip net.IP) bool {
	_, _ = rs.FindProvider(ip)
	return rs.providers != nil
}

// FindProvider returns the provider ID if the IP is in a WAF range
// Returns (providerID, found)
func (rs *RangeSet) FindProvider(ip net.IP) (string, bool) {
	for _, r := range rs.ranges {
		if r.Network.Contains(ip) {
			return r.Provider, true
		}
	}
	return "", false
}

// Count returns the number of ranges in the set
func (rs *RangeSet) Count() int {
	return len(rs.ranges)
}

// Providers returns a list of provider IDs in the set
func (rs *RangeSet) Providers() []string {
	ids := make([]string, 0, len(rs.providers))
	for id := range rs.providers {
		ids = append(ids, id)
	}
	return ids
}

// LoadFromDatabase loads ranges from a database for specific provider IDs
func LoadFromDatabase(db *WAFDatabase, providerIDs []string) (*RangeSet, error) {
	rs := NewRangeSet()

	if len(providerIDs) == 0 {
		// Load all providers
		for i := range db.Providers {
			if err := rs.AddProvider(&db.Providers[i]); err != nil {
				return nil, err
			}
		}
	} else {
		// Load specific providers
		for _, id := range providerIDs {
			provider := db.GetProvider(id)
			if provider == nil {
				return nil, fmt.Errorf("provider not found: %s", id)
			}
			if err := rs.AddProvider(provider); err != nil {
				return nil, err
			}
		}
	}

	return rs, nil
}

// LoadCustomRanges loads custom CIDR ranges from a file
// Supports two formats:
//  1. JSON format (same as waf_ranges.json):
//     {"providers": [{"id": "custom", "name": "Custom", "ranges": ["1.2.3.0/24"]}]}
//  2. Plain text format (one CIDR per line, comments with #)
func LoadCustomRanges(filepath string) (*RangeSet, error) {
	data, err := os.ReadFile(filepath)
	if err != nil {
		return nil, fmt.Errorf("failed to read custom ranges file: %w", err)
	}

	rs := NewRangeSet()

	// Try to parse as JSON first
	if strings.TrimSpace(string(data))[0] == '{' {
		var db WAFDatabase
		if err := json.Unmarshal(data, &db); err != nil {
			return nil, fmt.Errorf("failed to parse JSON: %w", err)
		}

		// Add all providers from custom file
		for i := range db.Providers {
			if err := rs.AddProvider(&db.Providers[i]); err != nil {
				return nil, err
			}
		}

		return rs, nil
	}

	// Parse as plain text (one CIDR per line)
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	lineNum := 0
	customProvider := &Provider{
		ID:     "custom",
		Name:   "Custom WAF Ranges",
		Ranges: make([]string, 0),
	}

	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Validate CIDR
		_, _, err := net.ParseCIDR(line)
		if err != nil {
			return nil, fmt.Errorf("line %d: invalid CIDR %q: %w", lineNum, line, err)
		}

		customProvider.Ranges = append(customProvider.Ranges, line)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading file: %w", err)
	}

	if len(customProvider.Ranges) == 0 {
		return nil, fmt.Errorf("no valid CIDR ranges found in file")
	}

	// Add custom provider to range set
	if err := rs.AddProvider(customProvider); err != nil {
		return nil, err
	}

	return rs, nil
}
