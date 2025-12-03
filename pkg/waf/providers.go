// Package waf provides WAF/CDN detection and IP filtering
package waf

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"time"
)

// Provider represents a WAF/CDN provider with their IP ranges
type Provider struct {
	Name        string   `json:"name"`
	ID          string   `json:"id"`
	Description string   `json:"description"`
	Ranges      []string `json:"ranges"` // CIDR notation
}

// WAFDatabase represents the complete WAF IP ranges database
type WAFDatabase struct {
	LastUpdated time.Time         `json:"last_updated"`
	Sources     map[string]string `json:"sources"`
	Providers   []Provider        `json:"providers"`
}

// LoadWAFDatabase loads the WAF ranges database from a JSON file
func LoadWAFDatabase(filepath string) (*WAFDatabase, error) {
	data, err := os.ReadFile(filepath)
	if err != nil {
		return nil, fmt.Errorf("failed to read WAF database: %w", err)
	}

	var db WAFDatabase
	if err := json.Unmarshal(data, &db); err != nil {
		return nil, fmt.Errorf("failed to parse WAF database: %w", err)
	}

	return &db, nil
}

// SaveWAFDatabase saves the WAF ranges database to a JSON file
func SaveWAFDatabase(filepath string, db *WAFDatabase) error {
	data, err := json.MarshalIndent(db, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal WAF database: %w", err)
	}

	if err := os.WriteFile(filepath, data, 0644); err != nil {
		return fmt.Errorf("failed to write WAF database: %w", err)
	}

	return nil
}

// GetProvider returns a provider by ID
func (db *WAFDatabase) GetProvider(id string) *Provider {
	for i := range db.Providers {
		if db.Providers[i].ID == id {
			return &db.Providers[i]
		}
	}
	return nil
}

// GetProviderByName returns a provider by name (case-insensitive)
func (db *WAFDatabase) GetProviderByName(name string) *Provider {
	lowerName := toLower(name)
	for i := range db.Providers {
		if toLower(db.Providers[i].Name) == lowerName || toLower(db.Providers[i].ID) == lowerName {
			return &db.Providers[i]
		}
	}
	return nil
}

// ListProviders returns a list of all provider IDs
func (db *WAFDatabase) ListProviders() []string {
	ids := make([]string, 0, len(db.Providers))
	for _, p := range db.Providers {
		ids = append(ids, p.ID)
	}
	return ids
}

// GetTotalRanges returns the total number of CIDR ranges across all providers
func (db *WAFDatabase) GetTotalRanges() int {
	total := 0
	for _, p := range db.Providers {
		total += len(p.Ranges)
	}
	return total
}

// ValidateRanges validates all CIDR ranges in the database
func (db *WAFDatabase) ValidateRanges() error {
	for _, provider := range db.Providers {
		for _, cidr := range provider.Ranges {
			if _, _, err := net.ParseCIDR(cidr); err != nil {
				return fmt.Errorf("invalid CIDR in provider %s: %s - %w", provider.ID, cidr, err)
			}
		}
	}
	return nil
}

// toLower is a simple helper for case-insensitive comparison
func toLower(s string) string {
	// Simple ASCII lowercase conversion
	result := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		result[i] = c
	}
	return string(result)
}
