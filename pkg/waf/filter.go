// Package waf provides WAF/CDN IP filtering functionality
package waf

import (
	"fmt"
	"net"
	"sync/atomic"
)

// Filter provides WAF IP filtering with statistics tracking
type Filter struct {
	rangeSet *RangeSet
	enabled  bool

	// Statistics (atomic counters for thread safety)
	totalChecked      uint64
	totalSkipped      uint64
	skippedByProvider map[string]*uint64 // provider -> count
}

// NewFilter creates a new WAF filter
func NewFilter(rangeSet *RangeSet, enabled bool) *Filter {
	f := &Filter{
		rangeSet:          rangeSet,
		enabled:           enabled,
		skippedByProvider: make(map[string]*uint64),
	}

	// Initialize counters for each provider
	if rangeSet != nil {
		for _, providerID := range rangeSet.Providers() {
			count := uint64(0)
			f.skippedByProvider[providerID] = &count
		}
	}

	return f
}

// ShouldSkip checks if an IP should be skipped (is in WAF range)
// Returns (shouldSkip, providerID)
func (f *Filter) ShouldSkip(ip net.IP) (bool, string) {
	if !f.enabled || f.rangeSet == nil {
		return false, ""
	}

	atomic.AddUint64(&f.totalChecked, 1)

	providerID, found := f.rangeSet.FindProvider(ip)
	if found {
		atomic.AddUint64(&f.totalSkipped, 1)
		if counter, ok := f.skippedByProvider[providerID]; ok {
			atomic.AddUint64(counter, 1)
		}
		return true, providerID
	}

	return false, ""
}

// ShouldSkipString checks if an IP string should be skipped
func (f *Filter) ShouldSkipString(ipStr string) (bool, string) {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false, ""
	}
	return f.ShouldSkip(ip)
}

// GetStats returns filtering statistics
func (f *Filter) GetStats() FilterStats {
	stats := FilterStats{
		TotalChecked: atomic.LoadUint64(&f.totalChecked),
		TotalSkipped: atomic.LoadUint64(&f.totalSkipped),
		ByProvider:   make(map[string]uint64),
	}

	for provider, counter := range f.skippedByProvider {
		stats.ByProvider[provider] = atomic.LoadUint64(counter)
	}

	return stats
}

// Reset resets all statistics
func (f *Filter) Reset() {
	atomic.StoreUint64(&f.totalChecked, 0)
	atomic.StoreUint64(&f.totalSkipped, 0)
	for _, counter := range f.skippedByProvider {
		atomic.StoreUint64(counter, 0)
	}
}

// IsEnabled returns whether the filter is enabled
func (f *Filter) IsEnabled() bool {
	return f.enabled
}

// Enable enables the filter
func (f *Filter) Enable() {
	f.enabled = true
}

// Disable disables the filter
func (f *Filter) Disable() {
	f.enabled = false
}

// FilterStats represents filtering statistics
type FilterStats struct {
	TotalChecked uint64            `json:"total_checked"`
	TotalSkipped uint64            `json:"total_skipped"`
	ByProvider   map[string]uint64 `json:"by_provider"`
}

// String returns a human-readable representation of the stats
func (fs FilterStats) String() string {
	if fs.TotalChecked == 0 {
		return "No IPs checked"
	}

	percentage := float64(fs.TotalSkipped) / float64(fs.TotalChecked) * 100
	result := fmt.Sprintf("Checked: %d, Skipped: %d (%.1f%%)",
		fs.TotalChecked, fs.TotalSkipped, percentage)

	if len(fs.ByProvider) > 0 {
		result += "\nSkipped by provider:"
		for provider, count := range fs.ByProvider {
			if count > 0 {
				result += fmt.Sprintf("\n  - %s: %d", provider, count)
			}
		}
	}

	return result
}

// NewFilterFromDatabase creates a filter from a WAF database
// If providerIDs is empty, all providers are loaded
func NewFilterFromDatabase(db *WAFDatabase, providerIDs []string, enabled bool) (*Filter, error) {
	rangeSet, err := LoadFromDatabase(db, providerIDs)
	if err != nil {
		return nil, fmt.Errorf("failed to load ranges from database: %w", err)
	}

	return NewFilter(rangeSet, enabled), nil
}
