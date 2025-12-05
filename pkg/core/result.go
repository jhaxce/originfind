// Package core provides result types for scan operations
package core

import "time"

// ScanResult represents the complete result of a scan operation
type ScanResult struct {
	Domain    string    `json:"domain"`
	Mode      ScanMode  `json:"mode"`
	StartTime time.Time `json:"start_time"`
	EndTime   time.Time `json:"end_time"`

	// Results by category
	Success   []*IPResult `json:"success"`   // 200 OK
	Redirects []*IPResult `json:"redirects"` // 3xx
	Other     []*IPResult `json:"other"`     // 4xx, 5xx
	Timeouts  []*IPResult `json:"timeouts"`  // Timeout
	Errors    []*IPResult `json:"errors"`    // Connection errors

	// Passive scan results (if applicable)
	PassiveIPs []PassiveIP `json:"passive_ips,omitempty"`

	// Summary statistics
	Summary ScanSummary `json:"summary"`
}

// ScanSummary contains summary statistics
type ScanSummary struct {
	TotalIPs           uint64            `json:"total_ips"`
	ScannedIPs         uint64            `json:"scanned_ips"`
	SkippedIPs         uint64            `json:"skipped_ips"` // WAF IPs
	SuccessCount       uint64            `json:"success_count"`
	SuccessIPs         []string          `json:"success_ips,omitempty"`          // List of 200 OK IPs
	FalsePositiveCount uint64            `json:"false_positive_count,omitempty"` // IPs with Host header warnings
	FalsePositiveIPs   []string          `json:"false_positive_ips,omitempty"`   // IPs flagged as potential false positives
	Duration           time.Duration     `json:"duration"`
	WAFStats           map[string]uint64 `json:"waf_stats,omitempty"` // provider -> count
}

// IPResult represents the result of scanning a single IP
type IPResult struct {
	IP            string   `json:"ip"`
	Status        string   `json:"status"` // "200", "3xx", "4xx", "5xx", "timeout", "error", "skipped"
	HTTPCode      int      `json:"http_code"`
	ResponseTime  string   `json:"response_time"`
	BodyHash      string   `json:"body_hash,omitempty"`      // SHA256 hash of response body (first 8KB)
	Title         string   `json:"title,omitempty"`          // HTML title tag content
	ContentType   string   `json:"content_type,omitempty"`   // Response Content-Type header
	Server        string   `json:"server,omitempty"`         // Server header
	RedirectChain []string `json:"redirect_chain,omitempty"` // Redirect URLs if --follow-redirect is used
	Error         string   `json:"error,omitempty"`
	Provider      string   `json:"provider,omitempty"` // WAF provider if skipped
}

// PassiveIP represents an IP discovered through passive reconnaissance
type PassiveIP struct {
	IP         string                 `json:"ip"`
	Source     string                 `json:"source"`     // "ct", "dns", "shodan", etc.
	Confidence float64                `json:"confidence"` // 0.0 - 1.0
	FirstSeen  time.Time              `json:"first_seen"`
	LastSeen   time.Time              `json:"last_seen"`
	Metadata   map[string]interface{} `json:"metadata,omitempty"`
}

// NewScanResult creates a new scan result
func NewScanResult(domain string, mode ScanMode) *ScanResult {
	return &ScanResult{
		Domain:    domain,
		Mode:      mode,
		StartTime: time.Now(),
		Success:   make([]*IPResult, 0),
		Redirects: make([]*IPResult, 0),
		Other:     make([]*IPResult, 0),
		Timeouts:  make([]*IPResult, 0),
		Errors:    make([]*IPResult, 0),
		Summary: ScanSummary{
			WAFStats: make(map[string]uint64),
		},
	}
}

// AddResult adds an IP result to the appropriate category
func (sr *ScanResult) AddResult(result *IPResult) {
	switch result.Status {
	case "200":
		sr.Success = append(sr.Success, result)
	case "3xx":
		sr.Redirects = append(sr.Redirects, result)
	case "timeout":
		sr.Timeouts = append(sr.Timeouts, result)
	case "error":
		sr.Errors = append(sr.Errors, result)
	default:
		sr.Other = append(sr.Other, result)
	}
}

// Finalize finalizes the scan result (no longer needed, summary is updated inline)
func (sr *ScanResult) Finalize() {
	sr.Summary.Duration = sr.EndTime.Sub(sr.StartTime)
}

// GetSummary returns the current summary
func (sr *ScanResult) GetSummary() *ScanSummary {
	return &sr.Summary
}
