// Package core provides core types and configuration for origindive
package core

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"gopkg.in/yaml.v3"
)

// GlobalConfig holds persistent configuration (API keys, preferences)
// Stored at: ~/.config/origindive/config.yaml (all platforms - XDG compliant)
type GlobalConfig struct {
	// API keys for passive sources (multiple keys per service for rotation)
	ShodanKeys         []string           `yaml:"shodan_keys,omitempty" json:"shodan_keys,omitempty"`
	CensysTokens       []string           `yaml:"censys_tokens,omitempty" json:"censys_tokens,omitempty"` // PAT tokens (Bearer auth)
	CensysOrgID        string             `yaml:"censys_org_id,omitempty" json:"censys_org_id,omitempty"` // Organization ID for paid plans
	SecurityTrailsKeys []string           `yaml:"securitytrails_keys,omitempty" json:"securitytrails_keys,omitempty"`
	ZoomEyeKeys        []string           `yaml:"zoomeye_keys,omitempty" json:"zoomeye_keys,omitempty"`
	DNSDumpsterKeys    []string           `yaml:"dnsdumpster_keys,omitempty" json:"dnsdumpster_keys,omitempty"`
	VirusTotalKeys     []string           `yaml:"virustotal_keys,omitempty" json:"virustotal_keys,omitempty"`
	ViewDNSKeys        []string           `yaml:"viewdns_keys,omitempty" json:"viewdns_keys,omitempty"`
	CensysCreds        []CensysCredential `yaml:"censys_creds,omitempty" json:"censys_creds,omitempty"` // Legacy format (deprecated)

	// Proxy service API keys
	WebshareKeys    []string `yaml:"webshare_keys,omitempty" json:"webshare_keys,omitempty"`         // Webshare.io API keys
	WebsharePlanIDs []string `yaml:"webshare_plan_ids,omitempty" json:"webshare_plan_ids,omitempty"` // Plan IDs (optional, maps 1:1 with keys)

	// HTTP configuration (global defaults)
	HTTPMethod     string `yaml:"http_method,omitempty" json:"http_method,omitempty"`
	Timeout        string `yaml:"timeout,omitempty" json:"timeout,omitempty"`                 // e.g., "5s", "10s"
	ConnectTimeout string `yaml:"connect_timeout,omitempty" json:"connect_timeout,omitempty"` // e.g., "3s"
	NoUserAgent    bool   `yaml:"no_user_agent,omitempty" json:"no_user_agent,omitempty"`

	// Performance (global defaults)
	Workers int `yaml:"workers,omitempty" json:"workers,omitempty"`

	// WAF filtering (global defaults)
	SkipWAF       bool     `yaml:"skip_waf,omitempty" json:"skip_waf,omitempty"`
	SkipProviders []string `yaml:"skip_providers,omitempty" json:"skip_providers,omitempty"`
	ShowSkipped   bool     `yaml:"show_skipped,omitempty" json:"show_skipped,omitempty"`
	NoWAFUpdate   bool     `yaml:"no_waf_update,omitempty" json:"no_waf_update,omitempty"`

	// Passive scan (global defaults)
	PassiveSources []string `yaml:"passive_sources,omitempty" json:"passive_sources,omitempty"`
	MinConfidence  float64  `yaml:"min_confidence,omitempty" json:"min_confidence,omitempty"`

	// Output (global defaults)
	Format     string `yaml:"format,omitempty" json:"format,omitempty"`
	Quiet      bool   `yaml:"quiet,omitempty" json:"quiet,omitempty"`
	Verbose    bool   `yaml:"verbose,omitempty" json:"verbose,omitempty"`
	NoColor    bool   `yaml:"no_color,omitempty" json:"no_color,omitempty"`
	NoProgress bool   `yaml:"no_progress,omitempty" json:"no_progress,omitempty"`

	// API failover configuration
	APIFailover APIFailoverConfig `yaml:"api_failover,omitempty" json:"api_failover,omitempty"`
}

// CensysCredential holds Censys API credentials
type CensysCredential struct {
	ID     string `yaml:"id" json:"id"`
	Secret string `yaml:"secret" json:"secret"`
}

// APIFailoverConfig controls API failover behavior
type APIFailoverConfig struct {
	Enabled            bool `yaml:"enabled" json:"enabled"`                           // Enable automatic failover
	SkipOnRateLimit    bool `yaml:"skip_on_rate_limit" json:"skip_on_rate_limit"`     // Skip source if rate limited
	RetryAfterCooldown bool `yaml:"retry_after_cooldown" json:"retry_after_cooldown"` // Retry after cooldown period
}

// GetGlobalConfigPath returns the path to the global config file
func GetGlobalConfigPath() (string, error) {
	var homeDir string
	if runtime.GOOS == "windows" {
		homeDir = os.Getenv("USERPROFILE")
	} else {
		homeDir = os.Getenv("HOME")
	}

	if homeDir == "" {
		return "", fmt.Errorf("could not determine home directory")
	}

	configDir := filepath.Join(homeDir, ".config", "origindive")
	return filepath.Join(configDir, "config.yaml"), nil
}

// LoadGlobalConfig loads the global configuration from the default location
func LoadGlobalConfig() (*GlobalConfig, error) {
	configPath, err := GetGlobalConfigPath()
	if err != nil {
		return nil, err
	}

	// If file doesn't exist, return default config
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		return DefaultGlobalConfig(), nil
	}

	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read global config: %w", err)
	}

	config := DefaultGlobalConfig()
	if err := yaml.Unmarshal(data, config); err != nil {
		return nil, fmt.Errorf("failed to parse global config: %w", err)
	}

	return config, nil
}

// SaveGlobalConfig saves the global configuration to the default location
func SaveGlobalConfig(config *GlobalConfig) error {
	configPath, err := GetGlobalConfigPath()
	if err != nil {
		return err
	}

	// Create config directory if it doesn't exist
	configDir := filepath.Dir(configPath)
	if err := os.MkdirAll(configDir, 0700); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	// Generate clean YAML with comments
	data := formatGlobalConfigYAML(config)

	if err := os.WriteFile(configPath, []byte(data), 0600); err != nil {
		return fmt.Errorf("failed to write global config: %w", err)
	}

	return nil
}

// formatGlobalConfigYAML formats the global config as clean YAML with comments
func formatGlobalConfigYAML(config *GlobalConfig) string {
	var sb strings.Builder

	sb.WriteString("# origindive Global Configuration\n")
	sb.WriteString("# Generated by --init-config\n")
	sb.WriteString("# Edit this file to change default settings for all scans\n\n")

	// API Keys Section
	sb.WriteString("# ═══════════════════════════════════════════════════════════════\n")
	sb.WriteString("# API Keys (Passive Reconnaissance Sources)\n")
	sb.WriteString("# ═══════════════════════════════════════════════════════════════\n\n")

	if len(config.ShodanKeys) > 0 {
		sb.WriteString("# Shodan\n")
		sb.WriteString("# Get API key: https://account.shodan.io/ | Docs: https://developer.shodan.io/api\n")
		sb.WriteString("shodan_keys:\n")
		for _, key := range config.ShodanKeys {
			sb.WriteString(fmt.Sprintf("  - %s\n", key))
		}
		sb.WriteString("\n")
	}

	if len(config.CensysTokens) > 0 {
		sb.WriteString("# Censys\n")
		sb.WriteString("# Get API token: https://accounts.censys.io/settings/personal-access-tokens | Docs: https://docs.censys.com/reference/get-started\n")
		sb.WriteString("censys_tokens:\n")
		for _, token := range config.CensysTokens {
			sb.WriteString(fmt.Sprintf("  - %s\n", token))
		}
		if config.CensysOrgID != "" {
			sb.WriteString(fmt.Sprintf("censys_org_id: %s\n", config.CensysOrgID))
		}
		sb.WriteString("\n")
	}

	if len(config.SecurityTrailsKeys) > 0 {
		sb.WriteString("# SecurityTrails\n")
		sb.WriteString("# Get API key: https://securitytrails.com/app/account/credentials | Docs: https://securitytrails.com/app/account/docs-and-examples\n")
		sb.WriteString("securitytrails_keys:\n")
		for _, key := range config.SecurityTrailsKeys {
			sb.WriteString(fmt.Sprintf("  - %s\n", key))
		}
		sb.WriteString("\n")
	}

	if len(config.VirusTotalKeys) > 0 {
		sb.WriteString("# VirusTotal\n")
		sb.WriteString("# Get API key: https://www.virustotal.com/gui/user/[USERNAME]/apikey | Docs: https://docs.virustotal.com/reference/overview\n")
		sb.WriteString("virustotal_keys:\n")
		for _, key := range config.VirusTotalKeys {
			sb.WriteString(fmt.Sprintf("  - %s\n", key))
		}
		sb.WriteString("\n")
	}

	if len(config.ZoomEyeKeys) > 0 {
		sb.WriteString("# ZoomEye\n")
		sb.WriteString("# Get API key: https://www.zoomeye.ai/profile | Docs: https://www.zoomeye.ai/doc\n")
		sb.WriteString("zoomeye_keys:\n")
		for _, key := range config.ZoomEyeKeys {
			sb.WriteString(fmt.Sprintf("  - %s\n", key))
		}
		sb.WriteString("\n")
	}

	if len(config.ViewDNSKeys) > 0 {
		sb.WriteString("# ViewDNS\n")
		sb.WriteString("# Get API key: https://viewdns.info/dashboard/api/account-details/ | Docs: https://viewdns.info/api/\n")
		sb.WriteString("viewdns_keys:\n")
		for _, key := range config.ViewDNSKeys {
			sb.WriteString(fmt.Sprintf("  - %s\n", key))
		}
		sb.WriteString("\n")
	}

	if len(config.DNSDumpsterKeys) > 0 {
		sb.WriteString("# DNSDumpster\n")
		sb.WriteString("# Get API key: https://dnsdumpster.com/my-account/ | Docs: https://dnsdumpster.com/developer/\n")
		sb.WriteString("dnsdumpster_keys:\n")
		for _, key := range config.DNSDumpsterKeys {
			sb.WriteString(fmt.Sprintf("  - %s\n", key))
		}
		sb.WriteString("\n")
	}

	if len(config.WebshareKeys) > 0 {
		sb.WriteString("# Webshare Proxy Service\n")
		sb.WriteString("# Get API key: https://dashboard.webshare.io/userapi/keys | Docs: https://apidocs.webshare.io/\n")
		sb.WriteString("webshare_keys:\n")
		for _, key := range config.WebshareKeys {
			sb.WriteString(fmt.Sprintf("  - %s\n", key))
		}
		if len(config.WebsharePlanIDs) > 0 {
			sb.WriteString("webshare_plan_ids:\n")
			for _, planID := range config.WebsharePlanIDs {
				sb.WriteString(fmt.Sprintf("  - %s\n", planID))
			}
		}
		sb.WriteString("\n")
	}

	// Default Settings Section
	sb.WriteString("# ═══════════════════════════════════════════════════════════════\n")
	sb.WriteString("# Default Scan Settings\n")
	sb.WriteString("# ═══════════════════════════════════════════════════════════════\n\n")

	sb.WriteString("# HTTP Configuration\n")
	if config.HTTPMethod != "" {
		sb.WriteString(fmt.Sprintf("http_method: %s\n", config.HTTPMethod))
	}
	if config.Timeout != "" {
		sb.WriteString(fmt.Sprintf("timeout: %s\n", config.Timeout))
	}
	if config.ConnectTimeout != "" {
		sb.WriteString(fmt.Sprintf("connect_timeout: %s\n", config.ConnectTimeout))
	}
	if config.NoUserAgent {
		sb.WriteString("no_user_agent: true\n")
	}
	sb.WriteString("\n")

	sb.WriteString("# Performance\n")
	if config.Workers > 0 {
		sb.WriteString(fmt.Sprintf("workers: %d\n", config.Workers))
	}
	sb.WriteString("\n")

	sb.WriteString("# WAF/CDN Filtering\n")
	if config.SkipWAF {
		sb.WriteString("skip_waf: true\n")
	}
	if len(config.SkipProviders) > 0 {
		sb.WriteString("skip_providers:\n")
		for _, provider := range config.SkipProviders {
			sb.WriteString(fmt.Sprintf("  - %s\n", provider))
		}
	}
	if config.ShowSkipped {
		sb.WriteString("show_skipped: true\n")
	}
	if config.NoWAFUpdate {
		sb.WriteString("no_waf_update: true\n")
	}
	sb.WriteString("\n")

	sb.WriteString("# Passive Reconnaissance\n")
	if len(config.PassiveSources) > 0 {
		sb.WriteString("passive_sources:\n")
		for _, source := range config.PassiveSources {
			sb.WriteString(fmt.Sprintf("  - %s\n", source))
		}
	}
	if config.MinConfidence > 0 {
		sb.WriteString(fmt.Sprintf("min_confidence: %.1f\n", config.MinConfidence))
	}
	sb.WriteString("\n")

	sb.WriteString("# Output Settings\n")
	if config.Format != "" {
		sb.WriteString(fmt.Sprintf("format: %s  # text, json, or csv\n", config.Format))
	}
	if config.Quiet {
		sb.WriteString("quiet: true\n")
	}
	if config.Verbose {
		sb.WriteString("verbose: true\n")
	}
	if config.NoColor {
		sb.WriteString("no_color: true\n")
	}
	if config.NoProgress {
		sb.WriteString("no_progress: true\n")
	}
	sb.WriteString("\n")

	sb.WriteString("# API Failover Configuration\n")
	sb.WriteString("api_failover:\n")
	sb.WriteString(fmt.Sprintf("  enabled: %v\n", config.APIFailover.Enabled))
	sb.WriteString(fmt.Sprintf("  skip_on_rate_limit: %v\n", config.APIFailover.SkipOnRateLimit))
	sb.WriteString(fmt.Sprintf("  retry_after_cooldown: %v\n", config.APIFailover.RetryAfterCooldown))

	return sb.String()
}

// DefaultGlobalConfig returns a global configuration with sensible defaults
func DefaultGlobalConfig() *GlobalConfig {
	return &GlobalConfig{
		HTTPMethod:     "GET",
		Timeout:        "5s",
		ConnectTimeout: "3s",
		Workers:        20,
		SkipWAF:        true,
		PassiveSources: []string{"ct", "dns", "shodan", "censys", "securitytrails", "zoomeye", "wayback", "virustotal", "viewdns", "dnsdumpster"},
		MinConfidence:  0.7,
		Format:         "text",
		APIFailover: APIFailoverConfig{
			Enabled:            true,
			SkipOnRateLimit:    true,
			RetryAfterCooldown: false,
		},
	}
}

// MergeIntoConfig merges global config into a scan config (scan config takes precedence)
func (gc *GlobalConfig) MergeIntoConfig(c *Config) {
	// Copy API keys from global config to scan config (if not already set)
	if len(c.ShodanKeys) == 0 && len(gc.ShodanKeys) > 0 {
		c.ShodanKeys = gc.ShodanKeys
	}
	if len(c.CensysTokens) == 0 && len(gc.CensysTokens) > 0 {
		c.CensysTokens = gc.CensysTokens
	}
	if c.CensysOrgID == "" && gc.CensysOrgID != "" {
		c.CensysOrgID = gc.CensysOrgID
	}
	if len(c.SecurityTrailsKeys) == 0 && len(gc.SecurityTrailsKeys) > 0 {
		c.SecurityTrailsKeys = gc.SecurityTrailsKeys
	}
	if len(c.ZoomEyeKeys) == 0 && len(gc.ZoomEyeKeys) > 0 {
		c.ZoomEyeKeys = gc.ZoomEyeKeys
	}
	if len(c.DNSDumpsterKeys) == 0 && len(gc.DNSDumpsterKeys) > 0 {
		c.DNSDumpsterKeys = gc.DNSDumpsterKeys
	}
	if len(c.VirusTotalKeys) == 0 && len(gc.VirusTotalKeys) > 0 {
		c.VirusTotalKeys = gc.VirusTotalKeys
	}
	if len(c.ViewDNSKeys) == 0 && len(gc.ViewDNSKeys) > 0 {
		c.ViewDNSKeys = gc.ViewDNSKeys
	}

	// Proxy service keys
	if c.WebshareAPIKey == "" && len(gc.WebshareKeys) > 0 {
		c.WebshareAPIKey = gc.WebshareKeys[0]
		if len(gc.WebsharePlanIDs) > 0 {
			c.WebsharePlanID = gc.WebsharePlanIDs[0]
		}
	}

	// HTTP settings - use global if not set in scan config
	if c.HTTPMethod == "" || c.HTTPMethod == "GET" {
		if gc.HTTPMethod != "" {
			c.HTTPMethod = gc.HTTPMethod
		}
	}
	if gc.Timeout != "" {
		// Parse and apply if scan config uses default
		// (actual parsing happens in config validation)
	}
	if gc.NoUserAgent {
		c.NoUserAgent = gc.NoUserAgent
	}

	// Performance
	if c.Workers == 10 && gc.Workers != 0 { // 10 is package default
		c.Workers = gc.Workers
	}

	// WAF filtering
	if !c.SkipWAF && gc.SkipWAF {
		c.SkipWAF = gc.SkipWAF
	}
	if len(c.SkipProviders) == 0 && len(gc.SkipProviders) > 0 {
		c.SkipProviders = gc.SkipProviders
	}
	if !c.ShowSkipped && gc.ShowSkipped {
		c.ShowSkipped = gc.ShowSkipped
	}
	if !c.NoWAFUpdate && gc.NoWAFUpdate {
		c.NoWAFUpdate = gc.NoWAFUpdate
	}

	// Passive sources
	if len(c.PassiveSources) == 0 && len(gc.PassiveSources) > 0 {
		c.PassiveSources = gc.PassiveSources
	}
	if c.MinConfidence == 0.7 && gc.MinConfidence != 0 { // 0.7 is package default
		c.MinConfidence = gc.MinConfidence
	}

	// Output settings
	if c.Format == "" || c.Format == FormatText {
		if gc.Format != "" {
			c.Format = OutputFormat(gc.Format)
		}
	}
	if !c.Quiet && gc.Quiet {
		c.Quiet = gc.Quiet
	}
	if !c.Verbose && gc.Verbose {
		c.Verbose = gc.Verbose
	}
	if !c.NoColor && gc.NoColor {
		c.NoColor = gc.NoColor
	}
	if !c.NoProgress && gc.NoProgress {
		c.NoProgress = gc.NoProgress
	}
}

// GetShodanKey returns the first available Shodan key (for backward compatibility)
func (gc *GlobalConfig) GetShodanKey() string {
	if len(gc.ShodanKeys) > 0 {
		return gc.ShodanKeys[0]
	}
	return ""
}

// GetCensysCred returns the first available Censys credential (for backward compatibility)
func (gc *GlobalConfig) GetCensysCred() (string, string) {
	if len(gc.CensysCreds) > 0 {
		return gc.CensysCreds[0].ID, gc.CensysCreds[0].Secret
	}
	return "", ""
}
