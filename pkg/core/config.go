// Package core provides core types and configuration for origindive
package core

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// Config holds all configuration for origindive
type Config struct {
	// Target configuration
	Domain string `yaml:"domain" json:"domain"`

	// Scan mode
	Mode ScanMode `yaml:"mode" json:"mode"` // passive, active, auto

	// IP ranges for active scan
	IPRanges  [][2]uint32 `yaml:"-" json:"-"` // Computed from inputs
	StartIP   string      `yaml:"start_ip" json:"start_ip"`
	EndIP     string      `yaml:"end_ip" json:"end_ip"`
	CIDR      string      `yaml:"cidr" json:"cidr"`
	InputFile string      `yaml:"input_file" json:"input_file"`

	// HTTP configuration
	HTTPMethod     string        `yaml:"http_method" json:"http_method"`
	Timeout        time.Duration `yaml:"timeout" json:"timeout"`
	ConnectTimeout time.Duration `yaml:"connect_timeout" json:"connect_timeout"`
	CustomHeader   string        `yaml:"custom_header" json:"custom_header"`
	NoUserAgent    bool          `yaml:"no_user_agent" json:"no_user_agent"`

	// Performance
	Workers int `yaml:"workers" json:"workers"`

	// WAF filtering
	SkipWAF       bool     `yaml:"skip_waf" json:"skip_waf"`
	SkipProviders []string `yaml:"skip_providers" json:"skip_providers"`
	CustomWAFFile string   `yaml:"custom_waf_file" json:"custom_waf_file"`
	ShowSkipped   bool     `yaml:"show_skipped" json:"show_skipped"`
	NoWAFUpdate   bool     `yaml:"no_waf_update" json:"no_waf_update"`

	// Passive scan configuration
	PassiveOnly    bool     `yaml:"passive_only" json:"passive_only"`
	AutoScan       bool     `yaml:"auto_scan" json:"auto_scan"`
	MinConfidence  float64  `yaml:"min_confidence" json:"min_confidence"`
	PassiveSources []string `yaml:"passive_sources" json:"passive_sources"`

	// API keys for passive sources
	ShodanKey    string `yaml:"shodan_key" json:"shodan_key"`
	CensysID     string `yaml:"censys_id" json:"censys_id"`
	CensysSecret string `yaml:"censys_secret" json:"censys_secret"`

	// Output configuration
	OutputFile string       `yaml:"output_file" json:"output_file"`
	Format     OutputFormat `yaml:"format" json:"format"`
	Quiet      bool         `yaml:"quiet" json:"quiet"`
	Verbose    bool         `yaml:"verbose" json:"verbose"`
	ShowAll    bool         `yaml:"show_all" json:"show_all"`
	NoColor    bool         `yaml:"no_color" json:"no_color"`
	NoProgress bool         `yaml:"no_progress" json:"no_progress"`
}

// ScanMode represents the scanning mode
type ScanMode string

const (
	ModePassive ScanMode = "passive" // Only passive OSINT
	ModeActive  ScanMode = "active"  // Only active scanning
	ModeAuto    ScanMode = "auto"    // Passive then active
)

// OutputFormat represents the output format
type OutputFormat string

const (
	FormatText OutputFormat = "text"
	FormatJSON OutputFormat = "json"
	FormatCSV  OutputFormat = "csv"
)

// DefaultConfig returns a configuration with sensible defaults
func DefaultConfig() *Config {
	return &Config{
		Mode:           ModeActive,
		HTTPMethod:     "GET",
		Timeout:        5 * time.Second,
		ConnectTimeout: 3 * time.Second,
		Workers:        10,
		Format:         FormatText,
		MinConfidence:  0.7,
		PassiveSources: []string{"ct", "dns"},
	}
}

// Validate checks if the configuration is valid
func (c *Config) Validate() error {
	if c.Domain == "" {
		return ErrNoDomain
	}

	if c.Mode == ModeActive || c.Mode == ModeAuto {
		if len(c.IPRanges) == 0 && c.StartIP == "" && c.EndIP == "" && c.CIDR == "" && c.InputFile == "" && c.Mode != ModeAuto {
			return ErrNoIPRange
		}
	}

	if c.Workers < 1 {
		c.Workers = 1
	}

	if c.Workers > 1000 {
		return ErrTooManyWorkers
	}

	return nil
}

// LoadFromFile loads configuration from a YAML file
func LoadFromFile(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	config := DefaultConfig()
	if err := yaml.Unmarshal(data, config); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	return config, nil
}

// MergeWithCLI merges CLI flags with config (CLI takes precedence)
func (c *Config) MergeWithCLI(cli *Config) {
	// Only merge non-zero/non-empty CLI values
	if cli.Domain != "" {
		c.Domain = cli.Domain
	}
	if cli.Mode != "" {
		c.Mode = cli.Mode
	}
	if cli.StartIP != "" {
		c.StartIP = cli.StartIP
	}
	if cli.EndIP != "" {
		c.EndIP = cli.EndIP
	}
	if cli.CIDR != "" {
		c.CIDR = cli.CIDR
	}
	if cli.InputFile != "" {
		c.InputFile = cli.InputFile
	}
	if cli.HTTPMethod != "" && cli.HTTPMethod != "GET" {
		c.HTTPMethod = cli.HTTPMethod
	}
	if cli.Timeout != 0 && cli.Timeout != 5*time.Second {
		c.Timeout = cli.Timeout
	}
	if cli.ConnectTimeout != 0 && cli.ConnectTimeout != 3*time.Second {
		c.ConnectTimeout = cli.ConnectTimeout
	}
	if cli.CustomHeader != "" {
		c.CustomHeader = cli.CustomHeader
	}
	if cli.NoUserAgent {
		c.NoUserAgent = cli.NoUserAgent
	}
	if cli.Workers != 0 && cli.Workers != 10 {
		c.Workers = cli.Workers
	}
	if cli.SkipWAF {
		c.SkipWAF = cli.SkipWAF
	}
	if len(cli.SkipProviders) > 0 {
		c.SkipProviders = cli.SkipProviders
	}
	if cli.CustomWAFFile != "" {
		c.CustomWAFFile = cli.CustomWAFFile
	}
	if cli.ShowSkipped {
		c.ShowSkipped = cli.ShowSkipped
	}
	if cli.NoWAFUpdate {
		c.NoWAFUpdate = cli.NoWAFUpdate
	}
	if cli.PassiveOnly {
		c.PassiveOnly = cli.PassiveOnly
	}
	if cli.AutoScan {
		c.AutoScan = cli.AutoScan
	}
	if cli.MinConfidence != 0 && cli.MinConfidence != 0.7 {
		c.MinConfidence = cli.MinConfidence
	}
	if len(cli.PassiveSources) > 0 {
		c.PassiveSources = cli.PassiveSources
	}
	if cli.ShodanKey != "" {
		c.ShodanKey = cli.ShodanKey
	}
	if cli.CensysID != "" {
		c.CensysID = cli.CensysID
	}
	if cli.CensysSecret != "" {
		c.CensysSecret = cli.CensysSecret
	}
	if cli.OutputFile != "" {
		c.OutputFile = cli.OutputFile
	}
	if cli.Format != "" && cli.Format != FormatText {
		c.Format = cli.Format
	}
	if cli.Quiet {
		c.Quiet = cli.Quiet
	}
	if cli.Verbose {
		c.Verbose = cli.Verbose
	}
	if cli.ShowAll {
		c.ShowAll = cli.ShowAll
	}
	if cli.NoColor {
		c.NoColor = cli.NoColor
	}
	if cli.NoProgress {
		c.NoProgress = cli.NoProgress
	}
}
