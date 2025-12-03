// origindive - Security analysis tool for origin IP discovery
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/jhaxce/origindive/v3/internal/colors"
	"github.com/jhaxce/origindive/v3/internal/version"
	"github.com/jhaxce/origindive/v3/pkg/core"
	"github.com/jhaxce/origindive/v3/pkg/ip"
	"github.com/jhaxce/origindive/v3/pkg/output"
	"github.com/jhaxce/origindive/v3/pkg/scanner"
	"github.com/jhaxce/origindive/v3/pkg/update"
)

func main() {
	// Parse command line flags
	config := parseFlags()

	// Initialize colors
	colors.Init(!config.NoColor)

	// Validate configuration
	if err := validateConfig(config); err != nil {
		fmt.Fprintf(os.Stderr, "%sError: %s%s\n", colors.RED, err, colors.NC)
		os.Exit(1)
	}

	// Parse IP ranges
	if err := parseIPRanges(config); err != nil {
		fmt.Fprintf(os.Stderr, "%sError: %s%s\n", colors.RED, err, colors.NC)
		os.Exit(1)
	}

	// Create scanner
	s, err := scanner.New(config)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%sError creating scanner: %s%s\n", colors.RED, err, colors.NC)
		os.Exit(1)
	}

	// Print banner
	if !config.Quiet {
		printBanner(config)
	}

	// Create output writer
	formatter := output.NewFormatter(config.Format, !config.NoColor, config.ShowAll)
	writer, err := output.NewWriter(config.OutputFile, formatter, config.Quiet)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%sError creating output writer: %s%s\n", colors.RED, err, colors.NC)
		os.Exit(1)
	}
	defer writer.Close()

	// Write header
	// Calculate total IPs from ranges
	ranges := make([]ip.IPRange, len(config.IPRanges))
	for i, r := range config.IPRanges {
		ranges[i] = ip.IPRange{Start: r[0], End: r[1]}
	}
	iterator := ip.NewIterator(ranges)
	totalIPs := iterator.TotalIPs()
	writer.WriteHeader(config, totalIPs)

	// Create progress tracker
	var prog *output.Progress
	if !config.NoProgress && !config.Quiet {
		prog = output.NewProgress(totalIPs, true, !config.NoColor)
		go prog.Display()
	}

	// Perform scan
	ctx := context.Background()
	result, err := s.Scan(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%sError during scan: %s%s\n", colors.RED, err, colors.NC)
		os.Exit(1)
	}

	// Write results
	for _, r := range result.Success {
		writer.WriteResult(*r)
	}
	if config.ShowAll {
		for _, r := range result.Redirects {
			writer.WriteResult(*r)
		}
		for _, r := range result.Other {
			writer.WriteResult(*r)
		}
		for _, r := range result.Timeouts {
			writer.WriteResult(*r)
		}
		for _, r := range result.Errors {
			writer.WriteResult(*r)
		}
	}

	// Write summary
	writer.WriteSummary(result.Summary)

	// Exit
	if len(result.Success) > 0 {
		os.Exit(0)
	} else {
		os.Exit(1)
	}
}

func parseFlags() *core.Config {
	config := core.DefaultConfig()

	// Config file flag (no short flag to avoid conflict with -c for connect-timeout)
	var configFile string
	flag.StringVar(&configFile, "config", "", "Config file path (YAML)")

	// Update flag
	doUpdate := flag.Bool("update", false, "Check and install updates")

	// Basic flags
	flag.StringVar(&config.Domain, "d", "", "Target domain (required)")
	flag.StringVar(&config.Domain, "domain", "", "Target domain (required)")

	// IP range flags
	flag.StringVar(&config.StartIP, "s", "", "Start IP address")
	flag.StringVar(&config.StartIP, "start-ip", "", "Start IP address")
	flag.StringVar(&config.EndIP, "e", "", "End IP address")
	flag.StringVar(&config.EndIP, "end-ip", "", "End IP address")
	flag.StringVar(&config.CIDR, "n", "", "CIDR notation (e.g., 192.168.1.0/24)")
	flag.StringVar(&config.CIDR, "cidr", "", "CIDR notation")
	flag.StringVar(&config.InputFile, "i", "", "Input file with IPs/CIDRs")
	flag.StringVar(&config.InputFile, "input", "", "Input file")

	// Performance flags
	flag.IntVar(&config.Workers, "j", 10, "Number of parallel workers")
	flag.IntVar(&config.Workers, "threads", 10, "Number of parallel workers")

	// HTTP flags
	flag.StringVar(&config.HTTPMethod, "m", "GET", "HTTP method")
	flag.StringVar(&config.HTTPMethod, "method", "GET", "HTTP method")
	var timeout int
	var connectTimeout int
	flag.IntVar(&timeout, "t", 5, "HTTP timeout in seconds")
	flag.IntVar(&timeout, "timeout", 5, "HTTP timeout")
	flag.IntVar(&connectTimeout, "c", 3, "TCP connect timeout in seconds")
	flag.IntVar(&connectTimeout, "connect-timeout", 3, "TCP connect timeout")
	flag.StringVar(&config.CustomHeader, "H", "", "Custom header")
	flag.BoolVar(&config.NoUserAgent, "no-ua", false, "Disable User-Agent header")

	// WAF filtering flags
	flag.BoolVar(&config.SkipWAF, "skip-waf", false, "Skip known WAF/CDN IP ranges")
	var skipProviders string
	flag.StringVar(&skipProviders, "skip-providers", "", "Comma-separated list of providers to skip")
	flag.BoolVar(&config.ShowSkipped, "show-skipped", false, "Display skipped IPs")
	flag.BoolVar(&config.NoWAFUpdate, "no-waf-update", false, "Disable WAF database auto-update")

	// Output flags
	flag.StringVar(&config.OutputFile, "o", "", "Output file")
	flag.StringVar(&config.OutputFile, "output", "", "Output file")
	var format string
	flag.StringVar(&format, "f", "text", "Output format (text|json|csv)")
	flag.StringVar(&format, "format", "text", "Output format")
	flag.BoolVar(&config.Quiet, "q", false, "Quiet mode")
	flag.BoolVar(&config.Quiet, "quiet", false, "Quiet mode")
	flag.BoolVar(&config.ShowAll, "a", false, "Show all responses")
	flag.BoolVar(&config.ShowAll, "show-all", false, "Show all responses")
	flag.BoolVar(&config.NoColor, "no-color", false, "Disable colored output")
	flag.BoolVar(&config.NoProgress, "no-progress", false, "Disable progress bar")

	// Version flag
	showVersion := flag.Bool("V", false, "Show version")
	flag.BoolVar(showVersion, "version", false, "Show version")

	flag.Parse()

	// Handle update
	if *doUpdate {
		if err := update.Update(); err != nil {
			fmt.Fprintf(os.Stderr, "%sUpdate failed: %s%s\n", colors.RED, err, colors.NC)
			os.Exit(1)
		}
		os.Exit(0)
	}

	// Handle version
	if *showVersion {
		fmt.Printf("origindive v%s\n", version.Version)
		fmt.Printf("Go version: %s\n", runtime.Version())
		fmt.Printf("OS/Arch: %s/%s\n", runtime.GOOS, runtime.GOARCH)
		os.Exit(0)
	}

	// Load config file if specified
	if configFile != "" {
		fileConfig, err := core.LoadFromFile(configFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%sError loading config file: %s%s\n", colors.RED, err, colors.NC)
			os.Exit(1)
		}
		// Merge with CLI flags (CLI takes precedence)
		cliConfig := config
		config = fileConfig
		config.MergeWithCLI(cliConfig)
	}

	// Parse durations
	config.Timeout = time.Duration(timeout) * time.Second
	config.ConnectTimeout = time.Duration(connectTimeout) * time.Second

	// Parse format
	switch strings.ToLower(format) {
	case "text":
		config.Format = core.FormatText
	case "json":
		config.Format = core.FormatJSON
	case "csv":
		config.Format = core.FormatCSV
	default:
		fmt.Fprintf(os.Stderr, "Invalid format: %s\n", format)
		os.Exit(1)
	}

	// Parse skip providers
	if skipProviders != "" {
		config.SkipProviders = strings.Split(skipProviders, ",")
	}

	// Set scan mode
	config.Mode = core.ModeActive

	return config
}

func validateConfig(config *core.Config) error {
	if config.Domain == "" {
		return fmt.Errorf("domain is required (-d or --domain)")
	}

	// Must have at least one IP range method
	if config.StartIP == "" && config.CIDR == "" && config.InputFile == "" {
		return fmt.Errorf("must specify IP range: -s/-e, -n, or -i")
	}

	// If start IP specified, end IP must also be specified
	if config.StartIP != "" && config.EndIP == "" {
		return fmt.Errorf("both start IP (-s) and end IP (-e) required for range mode")
	}

	return nil
}

func parseIPRanges(config *core.Config) error {
	var ranges [][2]uint32

	// Parse IP range
	if config.StartIP != "" && config.EndIP != "" {
		r, err := ip.ParseIPRange(config.StartIP, config.EndIP)
		if err != nil {
			return fmt.Errorf("invalid IP range: %w", err)
		}
		ranges = append(ranges, [2]uint32{r.Start, r.End})
	}

	// Parse CIDR
	if config.CIDR != "" {
		r, err := ip.ParseCIDRRange(config.CIDR)
		if err != nil {
			return fmt.Errorf("invalid CIDR: %w", err)
		}
		ranges = append(ranges, [2]uint32{r.Start, r.End})
	}

	// Parse input file
	if config.InputFile != "" {
		fileRanges, err := ip.ParseInputFile(config.InputFile)
		if err != nil {
			return fmt.Errorf("failed to parse input file: %w", err)
		}
		for _, r := range fileRanges {
			ranges = append(ranges, [2]uint32{r.Start, r.End})
		}
	}

	config.IPRanges = ranges
	return nil
}
func printBanner(config *core.Config) {
	fmt.Println()
	fmt.Printf("%s════════════════════════════════════════════════════════════════%s\n", colors.CYAN, colors.NC)
	fmt.Printf("%sorigindive v%s - Origin IP Discovery Tool%s\n", colors.BOLD, version.Version, colors.NC)
	if config.SkipWAF {
		fmt.Printf("%sWAF Filtering: ENABLED%s\n", colors.GREEN, colors.NC)
	}
	fmt.Printf("%s════════════════════════════════════════════════════════════════%s\n", colors.CYAN, colors.NC)
	fmt.Printf("%s[*]%s Domain: %s\n", colors.BLUE, colors.NC, config.Domain)
	fmt.Printf("%s[*]%s Workers: %d\n", colors.BLUE, colors.NC, config.Workers)
	fmt.Printf("%s[*]%s Timeout: %s\n", colors.BLUE, colors.NC, config.Timeout)
	fmt.Println()
}
