// Package output provides result formatting functionality
package output

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/jhaxce/origindive/v3/pkg/core"
)

// Formatter provides result formatting in various formats
type Formatter struct {
	format    core.OutputFormat
	useColors bool
	showAll   bool

	// Colors
	red     string
	green   string
	yellow  string
	blue    string
	cyan    string
	magenta string
	bold    string
	nc      string
}

// NewFormatter creates a new result formatter
func NewFormatter(format core.OutputFormat, useColors bool, showAll bool) *Formatter {
	f := &Formatter{
		format:    format,
		useColors: useColors,
		showAll:   showAll,
	}

	if useColors {
		f.red = "\033[31m"
		f.green = "\033[32m"
		f.yellow = "\033[33m"
		f.blue = "\033[34m"
		f.cyan = "\033[36m"
		f.magenta = "\033[35m"
		f.bold = "\033[1m"
		f.nc = "\033[0m"
	}

	return f
}

// FormatHeader formats the scan header
func (f *Formatter) FormatHeader(config *core.Config, totalIPs uint64) string {
	if f.format != core.FormatText {
		return ""
	}

	var sb strings.Builder
	sb.WriteString("\n")
	sb.WriteString(f.cyan + "═══════════════════════════════════════════════════════════════\n")
	sb.WriteString("              _       _           ___          \n")
	sb.WriteString("  ____  _____(_)___ _(_)___  ____/ (_)   _____ \n")
	sb.WriteString(" / __ \\/ ___/ / __ `/ / __ \\/ __  / / | / / _ \\\n")
	sb.WriteString("/ /_/ / /  / / /_/ / / / / / /_/ / /| |/ /  __/\n")
	sb.WriteString("\\____/_/  /_/\\__, /_/_/ /_/\\__,_/_/ |___/\\___/ \n")
	sb.WriteString("            /____/\n")
	sb.WriteString("═══════════════════════════════════════════════════════════════" + f.nc + "\n")
	sb.WriteString(fmt.Sprintf("[*] Domain: %s\n", config.Domain))
	sb.WriteString(fmt.Sprintf("[*] Mode: %s\n", config.Mode))
	sb.WriteString(fmt.Sprintf("[*] Total IPs: %d\n", totalIPs))
	sb.WriteString(fmt.Sprintf("[*] Workers: %d\n", config.Workers))

	if config.SkipWAF {
		providers := "all"
		if len(config.SkipProviders) > 0 {
			providers = strings.Join(config.SkipProviders, ", ")
		}
		sb.WriteString(fmt.Sprintf("[*] WAF Filtering: %s\n", providers))
	}

	sb.WriteString(f.cyan + "═══════════════════════════════════════════════════════════════" + f.nc + "\n\n")

	return sb.String()
}

// FormatResult formats a single IP result
func (f *Formatter) FormatResult(result core.IPResult) string {
	switch f.format {
	case core.FormatJSON:
		data, _ := json.Marshal(result)
		return string(data)
	case core.FormatCSV:
		return fmt.Sprintf("%s,%s,%d,%s", result.IP, result.Status, result.HTTPCode, result.Error)
	default:
		return f.formatTextResult(result)
	}
}

// formatTextResult formats a result in text format with colors
func (f *Formatter) formatTextResult(result core.IPResult) string {
	switch result.Status {
	case "200":
		return fmt.Sprintf("%s[+]%s %s --> %s200 OK%s (%s)",
			f.green, f.nc, result.IP, f.green, f.nc, result.ResponseTime)
	case "3xx":
		if !f.showAll {
			return ""
		}
		return fmt.Sprintf("%s[>]%s %s --> HTTP %d (Redirect)",
			f.yellow, f.nc, result.IP, result.HTTPCode)
	case "timeout":
		if !f.showAll {
			return ""
		}
		return fmt.Sprintf("%s[~]%s %s --> Timeout",
			f.blue, f.nc, result.IP)
	case "error":
		if !f.showAll {
			return ""
		}
		return fmt.Sprintf("%s[-]%s %s --> Error: %s",
			f.red, f.nc, result.IP, result.Error)
	default:
		if !f.showAll {
			return ""
		}
		return fmt.Sprintf("%s[~]%s %s --> HTTP %d",
			f.cyan, f.nc, result.IP, result.HTTPCode)
	}
}

// FormatSummary formats the final scan summary
func (f *Formatter) FormatSummary(summary core.ScanSummary) string {
	switch f.format {
	case core.FormatJSON:
		data, _ := json.MarshalIndent(summary, "", "  ")
		return string(data)
	default:
		return f.formatTextSummary(summary)
	}
}

// formatTextSummary formats summary in text format
func (f *Formatter) formatTextSummary(summary core.ScanSummary) string {
	var sb strings.Builder

	sb.WriteString("\n")
	sb.WriteString(f.cyan + "═══════════════════════════════════════════════════════════════\n")
	sb.WriteString(f.bold + "Scan Results Summary\n" + f.nc)
	sb.WriteString(f.cyan + "═══════════════════════════════════════════════════════════════" + f.nc + "\n")
	sb.WriteString(fmt.Sprintf("%s[+]%s 200 OK Found: %s%d%s\n", f.green, f.nc, f.green, summary.SuccessCount, f.nc))
	sb.WriteString(fmt.Sprintf("%s[*]%s Total Scanned: %s%d%s\n", f.bold, f.nc, f.bold, summary.ScannedIPs, f.nc))

	if summary.SkippedIPs > 0 {
		sb.WriteString(fmt.Sprintf("%s[S]%s WAF IPs Skipped: %s%d%s\n", f.yellow, f.nc, f.yellow, summary.SkippedIPs, f.nc))
	}

	sb.WriteString(fmt.Sprintf("%s[T]%s Duration: %s%.2fs%s\n", f.blue, f.nc, f.blue, summary.Duration.Seconds(), f.nc))

	if summary.Duration.Seconds() > 0 {
		rate := float64(summary.ScannedIPs) / summary.Duration.Seconds()
		sb.WriteString(fmt.Sprintf("%s[R]%s Scan Rate: %s%.2f IPs/s%s\n", f.magenta, f.nc, f.magenta, rate, f.nc))
	}

	sb.WriteString(f.cyan + "═══════════════════════════════════════════════════════════════" + f.nc + "\n\n")

	return sb.String()
}

// FormatCSVHeader returns CSV header row
func (f *Formatter) FormatCSVHeader() string {
	return "IP,Status,HTTPCode,ResponseTime,Error\n"
}

// WriteCSVResults writes results in CSV format
func (f *Formatter) WriteCSVResults(results []*core.IPResult, writer *csv.Writer) error {
	// Write header
	if err := writer.Write([]string{"IP", "Status", "HTTPCode", "ResponseTime", "Error"}); err != nil {
		return err
	}

	// Write results
	for _, r := range results {
		record := []string{
			r.IP,
			r.Status,
			fmt.Sprintf("%d", r.HTTPCode),
			r.ResponseTime,
			r.Error,
		}
		if err := writer.Write(record); err != nil {
			return err
		}
	}

	writer.Flush()
	return writer.Error()
}
