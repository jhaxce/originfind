// Package ip provides file parsing for IP addresses and ranges
package ip

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// ParseInputFile reads IPs, CIDRs, and IP ranges from a file
// Supports:
// - Single IPs: 192.168.1.1
// - CIDR notation: 192.168.1.0/24
// - IP ranges: 192.168.1.1-192.168.1.254
// - Comments (lines starting with #)
// - Blank lines (ignored)
func ParseInputFile(path string) ([]IPRange, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open input file: %w", err)
	}
	defer file.Close()

	var ranges []IPRange
	scanner := bufio.NewScanner(file)
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Try to parse as CIDR
		if strings.Contains(line, "/") {
			r, err := ParseCIDRRange(line)
			if err != nil {
				return nil, fmt.Errorf("line %d: invalid CIDR %q: %w", lineNum, line, err)
			}
			ranges = append(ranges, *r)
			continue
		}

		// Try to parse as IP range (start-end)
		if strings.Contains(line, "-") {
			parts := strings.Split(line, "-")
			if len(parts) != 2 {
				return nil, fmt.Errorf("line %d: invalid IP range format %q (expected start-end)", lineNum, line)
			}
			startIP := strings.TrimSpace(parts[0])
			endIP := strings.TrimSpace(parts[1])

			r, err := ParseIPRange(startIP, endIP)
			if err != nil {
				return nil, fmt.Errorf("line %d: invalid IP range %q: %w", lineNum, line, err)
			}
			ranges = append(ranges, *r)
			continue
		}

		// Parse as single IP
		ipInt, err := ParseIP(line)
		if err != nil {
			return nil, fmt.Errorf("line %d: invalid IP %q: %w", lineNum, line, err)
		}

		ipUint32, err := ToUint32(ipInt)
		if err != nil {
			return nil, fmt.Errorf("line %d: IP must be IPv4: %w", lineNum, err)
		}

		// Single IP becomes a range of 1
		ranges = append(ranges, IPRange{Start: ipUint32, End: ipUint32})
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading file: %w", err)
	}

	if len(ranges) == 0 {
		return nil, fmt.Errorf("no valid IPs or ranges found in file")
	}

	return ranges, nil
}
