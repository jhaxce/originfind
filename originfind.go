// originfind - Security Analysis Tool for Origin IP Discovery
//
// This tool helps security researchers discover real origin server IPs
// hidden behind CDN/WAF services by scanning IP ranges with custom Host headers.
//
// Author: jhaxce
// Repository: github.com/jhaxce/originfind
// License: MIT
//
// Build:
//
//	go build -o originfind originfind.go
//
// Usage Examples:
//
//	originfind example.com 192.168.1.1 192.168.1.254
//	originfind -d example.com -n 192.168.1.0/24 -j 10
//	originfind -d example.com -i targets.txt -n /24 -j 20
//
// Features:
//   - Multi-threaded IP range scanning
//   - CIDR notation support with auto-expansion
//   - Input file with mixed IPs and CIDR ranges
//   - CIDR mask application to input file IPs
//   - Colored terminal output with plain-text mode
//   - Custom HTTP headers and methods
//   - Configurable timeouts and workers
package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Version of the application
const version = "2.5.0"

// =============================================================================
// CLI FLAGS
// =============================================================================

var (
	// Target configuration
	domain = flag.String("d", "", "Target domain (e.g., example.com)")

	// IP range modes
	ipStart   = flag.String("s", "", "Start IP for range scan (e.g., 23.192.228.80)")
	ipEnd     = flag.String("e", "", "End IP for range scan (e.g., 23.192.228.90)")
	subnet    = flag.String("n", "", "CIDR subnet (e.g., 192.168.0.0/24) or mask for input file (e.g., /24)")
	inputFile = flag.String("i", "", "Input file with IPs/CIDRs, one per line")

	// HTTP configuration
	timeoutSec     = flag.Int("t", 5, "HTTP request timeout in seconds")
	connectTimeout = flag.Int("c", 3, "TCP connection timeout in seconds")
	customHeader   = flag.String("H", "", "Custom HTTP header (format: \"Name: value\")")
	httpMethod     = flag.String("m", "GET", "HTTP method (GET, HEAD, POST)")

	// Performance configuration
	threads = flag.Int("j", 1, "Number of parallel workers (recommended: 5-20)")

	// Output configuration
	quiet       = flag.Bool("q", false, "Quiet mode - minimal output")
	showAll     = flag.Bool("a", false, "Show all responses, not just 200 OK")
	saveOutput  = flag.String("o", "", "Save results to file")
	plain       = flag.Bool("p", false, "Plain text output - no colors")
	noColorFlag = flag.Bool("no-color", false, "Disable colored output")

	// Information flags
	showVersion = flag.Bool("V", false, "Show version and exit")
	helpFlag    = flag.Bool("h", false, "Show help message")
)

// =============================================================================
// COLOR CONFIGURATION
// =============================================================================

var (
	RED, GREEN, YELLOW, BLUE, CYAN, MAGENTA, BOLD, NC string
)

// initColors initializes ANSI color codes based on terminal capability
func initColors(enabled bool) {
	if !enabled {
		RED, GREEN, YELLOW, BLUE, CYAN, MAGENTA, BOLD, NC = "", "", "", "", "", "", "", ""
		return
	}
	RED = "\033[31m"
	GREEN = "\033[32m"
	YELLOW = "\033[33m"
	BLUE = "\033[34m"
	CYAN = "\033[36m"
	MAGENTA = "\033[35m"
	BOLD = "\033[1m"
	NC = "\033[0m"
}

// shouldUseColors determines if colored output should be enabled
// based on flags, environment variables, and terminal detection
func shouldUseColors() bool {
	// Explicit disable via flags or environment
	if *plain || *noColorFlag || os.Getenv("NO_COLOR") == "1" {
		return false
	}

	// Check if stdout is connected to a terminal (TTY)
	fileInfo, err := os.Stdout.Stat()
	if err == nil && (fileInfo.Mode()&os.ModeCharDevice) != 0 {
		return true // It's a terminal, enable colors
	}

	// Default: enable on Unix-like systems (Linux, macOS, WSL)
	return runtime.GOOS == "linux" || runtime.GOOS == "darwin"
}

// =============================================================================
// USAGE AND HELP
// =============================================================================

// usage displays the help message with ASCII banner and usage examples
func usage() {
	fmt.Printf(`%s════════════════════════════════════════════════════════════════%s
              _       _       _____           __
  ____  _____(_)___ _(_)___  / __(_)___  ____/ /
 / __ \/ ___/ / __ `+"`"+` / / __ \/ /_/ / __ \/ __  / 
/ /_/ / /  / / /_/ / / / / / __/ / / / / /_/ /  
\____/_/  /_/\__, /_/_/ /_/_/ /_/_/ /_/\__,_/   
            /____/

%soriginfind v%s - Origin IP Discovery Tool%s
%sFind real origin servers behind CDN/WAF protection%s
%s════════════════════════════════════════════════════════════════%s

USAGE:
  %s# IP range mode (start to end):%s
  originfind -d <domain> -s <start_ip> -e <end_ip>
  originfind <domain> <start_ip> <end_ip>

  %s# CIDR subnet mode:%s
  originfind -d <domain> -n <CIDR>
  originfind <domain> <CIDR>

  %s# Input file mode (mixed IPs and CIDRs):%s
  originfind -d <domain> -i <file>
  
  %s# Input file with CIDR mask (applies /mask to single IPs):%s
  originfind -d <domain> -i <file> -n /24

OPTIONS:
`, CYAN, NC, CYAN, version, NC, CYAN, NC, CYAN, NC, BOLD, NC, BOLD, NC, BOLD, NC, BOLD, NC)
	flag.PrintDefaults()
	fmt.Printf(`
EXAMPLES:
  %s# Basic IP range scan%s
  originfind example.com 23.192.228.80 23.192.228.90

  %s# CIDR subnet with 10 parallel workers%s
  originfind -d example.com -n 23.192.228.0/24 -j 10

  %s# Input file with mixed IPs and CIDR ranges%s
  originfind -d example.com -i targets.txt -j 20 -a -o results.txt

  %s# Apply /24 mask to all single IPs in input file%s
  originfind -d example.com -i single-ips.txt -n /24 -j 15
  
  %s# Show all responses (200, 3xx, 4xx, 5xx, timeouts, errors)%s
  originfind -d example.com -n 192.168.1.0/24 -a

  %s# Plain text output for piping or scripting%s
  originfind -d example.com -i targets.txt -p -j 15 | grep "200 OK"

  %s# Custom timeout and HTTP method%s
  originfind -d example.com -n 10.0.0.0/24 -t 10 -c 5 -m HEAD

INPUT FILE FORMAT:
  %s# targets.txt - One IP or CIDR per line, comments allowed%s
  # Cloudflare IP ranges
  104.16.0.0/24
  104.17.0.0/24
  
  # Single IPs (will use /mask if -n flag provided)
  192.168.1.100
  10.0.0.50
  
  # Mixed formats supported
  203.0.113.0/28

CIDR REFERENCE:
  /32 = 1 IP       /28 = 16 IPs     /24 = 256 IPs    /20 = 4096 IPs
  /31 = 2 IPs      /27 = 32 IPs     /23 = 512 IPs    /19 = 8192 IPs
  /30 = 4 IPs      /26 = 64 IPs     /22 = 1024 IPs   /18 = 16384 IPs
  /29 = 8 IPs      /25 = 128 IPs    /21 = 2048 IPs   /17 = 32768 IPs

NOTES:
  • Finds origin IPs by testing Host header against target IPs
  • Input file supports mixed single IPs and CIDR ranges
  • Use -n with -i to apply CIDR mask to all single IPs in file
  • Recommended workers: 5-20 for internet scans, 20-50 for local networks
  • Only scan systems you are authorized to test
  • For WSL/Kali terminals, colors are automatically enabled

AUTHOR:
  jhaxce - https://github.com/jhaxce/originfind

`, BOLD, NC, BOLD, NC, BOLD, NC, BOLD, NC, BOLD, NC, BOLD, NC, BOLD, NC, BOLD, NC)
}

// =============================================================================
// VALIDATION AND UTILITY FUNCTIONS
// =============================================================================

// isValidDomain performs basic validation on the domain string
// Returns true if the domain format appears valid
func isValidDomain(d string) bool {
	if d == "" {
		return false
	}
	// Reject domains with invalid characters
	if strings.ContainsAny(d, " /\\:") {
		return false
	}
	// Domain shouldn't start or end with hyphen
	if strings.HasPrefix(d, "-") || strings.HasSuffix(d, "-") {
		return false
	}
	return true
}

// ipToUint32 converts a net.IP to uint32 for range iteration
// Returns 0 if the IP is not a valid IPv4 address
func ipToUint32(ip net.IP) uint32 {
	ip = ip.To4()
	if ip == nil {
		return 0
	}
	return uint32(ip[0])<<24 | uint32(ip[1])<<16 | uint32(ip[2])<<8 | uint32(ip[3])
}

// uint32ToIP converts a uint32 back to net.IP
func uint32ToIP(n uint32) net.IP {
	return net.IPv4(byte(n>>24), byte(n>>16), byte(n>>8), byte(n))
}

// =============================================================================
// INPUT FILE PARSING
// =============================================================================

// parseInputFile reads and parses an input file containing IPs and/or CIDR ranges
//
// Parameters:
//   - filename: path to the input file
//   - cidrMask: optional CIDR mask (e.g., "/24") to apply to single IPs
//
// The file format supports:
//   - Single IP addresses (e.g., 192.168.1.100)
//   - CIDR notation (e.g., 192.168.1.0/24)
//   - Comments (lines starting with #)
//   - Empty lines (ignored)
//
// If cidrMask is provided (e.g., "/24"), it will be applied to all single IPs.
// Lines that already contain CIDR notation keep their original mask.
//
// Returns:
//   - A slice of IP ranges as [start, end] pairs (uint32)
//   - An error if the file cannot be read or contains no valid entries
func parseInputFile(filename string, cidrMask string) ([][2]uint32, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var ranges [][2]uint32
	scanner := bufio.NewScanner(file)
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Process CIDR notation (already has slash)
		if strings.Contains(line, "/") {
			ip, ipNet, err := net.ParseCIDR(line)
			if err != nil {
				fmt.Printf("%sWarning:%s Invalid CIDR at line %d: %s (skipping)\n", YELLOW, NC, lineNum, line)
				continue
			}
			ones, bits := ipNet.Mask.Size()
			if bits != 32 {
				fmt.Printf("%sWarning:%s Only IPv4 supported at line %d (skipping)\n", YELLOW, NC, lineNum)
				continue
			}

			// Calculate IP range from CIDR
			network := ipToUint32(ip.Mask(ipNet.Mask))
			var first, last uint32
			if ones < 31 {
				// Standard subnet: skip network and broadcast addresses
				first = network + 1
				last = ipToUint32(ipNet.IP) | ^ipToUint32(net.IP(ipNet.Mask))
				last = last - 1
			} else if ones == 31 {
				// /31 point-to-point: both IPs usable
				first = network
				last = network + 1
			} else { // /32
				// Single host
				first = network
				last = network
			}
			ranges = append(ranges, [2]uint32{first, last})
		} else {
			// Process single IP address
			ip := net.ParseIP(line)
			if ip == nil {
				fmt.Printf("%sWarning:%s Invalid IP at line %d: %s (skipping)\n", YELLOW, NC, lineNum, line)
				continue
			}
			ipInt := ipToUint32(ip)
			if ipInt == 0 {
				fmt.Printf("%sWarning:%s Invalid IPv4 at line %d (skipping)\n", YELLOW, NC, lineNum)
				continue
			}

			// Apply CIDR mask if provided
			if cidrMask != "" {
				cidrNotation := line + cidrMask
				ip, ipNet, err := net.ParseCIDR(cidrNotation)
				if err != nil {
					fmt.Printf("%sWarning:%s Invalid CIDR mask %s for IP at line %d (using single IP)\n",
						YELLOW, NC, cidrMask, lineNum)
					ranges = append(ranges, [2]uint32{ipInt, ipInt})
					continue
				}
				ones, bits := ipNet.Mask.Size()
				if bits != 32 {
					fmt.Printf("%sWarning:%s Only IPv4 supported at line %d (skipping)\n", YELLOW, NC, lineNum)
					continue
				}

				// Calculate expanded CIDR range
				network := ipToUint32(ip.Mask(ipNet.Mask))
				var first, last uint32
				if ones < 31 {
					first = network + 1
					last = ipToUint32(ipNet.IP) | ^ipToUint32(net.IP(ipNet.Mask))
					last = last - 1
				} else if ones == 31 {
					first = network
					last = network + 1
				} else { // /32
					first = network
					last = network
				}
				ranges = append(ranges, [2]uint32{first, last})
			} else {
				// No mask: just the single IP
				ranges = append(ranges, [2]uint32{ipInt, ipInt})
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	if len(ranges) == 0 {
		return nil, fmt.Errorf("no valid IPs or CIDRs found in file")
	}

	return ranges, nil
}

// =============================================================================
// SCANNING LOGIC
// =============================================================================

// result represents the outcome of scanning a single IP address
type result struct {
	Status   string // "200", "3xx", "xxx", "000" (timeout), "err" (error)
	IP       string // IP address that was scanned
	HTTPCode int    // HTTP status code (if applicable)
	Err      error  // Error details (if applicable)
}

// worker is a goroutine that processes IP addresses from the jobs channel
// and sends results to the results channel. It performs HTTP requests with
// custom Host headers to test if the IP responds to the target domain.
//
// Parameters:
//   - ctx: context for cancellation
//   - wg: wait group for coordination
//   - jobs: channel receiving IP addresses (as uint32) to scan
//   - results: channel for sending scan results
//   - client: configured HTTP client
//   - domain: target domain for Host header
//   - header: optional custom HTTP header
//   - method: HTTP method (GET, HEAD, POST, etc.)
func worker(ctx context.Context, wg *sync.WaitGroup, jobs <-chan uint32, results chan<- result,
	client *http.Client, domain string, header string, method string) {
	defer wg.Done()

	for {
		select {
		case <-ctx.Done():
			return
		case ipInt, ok := <-jobs:
			if !ok {
				return
			}
			ip := uint32ToIP(ipInt).String()

			// Build HTTP request
			req, err := http.NewRequest(method, "http://"+ip+"/", nil)
			if err != nil {
				results <- result{Status: "err", IP: ip, Err: err}
				continue
			}

			// Set Host header to target domain (this is the key to finding origin)
			req.Host = domain
			req.Header.Set("User-Agent", fmt.Sprintf("originfind/%s", version))

			// Add custom header if provided
			if header != "" {
				parts := strings.SplitN(header, ":", 2)
				if len(parts) == 2 {
					req.Header.Set(strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]))
				} else {
					req.Header.Set("X-Custom-Header", header)
				}
			}

			// Execute HTTP request
			resp, err := client.Do(req)
			if err != nil {
				// Classify error type
				if os.IsTimeout(err) || strings.Contains(err.Error(), "Client.Timeout") ||
					strings.Contains(err.Error(), "i/o timeout") {
					results <- result{Status: "000", IP: ip, Err: err}
				} else {
					results <- result{Status: "err", IP: ip, Err: err}
				}
				continue
			}

			// Process response
			code := resp.StatusCode
			_ = resp.Body.Close()

			if code == 200 {
				results <- result{Status: "200", IP: ip, HTTPCode: code}
			} else if code >= 300 && code < 400 {
				results <- result{Status: "3xx", IP: ip, HTTPCode: code}
			} else {
				results <- result{Status: "xxx", IP: ip, HTTPCode: code}
			}
		}
	}
}

func main() {
	// Initialize colors FIRST before anything else
	initColors(shouldUseColors())

	flag.Usage = usage
	flag.Parse()

	// Quick flags behavior
	if *helpFlag {
		usage()
		return
	}
	if *showVersion {
		fmt.Printf("originfind v%s\n", version)
		return
	}

	// support positional args: domain start end
	args := flag.Args()
	if len(args) >= 1 && *domain == "" {
		*domain = args[0]
	}
	if len(args) >= 3 && *ipStart == "" && *ipEnd == "" && *subnet == "" && *inputFile == "" {
		*ipStart = args[1]
		*ipEnd = args[2]
	} else if len(args) == 2 && *ipStart == "" && *ipEnd == "" && *subnet == "" && *inputFile == "" {
		// Check if second arg is CIDR notation
		if strings.Contains(args[1], "/") {
			*subnet = args[1]
		}
	}

	// Basic validation
	if *domain == "" {
		fmt.Println(RED + "Error: Domain is required (-d)" + NC)
		usage()
		os.Exit(1)
	}
	if !isValidDomain(*domain) {
		fmt.Printf("%sError: Invalid domain format: %s%s\n", RED, *domain, NC)
		os.Exit(1)
	}

	var ipRanges [][2]uint32
	var ipCount uint64

	// Determine input mode
	if *inputFile != "" {
		// File input mode
		if *ipStart != "" || *ipEnd != "" {
			fmt.Printf("%sError: Cannot use -i with -s or -e%s\n", RED, NC)
			os.Exit(1)
		}

		// Allow -n with -i to apply CIDR mask to single IPs in file
		cidrMask := ""
		if *subnet != "" {
			// Validate it's a CIDR mask format (starts with /)
			if !strings.HasPrefix(*subnet, "/") {
				fmt.Printf("%sError: When using -i with -n, provide CIDR mask (e.g., /24)%s\n", RED, NC)
				os.Exit(1)
			}
			cidrMask = *subnet
		}

		ranges, err := parseInputFile(*inputFile, cidrMask)
		if err != nil {
			fmt.Printf("%sError: Failed to read input file: %v%s\n", RED, err, NC)
			os.Exit(1)
		}
		ipRanges = ranges
		for _, r := range ipRanges {
			ipCount += uint64(r[1]-r[0]) + 1
		}
	} else if *subnet != "" {
		// parse CIDR
		ip, ipNet, err := net.ParseCIDR(*subnet)
		if err != nil {
			fmt.Printf("%sError: Invalid CIDR: %s%s\n", RED, *subnet, NC)
			os.Exit(1)
		}
		ones, bits := ipNet.Mask.Size()
		if bits != 32 {
			fmt.Printf("%sError: Only IPv4 CIDR supported%s\n", RED, NC)
			os.Exit(1)
		}
		network := ipToUint32(ip.Mask(ipNet.Mask))
		// calculate range: skip network and broadcast for typical subnets (unless /31 or /32)
		var first, last uint32
		if ones < 31 {
			first = network + 1
			last = ipToUint32(ipNet.IP) | ^ipToUint32(net.IP(ipNet.Mask))
			last = last - 1
		} else if ones == 31 {
			// two usable IPs (no skipping)
			first = network
			last = network + 1
		} else { // /32
			first = network
			last = network
		}
		ipRanges = [][2]uint32{{first, last}}
		ipCount = uint64(last-first) + 1
	} else {
		// range mode: both start and end required
		if *ipStart == "" || *ipEnd == "" {
			fmt.Println(RED + "Error: Either use -i (file), -n (CIDR), or -s/-e (range)" + NC)
			usage()
			os.Exit(1)
		}
		startIP := net.ParseIP(*ipStart)
		endIPAddr := net.ParseIP(*ipEnd)
		if startIP == nil || endIPAddr == nil {
			fmt.Printf("%sError: Invalid IP format%s\n", RED, NC)
			os.Exit(1)
		}
		startInt := ipToUint32(startIP)
		endInt := ipToUint32(endIPAddr)
		if startInt > endInt {
			fmt.Printf("%sError: Start IP greater than End IP%s\n", RED, NC)
			os.Exit(1)
		}
		ipRanges = [][2]uint32{{startInt, endInt}}
		ipCount = uint64(endInt-startInt) + 1
	}

	if ipCount == 0 {
		fmt.Printf("%sError: No IPs to scan%s\n", RED, NC)
		os.Exit(1)
	}
	if ipCount > 65536 {
		// Warn and ask for confirmation
		fmt.Printf("%sWarning: Large IP range (%d IPs). This may take a long time.%s\n", YELLOW, ipCount, NC)
		fmt.Print("Continue? (y/n) ")
		var resp string
		fmt.Scanln(&resp)
		if !strings.HasPrefix(strings.ToLower(strings.TrimSpace(resp)), "y") {
			fmt.Println("Scan cancelled")
			os.Exit(0)
		}
	}

	if *threads < 1 {
		*threads = 1
	}

	if *threads > 200 {
		fmt.Printf("%sWarning: Very large thread count (%d). This may be aggressive.%s\n", YELLOW, *threads, NC)
	}

	// Output header unless quiet
	if !*quiet {
		fmt.Println()
		fmt.Println("════════════════════════════════════════════════════════════")
		fmt.Printf("originfind v%s\n", version)
		fmt.Println("════════════════════════════════════════════════════════════")
		fmt.Printf("[*] Domain: %s\n", *domain)
		if *inputFile != "" {
			fmt.Printf("[*] Input File: %s\n", *inputFile)
			fmt.Printf("[*] IP Ranges: %d range(s)\n", len(ipRanges))
		} else if *subnet != "" {
			fmt.Printf("[*] CIDR Subnet: %s\n", *subnet)
			fmt.Printf("[*] IP Range: %s - %s\n", uint32ToIP(ipRanges[0][0]).String(), uint32ToIP(ipRanges[0][1]).String())
		} else {
			fmt.Printf("[*] IP Range: %s - %s\n", uint32ToIP(ipRanges[0][0]).String(), uint32ToIP(ipRanges[0][1]).String())
		}
		fmt.Printf("[*] Total IPs to check: %d\n", ipCount)
		fmt.Printf("[*] HTTP Method: %s\n", *httpMethod)
		fmt.Printf("[*] Timeout: %ds\n", *timeoutSec)
		fmt.Printf("[*] Connect Timeout: %ds\n", *connectTimeout)
		fmt.Printf("[*] Parallel Workers: %d\n", *threads)
		if *customHeader != "" {
			fmt.Printf("[*] Custom Header: %s\n", *customHeader)
		}
		if *plain || *noColorFlag {
			fmt.Printf("[*] Output Mode: Plain Text\n")
		} else if RED == "" {
			fmt.Printf("[*] Output Mode: No color\n")
		} else {
			fmt.Printf("[*] Output Mode: Colored\n")
		}
		fmt.Println("════════════════════════════════════════════════════════════")
		fmt.Println()
	}

	// Prepare results output file if requested
	var outFile *os.File
	var err error
	if *saveOutput != "" {
		outFile, err = os.Create(*saveOutput)
		if err != nil {
			fmt.Printf("%sError: Cannot create output file: %v%s\n", RED, err, NC)
			os.Exit(1)
		}
		defer outFile.Close()
	}

	// Create HTTP client with custom transport and timeouts
	dialer := &net.Dialer{
		Timeout:   time.Duration(*connectTimeout) * time.Second,
		KeepAlive: 30 * time.Second,
	}

	transport := &http.Transport{
		DialContext:         dialer.DialContext,
		ForceAttemptHTTP2:   false,
		MaxIdleConns:        100,
		IdleConnTimeout:     30 * time.Second,
		TLSHandshakeTimeout: 5 * time.Second,
		DisableCompression:  true,
		// Skip TLS verify if someone points to HTTPS later; but we use http:// so not relevant.
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   time.Duration(*timeoutSec) * time.Second,
		// Don't follow redirects - capture 3xx
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// Prepare channels and workers
	jobs := make(chan uint32, *threads*2)
	results := make(chan result, *threads*2)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var wg sync.WaitGroup

	// Start workers
	for i := 0; i < *threads; i++ {
		wg.Add(1)
		go worker(ctx, &wg, jobs, results, client, *domain, *customHeader, strings.ToUpper(*httpMethod))
	}

	// Launch result collector goroutine
	var totalScanned uint64
	var successCount uint64
	var redirectsCount uint64
	var otherCount uint64
	var timeoutCount uint64
	var errCount uint64

	var resultsLock sync.Mutex
	var printedLines []string

	collectorDone := make(chan struct{})
	go func() {
		for res := range results {
			atomic.AddUint64(&totalScanned, 1)
			line := ""
			switch res.Status {
			case "200":
				atomic.AddUint64(&successCount, 1)
				line = fmt.Sprintf("%s[+]%s %s --> %s200 OK%s", GREEN, NC, res.IP, GREEN, NC)
			case "3xx":
				atomic.AddUint64(&redirectsCount, 1)
				if *showAll {
					line = fmt.Sprintf("%s[>]%s %s --> HTTP %d (Redirect)", YELLOW, NC, res.IP, res.HTTPCode)
				}
			case "000":
				atomic.AddUint64(&timeoutCount, 1)
				if *showAll {
					line = fmt.Sprintf("%s[~]%s %s --> No Response/Timeout (%v)", BLUE, NC, res.IP, res.Err)
				}
			case "xxx":
				atomic.AddUint64(&otherCount, 1)
				if *showAll {
					line = fmt.Sprintf("%s[~]%s %s --> HTTP %d", CYAN, NC, res.IP, res.HTTPCode)
				}
			case "err":
				atomic.AddUint64(&errCount, 1)
				if *showAll {
					line = fmt.Sprintf("%s[-]%s %s --> Error: %v", RED, NC, res.IP, res.Err)
				}
			default:
				// unknown
				if *showAll {
					line = fmt.Sprintf("%s[?]%s %s --> %v", MAGENTA, NC, res.IP, res.Err)
				}
			}

			// Output line if not quiet and line is non-empty (either success or showAll)
			if line != "" && !*quiet {
				fmt.Println(line)
			}
			// Save to output file (cleaner format like bash script)
			if outFile != nil && line != "" {
				// Strip color codes for file output
				cleanLine := line
				for _, color := range []string{RED, GREEN, YELLOW, BLUE, CYAN, MAGENTA, BOLD, NC} {
					cleanLine = strings.ReplaceAll(cleanLine, color, "")
				}
				fmt.Fprintln(outFile, cleanLine)
			}

			// keep printed lines in memory for potential later use (not required)
			if line != "" {
				resultsLock.Lock()
				printedLines = append(printedLines, line)
				resultsLock.Unlock()
			}
		}
		close(collectorDone)
	}()

	// Feed jobs from all IP ranges
	startTime := time.Now()
	go func() {
		for _, r := range ipRanges {
			for ip := r[0]; ip <= r[1]; ip++ {
				jobs <- ip
			}
		}
		close(jobs)
	}()

	// Wait for workers to finish
	wg.Wait()
	// All workers done, close results channel and wait for collector
	close(results)
	<-collectorDone
	endTime := time.Now()
	elapsed := endTime.Sub(startTime).Seconds()

	// Summary output
	if !*quiet {
		fmt.Println()
		fmt.Printf("%s═══════════════════════════════════════════════════════════════%s\n", CYAN, NC)
		fmt.Printf("%sScan Results Summary%s\n", BOLD, NC)
		fmt.Printf("%s═══════════════════════════════════════════════════════════════%s\n", CYAN, NC)
		fmt.Printf("%s[+]%s 200 OK Found: %s%d%s\n", GREEN, NC, GREEN, atomic.LoadUint64(&successCount), NC)
		fmt.Printf("%s[>]%s Redirects (3xx): %s%d%s\n", YELLOW, NC, YELLOW, atomic.LoadUint64(&redirectsCount), NC)
		fmt.Printf("%s[~]%s Other Responses: %s%d%s\n", CYAN, NC, CYAN, atomic.LoadUint64(&otherCount), NC)
		fmt.Printf("%s[-]%s Timeout/Error: %s%d%s\n", RED, NC, RED, atomic.LoadUint64(&timeoutCount)+atomic.LoadUint64(&errCount), NC)
		fmt.Printf("%s[*]%s Total Scanned: %s%d%s\n", BOLD, NC, BOLD, atomic.LoadUint64(&totalScanned), NC)
		fmt.Printf("%s[T]%s Elapsed Time: %s%.2fs%s\n", BLUE, NC, BLUE, elapsed, NC)
		if elapsed > 0 {
			rate := float64(atomic.LoadUint64(&totalScanned)) / elapsed
			fmt.Printf("%s[S]%s Scan Rate: %s%.2f IPs/sec%s (%d worker(s))\n", MAGENTA, NC, MAGENTA, rate, NC, *threads)
		}
		fmt.Printf("%s═══════════════════════════════════════════════════════════════%s\n", CYAN, NC)
		fmt.Println()
	}

	// Close output file if any
	if outFile != nil {
		fmt.Printf("[*] Results saved to: %s\n", *saveOutput)
	}

	// set exit code
	if atomic.LoadUint64(&successCount) > 0 {
		os.Exit(0)
	} else {
		os.Exit(1)
	}
}
