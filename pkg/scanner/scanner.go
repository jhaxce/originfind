// Package scanner provides HTTP-based origin IP discovery with concurrent scanning.
package scanner

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jhaxce/origindive/v3/internal/version"
	"github.com/jhaxce/origindive/v3/pkg/core"
	"github.com/jhaxce/origindive/v3/pkg/ip"
	"github.com/jhaxce/origindive/v3/pkg/waf"
)

// Scanner performs HTTP-based origin IP discovery
type Scanner struct {
	config     *core.Config
	client     *http.Client
	wafFilter  *waf.Filter
	mu         sync.Mutex
	cancelFunc context.CancelFunc
}

// New creates a new scanner with the given configuration
func New(config *core.Config) (*Scanner, error) {
	if config == nil {
		return nil, core.ErrInvalidConfig
	}

	// Create HTTP client with timeouts
	client := &http.Client{
		Timeout: config.Timeout,
		Transport: &http.Transport{
			DialContext: (&net.Dialer{
				Timeout: config.ConnectTimeout,
			}).DialContext,
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true, // Required for testing origin servers
			},
			MaxIdleConns:        100,
			MaxIdleConnsPerHost: config.Workers,
			IdleConnTimeout:     30 * time.Second,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // Don't follow redirects
		},
	}

	s := &Scanner{
		config: config,
		client: client,
	}

	// Load WAF filter if enabled
	if config.SkipWAF {
		db, err := waf.LoadWAFDatabase("data/waf_ranges.json")
		if err != nil {
			return nil, fmt.Errorf("failed to load WAF database: %w", err)
		}

		filter, err := waf.NewFilterFromDatabase(db, config.SkipProviders, config.ShowSkipped)
		if err != nil {
			return nil, fmt.Errorf("failed to create WAF filter: %w", err)
		}

		s.wafFilter = filter
	}

	return s, nil
}

// Scan performs the HTTP scanning across the configured IP ranges
func (s *Scanner) Scan(ctx context.Context) (*core.ScanResult, error) {
	// Create cancellable context
	ctx, cancel := context.WithCancel(ctx)
	s.cancelFunc = cancel
	defer cancel()

	result := &core.ScanResult{
		Domain:    s.config.Domain,
		Mode:      s.config.Mode,
		StartTime: time.Now(),
	}

	// Calculate total IPs
	// Convert [][2]uint32 from config to []ip.IPRange
	ranges := make([]ip.IPRange, len(s.config.IPRanges))
	for i, r := range s.config.IPRanges {
		ranges[i] = ip.IPRange{Start: r[0], End: r[1]}
	}

	iterator := ip.NewIterator(ranges)
	totalIPs := iterator.TotalIPs()
	if totalIPs == 0 {
		return nil, fmt.Errorf("no IP ranges to scan")
	}

	// Create channels
	jobs := make(chan uint32, s.config.Workers*2)
	results := make(chan *core.IPResult, s.config.Workers*2)

	// Atomic counters
	var (
		scanned uint64
		skipped uint64
	)

	// Start workers
	var wg sync.WaitGroup
	for i := 0; i < s.config.Workers; i++ {
		wg.Add(1)
		go s.worker(ctx, &wg, jobs, results, &scanned, &skipped)
	}

	// Result collector
	var collectorWg sync.WaitGroup
	collectorWg.Add(1)
	go func() {
		defer collectorWg.Done()
		for ipResult := range results {
			result.AddResult(ipResult)
		}
	}()

	// Feed jobs
	go func() {
		defer close(jobs)
		for {
			ipInt, ok := iterator.NextUint32()
			if !ok {
				break
			}

			select {
			case jobs <- ipInt:
			case <-ctx.Done():
				return
			}
		}
	}()

	// Wait for workers
	wg.Wait()
	close(results)

	// Wait for collector
	collectorWg.Wait()

	// Finalize result
	result.EndTime = time.Now()
	result.Summary.TotalIPs = totalIPs
	result.Summary.ScannedIPs = scanned
	result.Summary.SkippedIPs = skipped
	result.Summary.SuccessCount = uint64(len(result.Success))
	result.Summary.Duration = result.EndTime.Sub(result.StartTime)

	// Add WAF stats if filter was used
	if s.wafFilter != nil {
		stats := s.wafFilter.GetStats()
		result.Summary.WAFStats = stats.ByProvider
	}

	return result, nil
}

// worker processes IP addresses from the jobs channel
func (s *Scanner) worker(ctx context.Context, wg *sync.WaitGroup, jobs <-chan uint32, results chan<- *core.IPResult, scanned, skipped *uint64) {
	defer wg.Done()

	for {
		select {
		case <-ctx.Done():
			return
		case ipInt, ok := <-jobs:
			if !ok {
				return
			}

			// Convert to net.IP
			ipAddr := ip.FromUint32(ipInt)

			// Check WAF filter
			if s.wafFilter != nil {
				shouldSkip, provider := s.wafFilter.ShouldSkip(ipAddr)
				if shouldSkip {
					atomic.AddUint64(skipped, 1)
					if s.config.ShowSkipped {
						results <- &core.IPResult{
							IP:       ipAddr.String(),
							Status:   "skipped",
							Provider: provider,
						}
					}
					continue
				}
			}

			// Scan the IP
			result := s.scanIP(ctx, ipAddr)
			atomic.AddUint64(scanned, 1)

			// Send result
			if s.config.ShowAll || result.Status == "200" {
				results <- result
			}
		}
	}
}

// scanIP performs HTTP request to a single IP
func (s *Scanner) scanIP(ctx context.Context, ipAddr net.IP) *core.IPResult {
	result := &core.IPResult{
		IP: ipAddr.String(),
	}

	// Construct URL
	url := fmt.Sprintf("http://%s", ipAddr.String())

	// Create request
	req, err := http.NewRequestWithContext(ctx, s.config.HTTPMethod, url, nil)
	if err != nil {
		result.Status = "error"
		result.Error = err.Error()
		return result
	}

	// Set Host header
	req.Host = s.config.Domain

	// Set User-Agent
	if !s.config.NoUserAgent {
		req.Header.Set("User-Agent", fmt.Sprintf("origindive/%s", version.Version))
	}

	// Set custom header if specified
	if s.config.CustomHeader != "" {
		// Parse header (format: "Name: Value")
		// Simple implementation - just set as-is
		req.Header.Set("X-Custom", s.config.CustomHeader)
	}

	// Perform request
	startTime := time.Now()
	resp, err := s.client.Do(req)
	result.ResponseTime = time.Since(startTime).String()

	if err != nil {
		// Check for timeout
		if ctx.Err() == context.DeadlineExceeded {
			result.Status = "timeout"
		} else {
			result.Status = "error"
			result.Error = err.Error()
		}
		return result
	}
	defer resp.Body.Close()

	// Record response
	result.HTTPCode = resp.StatusCode

	switch {
	case resp.StatusCode == 200:
		result.Status = "200"
	case resp.StatusCode >= 300 && resp.StatusCode < 400:
		result.Status = "3xx"
	case resp.StatusCode >= 400 && resp.StatusCode < 500:
		result.Status = "4xx"
	case resp.StatusCode >= 500:
		result.Status = "5xx"
	default:
		result.Status = fmt.Sprintf("%d", resp.StatusCode)
	}

	return result
}

// Stop cancels the ongoing scan
func (s *Scanner) Stop() {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.cancelFunc != nil {
		s.cancelFunc()
	}
}
