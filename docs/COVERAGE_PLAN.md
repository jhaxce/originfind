# Code Coverage Improvement Plan - Target: 100%

## Current State (47.7% overall)

### Critical Priority (0-50% coverage)
1. **cmd/origindive**: 0.0% - Skip (main packages are typically not tested)
2. **pkg/update**: 0.0% - Skip (requires complex HTTP mocking, low ROI)
3. **pkg/passive/securitytrails**: 34.2% ✅ Target
4. **pkg/passive/virustotal**: 42.3% ✅ Target
5. **pkg/passive/zoomeye**: 43.1% ✅ Target
6. **pkg/passive/ct**: 48.2% ✅ Target
7. **pkg/passive/dnsdumpster**: 48.5% ✅ Target
8. **pkg/passive/api**: 49.0% ✅ Target

### Medium Priority (50-75%)
9. **pkg/passive/shodan**: 52.7%
10. **pkg/asn**: 53.1%
11. **pkg/passive/viewdns**: 54.8%
12. **pkg/scanner**: 56.1%
13. **pkg/proxy**: 64.0%
14. **pkg/passive/wayback**: 66.7%
15. **pkg/core**: 69.4%

### Low Priority (75%+)
16. **pkg/ip**: 74.4%
17. **pkg/waf**: 76.8%
18. **pkg/output**: 80.6%
19. **pkg/passive/dns**: 94.1%
20. **pkg/passive/scoring**: 94.8%
21. **pkg/passive/subdomain**: 100.0% ✅ Complete!

## Test Strategy

### For Passive Source Packages (API Integrations)

Each passive source (securitytrails, virustotal, zoomeye, etc.) follows similar patterns:

**What to Test:**
1. **HTTP Request Building**
   - Correct URL formation
   - Headers (API keys, User-Agent, Accept)
   - Request method (GET/POST)

2. **Response Parsing**
   - Successful responses (200 OK)
   - Error responses (4xx, 5xx)
   - Invalid JSON
   - Missing fields

3. **Error Handling**
   - Network errors
   - Timeouts
   - Rate limiting (429)
   - Authentication errors (401, 403)
   - API-specific errors

4. **Key Rotation**
   - Multiple keys provided
   - Fallback to next key on rate limit
   - All keys exhausted error

5. **Data Validation**
   - IPv4 validation
   - Empty result handling
   - Deduplication

**Test Template:**
```go
func TestSearch_Success(t *testing.T) {
    server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        // Verify headers
        if r.Header.Get("API-Key") == "" {
            t.Error("API key header missing")
        }
        
        // Return mock JSON response
        w.WriteHeader(http.StatusOK)
        json.NewEncoder(w).Encode(mockResponse)
    }))
    defer server.Close()
    
    // Temporarily replace API endpoint
    old := apiEndpoint
    apiEndpoint = server.URL
    defer func() { apiEndpoint = old }()
    
    // Test function
    ips, err := Search(ctx, "example.com", []string{"testkey"}, 5*time.Second)
    if err != nil {
        t.Fatalf("unexpected error: %v", err)
    }
    if len(ips) != expectedCount {
        t.Errorf("got %d IPs, want %d", len(ips), expectedCount)
    }
}

func TestSearch_HTTPError(t *testing.T) {
    server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        w.WriteHeader(http.StatusInternalServerError)
    }))
    defer server.Close()
    
    _, err := Search(ctx, "example.com", []string{"testkey"}, 5*time.Second)
    if err == nil {
        t.Error("expected error for 500 status, got nil")
    }
}

func TestSearch_RateLimit(t *testing.T) {
    callCount := 0
    server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        if callCount == 0 {
            callCount++
            w.WriteHeader(http.StatusTooManyRequests)
            return
        }
        w.WriteHeader(http.StatusOK)
        json.NewEncoder(w).Encode(mockResponse)
    }))
    defer server.Close()
    
    // Should try second key after rate limit on first
    ips, err := Search(ctx, "example.com", []string{"key1", "key2"}, 5*time.Second)
    if err != nil {
        t.Fatalf("should succeed with second key: %v", err)
    }
}

func TestSearch_InvalidJSON(t *testing.T) {
    server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        w.WriteHeader(http.StatusOK)
        w.Write([]byte("not json"))
    }))
    defer server.Close()
    
    _, err := Search(ctx, "example.com", []string{"testkey"}, 5*time.Second)
    if err == nil {
        t.Error("expected error for invalid JSON")
    }
}

func TestSearch_Timeout(t *testing.T) {
    server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        time.Sleep(2 * time.Second) // Longer than test timeout
    }))
    defer server.Close()
    
    ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
    defer cancel()
    
    _, err := Search(ctx, "example.com", []string{"testkey"}, 100*time.Millisecond)
    if err == nil {
        t.Error("expected timeout error")
    }
}
```

### For Core Packages

**pkg/core** (69.4%):
- Test all config loading scenarios (YAML parsing, validation)
- Test config merging (CLI overrides file)
- Test error cases (invalid values, missing required fields)
- Test ScanMode, OutputFormat enums
- Test GlobalConfig loading, saving

**pkg/ip** (74.4%):
- Test edge cases for CIDR parsing (/31, /32, /0)
- Test IP range iteration (single IP, large ranges)
- Test file parsing (comments, blank lines, invalid entries)
- Test IPv4 validation (reject IPv6, invalid formats)

**pkg/scanner** (56.1%):
- Test worker pool behavior (1 worker, 100 workers)
- Test cancellation (context timeout, cancel)
- Test WAF integration (skip filtered IPs)
- Test HTTP methods (GET, POST, HEAD)
- Test redirect handling
- Test proxy rotation

**pkg/waf** (76.8%):
- Test range matching (in range, out of range, edge cases)
- Test provider filtering (skip specific providers)
- Test custom range loading (JSON, text formats)
- Test database updates (API calls, file writing)

**pkg/proxy** (64.0%):
- Test proxy fetching from public lists
- Test proxy validation (connect test)
- Test proxy rotation (sequential, random)
- Test SOCKS5 vs HTTP proxies
- Test Webshare.io API integration

### For ASN Package

**pkg/asn** (53.1%):
- Test ASN lookup (valid ASN, invalid ASN)
- Test prefix parsing (AS4775 vs 4775)
- Test CIDR extraction from ASN
- Test multiple ASNs (comma-separated)
- Test API errors, timeouts

## Quick Win Packages (Highest Impact)

### Phase 1: Passive Sources (34-49%)
Focus on 6 packages that will move overall coverage significantly:
1. securitytrails (34.2% → 100%) = +4.1%
2. virustotal (42.3% → 100%) = +3.6%
3. zoomeye (43.1% → 100%) = +3.5%
4. ct (48.2% → 100%) = +3.2%
5. dnsdumpster (48.5% → 100%) = +3.2%
6. api (49.0% → 100%) = +3.2%

**Total Impact**: ~20% overall coverage increase

### Phase 2: Medium Packages (50-69%)
1. shodan (52.7% → 100%) = +2.9%
2. asn (53.1% → 100%) = +2.9%
3. viewdns (54.8% → 100%) = +2.8%
4. scanner (56.1% → 100%) = +2.7%
5. proxy (64.0% → 100%) = +2.2%
6. wayback (66.7% → 100%) = +2.1%
7. core (69.4% → 100%) = +1.9%

**Total Impact**: ~17% overall coverage increase

### Phase 3: Polish (74-94%)
1. ip (74.4% → 100%) = +1.6%
2. waf (76.8% → 100%) = +1.4%
3. output (80.6% → 100%) = +1.2%
4. dns (94.1% → 100%) = +0.4%
5. scoring (94.8% → 100%) = +0.3%

**Total Impact**: ~4.9% overall coverage increase

## Realistic Target

**Skip:**
- cmd/origindive (0%) - main packages typically not tested
- pkg/update (0%) - complex HTTP mocking, low ROI

**Achievable Coverage**: ~95%+ overall
- Phase 1 (passive sources): 47.7% → 67.7%
- Phase 2 (medium packages): 67.7% → 84.7%
- Phase 3 (polish): 84.7% → 89.6%
- Additional edge cases: 89.6% → 95%+

## Implementation Approach

### 1. Create Test Helpers
```go
// testhelpers/http.go
func MockHTTPServer(handler http.HandlerFunc) *httptest.Server {
    return httptest.NewServer(handler)
}

func MockSuccessResponse(data interface{}) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        w.WriteHeader(http.StatusOK)
        json.NewEncoder(w).Encode(data)
    }
}

func MockErrorResponse(statusCode int, message string) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        w.WriteHeader(statusCode)
        w.Write([]byte(message))
    }
}
```

### 2. Use Table-Driven Tests
```go
func TestFunction(t *testing.T) {
    tests := []struct{
        name string
        input string
        want string
        wantErr bool
    }{
        // Test cases here
    }
    
    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            got, err := Function(tt.input)
            if (err != nil) != tt.wantErr {
                t.Errorf("error = %v, wantErr %v", err, tt.wantErr)
            }
            if got != tt.want {
                t.Errorf("got %v, want %v", got, tt.want)
            }
        })
    }
}
```

### 3. Use Coverage HTML Report
```bash
go test ./... -coverprofile=coverage.out -covermode=atomic
go tool cover -html=coverage.out -o coverage.html
```

Open `coverage.html` in browser to see which lines are not covered (red).

### 4. Focus on Uncovered Lines
Use `go tool cover -func=coverage.out | grep -v "100.0%"` to find functions needing tests.

## Next Steps

1. Start with **pkg/passive/securitytrails** (template provided)
2. Apply same pattern to other passive sources
3. Move to scanner, proxy, core packages
4. Polish with ip, waf, output tests
5. Run final coverage report
6. Upload to codecov.io

## Estimated Effort

- **Phase 1** (6 packages): ~4-6 hours
- **Phase 2** (7 packages): ~5-7 hours
- **Phase 3** (5 packages): ~2-3 hours
- **Total**: ~11-16 hours to reach 95%+ coverage

Each passive source package takes ~30-60 minutes to fully test.
