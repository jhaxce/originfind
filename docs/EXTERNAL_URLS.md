# External URLs and Fallback Mechanisms

This document lists all external URLs used by origindive with their fallback strategies and error handling.

## 📋 Summary

| Category | Primary URLs | Fallback Strategy | Error Handling |
|----------|-------------|-------------------|----------------|
| **Proxy Sources** | 2 API + 4 GitHub | Multi-source with warnings | Continue with partial results |
| **Proxy Validation** | 6 IP check endpoints | Sequential fallback | Try all until one succeeds |
| **GitHub Releases** | 1 API endpoint | Manual check URL | Rate limit detection |
| **ASN Lookup** | 1 API (ipapi.is) | Manual CIDR input | Clear fallback instructions |
| **WAF Updates** | 3 provider APIs | Cached ranges | Service-specific errors |
| **Passive APIs** | 9 intelligence sources | Individual failures | API-specific messages |

## 🔍 Proxy Validation Endpoints (pkg/proxy/proxy.go)

### IPCheckEndpoints Array
These endpoints validate **ALL proxies** (free public + Webshare premium) by returning your public IP address. Used by `ValidateProxy()` function in `pkg/proxy/proxy.go` with automatic fallback:

1. **api.ipify.org** (Primary)
   - URL: `https://api.ipify.org/`
   - Response: Plain IP (`192.0.2.1`)
   - Reliability: ⭐⭐⭐⭐⭐ Excellent
   - Format: Simple, fast
   - Fallback: Next endpoint

2. **AWS CloudFront CheckIP** (Secondary)
   - URL: `https://checkip.amazonaws.com/`
   - Response: Plain IP with newline
   - Reliability: ⭐⭐⭐⭐⭐ Excellent (AWS infrastructure)
   - Format: Simple
   - Fallback: Next endpoint

3. **icanhazip.com** (Tertiary)
   - URL: `https://icanhazip.com/`
   - Response: Plain IP
   - Reliability: ⭐⭐⭐⭐ Good (classic service)
   - Format: Simple
   - Fallback: Next endpoint

4. **Webshare.io IPv4**
   - URL: `https://ipv4.webshare.io/`
   - Response: Plain IP
   - Reliability: ⭐⭐⭐⭐ Good (Webshare premium)
   - Format: Simple
   - Fallback: Next endpoint

5. **checkip.dyndns.org** (Legacy)
   - URL: `http://checkip.dyndns.org/`
   - Response: HTML with IP (`<html>...Current IP Address: 1.2.3.4...</html>`)
   - Reliability: ⭐⭐⭐ Medium (legacy but working)
   - Format: HTML (requires extraction)
   - Fallback: Next endpoint

6. **Cloudflare CDN Trace** (Advanced)
   - URL: `https://cloudflare.com/cdn-cgi/trace`
   - Response: Multi-field trace data with `ip=1.2.3.4` line
   - Reliability: ⭐⭐⭐⭐⭐ Excellent (Cloudflare CDN)
   - Format: Key-value pairs (requires parsing)
   - Fallback: None (last resort)

### Validation Fallback Strategy
```go
// Try each endpoint sequentially until one succeeds
for each endpoint {
    if success and valid_ip {
        return ip
    }
    continue to next
}
return error // All endpoints failed
```

**Response Formats Supported:**
- Plain IP: `192.0.2.1`
- HTML: `<html>...Current IP Address: 192.0.2.1...</html>`
- Cloudflare trace: `fl=...\nip=192.0.2.1\nts=...`

**Error Handling:**
- Individual endpoint failure → Try next endpoint
- All endpoints fail → Return error with last failure message
- Invalid IP extraction → Try next endpoint
- Timeout (per endpoint) → 5 seconds default

**Usage in Code:**
```go
// pkg/proxy/proxy.go - ValidateProxy function (used by ALL proxy types)
ip, err := ValidateProxy(proxyURL, 5*time.Second)
if err != nil {
    return fmt.Errorf("proxy validation failed: %w", err)
}

// pkg/proxy/proxy.go - TestProxy method (called during validation)
func (p *Proxy) TestProxy(timeout time.Duration) error {
    _, err := ValidateProxy(p.URL, timeout)
    return err
}

// pkg/proxy/webshare.go - TestWebshareProxy wrapper (backwards compatibility)
func TestWebshareProxy(proxyURL string, timeout time.Duration) error {
    _, err := ValidateProxy(proxyURL, timeout)
    return err
}
```

**Key Design:**
- Single source of truth: `ValidateProxy()` in `proxy.go`
- Used by free public proxies (ProxyScrape, GeoNode, GitHub repos)
- Used by Webshare.io premium proxies
- Used by `ValidateProxies()` for batch validation
- Consistent behavior across all proxy sources

## 🌐 Proxy Sources (pkg/proxy/proxy.go)

### PublicProxySources Array
These sources are checked in order with automatic failover:

1. **ProxyScrape API v4** (Primary)
   - URL: `https://api.proxyscrape.com/v4/free-proxy-list/get?request=display_proxies&proxy_format=protocolipport&format=json`
   - Format: JSON
   - Reliability: High
   - Fallback: Next source
   - Error: Continue silently

2. **GeoNode API** (Secondary)
   - URL: `https://proxylist.geonode.com/api/proxy-list?limit=500&page=1&sort_by=lastChecked&sort_type=desc&protocols=http%2Chttps`
   - Format: JSON
   - Reliability: Medium
   - Fallback: Next source
   - Rate Limit: None known

3-7. **GitHub Repositories** (Fallback)
   - TheSpeedX/PROXY-List: `https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt`
   - clarketm/proxy-list: `https://raw.githubusercontent.com/clarketm/proxy-list/master/proxy-list-raw.txt`
   - ShiftyTR/Proxy-List: `https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/http.txt`
   - monosans/proxy-list (2 URLs): `https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt`
   - Format: Text (one proxy per line)
   - Reliability: Community-maintained (may be outdated)
   - Rate Limit: GitHub CDN limits

### Fallback Strategy
```
Primary fails → Try Secondary → Try GitHub repos → Warn if partial success → Error if all fail
```

**Error Message Pattern:**
```
[!] Warning: X/Y proxy sources failed (continuing with Z proxies)
```

### Removed Sources
- ❌ `https://advanced.name/freeproxy/6931786780f31` - Expires after 24 hours (captcha-protected)

---

## 🔄 GitHub Releases (pkg/update/updater.go)

### Primary API
- URL: `https://api.github.com/repos/jhaxce/origindive/releases/latest`
- Format: JSON (GitHub API v3)
- Authentication: None (public repo)
- Rate Limit: 60 req/hour (unauthenticated), 5000 req/hour (authenticated)

### Fallback URL
- Manual Check: `https://github.com/jhaxce/origindive/releases/latest`
- Purpose: User can manually download if API fails

### Error Handling

| Status Code | Message | Action |
|------------|---------|--------|
| 403 | Rate limit exceeded | Show manual URL |
| 429 | Too many requests | Show manual URL, suggest retry |
| 404 | Release not found | Show repository URL |
| 5xx | GitHub service error | Show manual URL, retry later |
| Network error | Connection failed | Show manual URL, check network |

**Error Message Pattern:**
```
failed to fetch release info from GitHub API: <error>
Fallback: Check manually at https://github.com/jhaxce/origindive/releases/latest
```

---

## 🔍 ASN Lookup (pkg/asn/asn.go)

### Primary API
- URL: `https://api.ipapi.is/?asn=<ASN>`
- Example: `https://api.ipapi.is/?asn=AS13335`
- Format: JSON
- Rate Limit: Unknown
- Free Tier: Yes

### Fallback Options
1. **Manual ASN Lookup**: `https://ipapi.is/geolocation.html`
2. **Direct CIDR Input**: `--cidr` flag with manual IP ranges

### Error Handling

| Status Code | Message | Recommendation |
|------------|---------|----------------|
| 429 | Rate limit exceeded | Use `--cidr` flag instead |
| 404 | ASN not found | Verify ASN code, use manual lookup |
| 5xx | API unavailable | Use manual lookup or `--cidr` |
| Network error | Connection failed | Check network, use `--cidr` |

**Error Message Pattern:**
```
API request failed: <error>
Fallback: Check manually at https://ipapi.is/geolocation.html or use direct CIDR input with --cidr flag
```

**Manual Workflow:**
1. Visit https://whois.ipinsight.io/countries to find ASN
2. Visit https://ipapi.is/geolocation.html for ASN details
3. Extract CIDR ranges manually
4. Use: `origindive -d example.com --cidr 192.0.2.0/24`

---

## 🛡️ WAF Range Updates (pkg/waf/updater.go, data/waf_sources.json)

### Provider APIs

1. **Cloudflare**
   - IPv4: `https://www.cloudflare.com/ips-v4`
   - IPv6: `https://www.cloudflare.com/ips-v6`
   - Format: Text (one CIDR per line)
   - Official: Yes
   - Reliability: Very High

2. **AWS CloudFront**
   - URL: `https://ip-ranges.amazonaws.com/ip-ranges.json`
   - Format: JSON (JSONPath: `$.prefixes[?(@.service=='CLOUDFRONT')].ip_prefix`)
   - Official: Yes
   - Reliability: Very High

3. **Fastly**
   - URL: `https://api.fastly.com/public-ip-list`
   - Format: JSON (JSONPath: `$.addresses`)
   - Official: Yes
   - Reliability: High

### Fallback Strategy
- **Cached Ranges**: `data/waf_ranges.json` (bundled with binary)
- **Update Interval**: 168 hours (1 week)
- **Graceful Degradation**: Use cached data if any source fails

### Error Handling

| Condition | Action | User Impact |
|-----------|--------|-------------|
| 429 (Rate limit) | Use cached ranges | No impact |
| 5xx (Server error) | Use cached ranges | No impact |
| Network error | Use cached ranges | No impact |
| All sources fail | Use bundled data | Warning message |

**Error Message Pattern:**
```
<Provider>: failed to fetch ranges from <URL>: <error> (using cached data)
```

**Cache Locations:**
- Primary: `data/waf_ranges.json` (bundled)
- Runtime: `~/.config/origindive/waf_ranges.json` (updated)

---

## 🕵️ Passive Reconnaissance APIs

### 1. Certificate Transparency (pkg/passive/ct/ct.go)

**Service:** crt.sh
- URL: `https://crt.sh/json?q=<domain>`
- Format: JSON
- Authentication: None
- Rate Limit: Unknown (service often overloaded)

**Known Issues:**
- Frequent 502/503/504 errors (gateway timeouts)
- Service can be slow or unavailable during peak hours

**Error Handling:**
```
crt.sh appears to be down (gateway error). Please try again later
```

---

### 2. Shodan (pkg/passive/shodan/shodan.go)

**Service:** Shodan API
- URL: `https://api.shodan.io/shodan/host/search?query=<query>&key=<key>`
- Format: JSON
- Authentication: API key required
- Rate Limit: Depends on plan (Academic: 100/month, Small Business: 10,000/month)

**API Key:** Get at `https://account.shodan.io/`

**Error Handling:**

| Status | Message | Action |
|--------|---------|--------|
| 401/403 | Authentication failed | Check API key at https://account.shodan.io/ |
| 429 | Rate limit exceeded | Upgrade plan at https://account.shodan.io/billing |
| Network | Request failed | Check network connection |

**Error Message:**
```
Shodan API authentication failed (status 401). Check your API key at https://account.shodan.io/
```

---

### 3. ViewDNS (pkg/passive/viewdns/viewdns.go)

**Service:** ViewDNS.info API
- URL: `https://api.viewdns.info/reverseip/?host=<domain>&apikey=<key>&output=json`
- Format: JSON
- Authentication: API key required
- Rate Limit: Depends on plan

**API Key:** Get at `https://viewdns.info/api/`

**Error Handling:**
```
ViewDNS API authentication failed (status 403). Check your API key at https://viewdns.info/api/
ViewDNS API rate limit exceeded. Please wait or upgrade at https://viewdns.info/api/
```

---

### 4. DNSDumpster (pkg/passive/dnsdumpster/dnsdumpster.go)

**Service:** DNSDumpster API
- URL: `https://api.dnsdumpster.com/domain/<domain>`
- Format: JSON
- Authentication: API key (optional for FREE tier)
- Rate Limit: 1 request per 2 seconds (FREE tier)

**Error Handling:**
```
DNSDumpster API rate limit exceeded (1 request per 2 seconds). Please wait
DNSDumpster API is temporarily unavailable. Please try again later
```

---

### 5. SecurityTrails (pkg/passive/securitytrails/securitytrails.go)

**Service:** SecurityTrails API
- Subdomain URL: `https://api.securitytrails.com/v1/domain/<domain>/subdomains`
- History URL: `https://api.securitytrails.com/v1/history/<domain>/dns/a`
- Format: JSON
- Authentication: APIKEY header required
- Rate Limit: Depends on plan

**API Key:** Get at `https://securitytrails.com/app/account/credentials`

**Error Handling:**
```
SecurityTrails API authentication failed (status 401). Check your API key at https://securitytrails.com/app/account/credentials
SecurityTrails API rate limit exceeded: <details>
Upgrade at https://securitytrails.com/app/account/billing
```

---

### 6. ZoomEye (pkg/passive/zoomeye/zoomeye.go)

**Service:** ZoomEye API v2
- URL: `https://api.zoomeye.ai/v2/search` (POST)
- Format: JSON (base64-encoded query)
- Authentication: API-KEY header required
- Credits: Pay-per-query system

**API Key:** Get at `https://www.zoomeye.ai/profile`

**Error Handling:**
```
ZoomEye API authentication failed (status 401). Check your API key at https://www.zoomeye.ai/profile
ZoomEye API quota/credit exceeded. Purchase credits at https://www.zoomeye.ai/purchase
```

---

### 7. Wayback Machine (pkg/passive/wayback/wayback.go)

**Service:** Internet Archive CDX API
- URL: `http://web.archive.org/cdx/search/cdx?url=*.<domain>&output=json&collapse=urlkey&fl=original`
- Format: JSON
- Authentication: None
- Rate Limit: None known

**Known Issues:**
- Service can be slow (operates on massive dataset)
- Occasional 503/504 timeouts during maintenance

**Error Handling:**
```
Wayback Machine request failed: <error> (archive.org may be temporarily unavailable)
Wayback Machine API is temporarily unavailable (status 503). Please try again later
```

---

### 8. VirusTotal (pkg/passive/virustotal/virustotal.go)

**Service:** VirusTotal API v3
- URL: `https://www.virustotal.com/api/v3/domains/<domain>/subdomains`
- Format: JSON
- Authentication: x-apikey header required
- Rate Limit: 4 requests/minute (FREE tier)

**API Key:** Get at `https://www.virustotal.com/gui/my-apikey`

---

### 9. Censys (pkg/passive/censys/censys.go)

**Service:** Censys Search API v3
- URL: `https://search.censys.io/api/v2/hosts/search` (POST)
- Format: JSON
- Authentication: Bearer token (Personal Access Token)
- Rate Limit: Depends on plan

**API Token:** Get at `https://search.censys.io/account/api`

---

## 🔧 Webshare.io Premium Proxy (pkg/proxy/webshare.go)

### API Endpoints

1. **Proxy List** (Primary)
   - URL: `https://proxy.webshare.io/api/v2/proxy/list/?mode=direct&page=1&page_size=100`
   - Method: GET
   - Authentication: `Authorization: Token <api_key>`
   - Format: JSON

2. **Proxy Download** (Alternative)
   - URL: `https://proxy.webshare.io/api/v2/proxy/list/download/<token>/-/any/username/direct/-/`
   - Method: GET
   - Authentication: Token in URL
   - Format: Text (username:password@host:port per line)

3. **Profile**
   - URL: `https://proxy.webshare.io/api/v2/profile/`
   - Method: GET
   - Authentication: `Authorization: Token <api_key>`
   - Purpose: Check quota/bandwidth

**API Key:** Get at `https://proxy.webshare.io/`  
**Docs:** `https://apidocs.webshare.io/`

**Error Handling:**
- 401/403: Invalid API key
- 429: Rate limit
- Network errors: Fall back to public proxy sources

---

## 📝 Best Practices

### For Users

1. **Always have fallback options**
   - Store multiple API keys for critical services
   - Have manual CIDR ranges ready for ASN failures
   - Don't rely on single proxy source

2. **Monitor rate limits**
   - Use `--verbose` to see API call details
   - Space out scans to avoid hitting limits
   - Upgrade API plans if needed

3. **Check service status**
   - If passive source fails, try alternative sources
   - crt.sh is notoriously unstable (have backups)
   - GitHub rate limits apply to all repos combined

### For Developers

1. **Add timeout context**
   - All HTTP requests use `context.WithTimeout`
   - Default: 10-30 seconds depending on service

2. **Implement retry logic**
   - Not yet implemented (future enhancement)
   - Would help with transient failures

3. **Cache responses**
   - ASN lookups are cached (`~/.cache/origindive/asn_cache.json`)
   - WAF ranges are cached and updated weekly
   - Consider caching passive results (future)

4. **Graceful degradation**
   - Continue scan even if some sources fail
   - Warn user about partial results
   - Use cached data when available

---

## 🚨 Error Message Reference

### Pattern: Clear + Actionable

✅ **Good:**
```
Shodan API authentication failed (status 401). Check your API key at https://account.shodan.io/
```

❌ **Bad:**
```
Error: 401
```

### Components of Good Error Messages

1. **Service name**: "Shodan API"
2. **Problem**: "authentication failed"
3. **Technical detail**: "(status 401)"
4. **Action**: "Check your API key"
5. **Resource**: "at https://account.shodan.io/"

---

## 🔗 Quick Reference: All URLs

### Download/Installation
- Latest releases: `https://github.com/jhaxce/origindive/releases/latest`
- Release API: `https://api.github.com/repos/jhaxce/origindive/releases/latest`

### Proxy Sources (7 total)
1. `https://api.proxyscrape.com/v4/free-proxy-list/get?request=display_proxies&proxy_format=protocolipport&format=json`
2. `https://proxylist.geonode.com/api/proxy-list?limit=500&page=1&sort_by=lastChecked&sort_type=desc&protocols=http%2Chttps`
3-7. GitHub raw content URLs (5 repositories)

### Intelligence Sources (10 total)
1. `https://crt.sh/json?q=<domain>` (Certificate Transparency)
2. `https://api.shodan.io/shodan/host/search` (Shodan)
3. `https://api.viewdns.info/reverseip/` (ViewDNS)
4. `https://api.dnsdumpster.com/domain/` (DNSDumpster)
5. `https://api.securitytrails.com/v1/domain/` (SecurityTrails)
6. `https://api.zoomeye.ai/v2/search` (ZoomEye)
7. `http://web.archive.org/cdx/search/cdx` (Wayback Machine)
8. `https://www.virustotal.com/api/v3/domains/` (VirusTotal)
9. `https://search.censys.io/api/v2/hosts/search` (Censys)
10. `https://proxy.webshare.io/api/v2/` (Webshare.io)

### Utility APIs
- ASN Lookup: `https://api.ipapi.is/?asn=<ASN>`
- Cloudflare IPs: `https://www.cloudflare.com/ips-v4`, `https://www.cloudflare.com/ips-v6`
- AWS CloudFront: `https://ip-ranges.amazonaws.com/ip-ranges.json`
- Fastly IPs: `https://api.fastly.com/public-ip-list`

---

## 📊 Reliability Matrix

| Service | Uptime | Speed | Free Tier | Requires Key | Rate Limited |
|---------|--------|-------|-----------|--------------|--------------|
| ProxyScrape | High | Fast | Yes | No | No |
| GeoNode | Medium | Fast | Yes | No | No |
| GitHub Raw | High | Fast | Yes | No | Yes (60/hr) |
| Webshare.io | Very High | Very Fast | No | Yes | Yes (quota) |
| crt.sh | Low | Slow | Yes | No | Unknown |
| Shodan | High | Fast | Limited | Yes | Yes (plan) |
| ViewDNS | Medium | Medium | Limited | Yes | Yes (plan) |
| DNSDumpster | Medium | Medium | Yes | Optional | Yes (1 req/2s) |
| SecurityTrails | High | Fast | Limited | Yes | Yes (plan) |
| ZoomEye | High | Fast | No | Yes | Yes (credits) |
| Wayback Machine | Medium | Slow | Yes | No | No |
| VirusTotal | High | Medium | Yes | Yes | Yes (4 req/min) |
| Censys | High | Fast | Limited | Yes | Yes (plan) |
| ipapi.is | Unknown | Fast | Yes | No | Unknown |
| AWS/Cloudflare | Very High | Very Fast | Yes | No | No |

**Legend:**
- Uptime: Service availability
- Speed: Response time
- Free Tier: Usable without payment
- Requires Key: API key needed
- Rate Limited: Has request limits

---

## 🎯 Recommendations

### Critical Path (must work)
1. ✅ Proxy sources: Multiple fallbacks implemented
2. ✅ WAF updates: Cached data available
3. ⚠️ Self-update: Add manual download link (DONE)
4. ⚠️ ASN lookup: Add fallback instructions (DONE)

### Nice to Have (can fail gracefully)
1. ✅ Passive sources: Individual failures handled
2. ⚠️ crt.sh: Known to be unreliable, warn users
3. ✅ Wayback: Slow but stable, timeout detection added

### Future Enhancements
1. ⏳ Retry logic with exponential backoff
2. ⏳ Local caching for passive results
3. ⏳ Health checks before API calls
4. ⏳ Alternative passive sources (when primaries fail)
5. ⏳ User notification system for service outages

---

**Last Updated:** December 4, 2025  
**Version:** 3.2.0-dev  
**Maintainer:** jhaxce
