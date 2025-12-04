# Proxy Support Guide

## Overview

origindive v3.1+ includes comprehensive proxy support for enhanced anonymity and bypassing rate limits. This guide covers proxy configuration, auto-fetching, validation, and troubleshooting.

## Quick Start

```bash
# Auto-fetch free proxies (country-aware)
origindive -d example.com --proxy-auto -n 192.168.1.0/24

# Use specific proxy
origindive -d example.com -P http://proxy-server:8080

# Use Webshare.io FREE proxies
origindive -d example.com --proxy-auto --webshare-key YOUR_API_KEY

# Load proxies from file
origindive -d example.com --proxy-file proxies.txt
```

## Proxy Sources

### 1. Webshare.io (FREE Tier)
**10 Premium Proxies | No Credit Card Required**

Sign up: https://www.webshare.io/  
Get API key: https://proxy.webshare.io/userapi/

```bash
# CLI flag
origindive -d example.com --proxy-auto --webshare-key zsowhhlyrq2l13ci3fal2sq35ydar7v396hu1ux6

# Global config
echo 'webshare_keys:
  - "YOUR_API_KEY_HERE"' > ~/.config/origindive/config.yaml
```

**Features:**
- ✅ 10 datacenter proxies (US, GB, JP, PL, ES)
- ✅ Authenticated (always prioritized in validation)
- ✅ 90%+ success rate
- ✅ FREE tier (no credit card)
- ✅ Automatic rotation

**Locations:** United States, United Kingdom, Japan, Poland, Spain

---

### 2. ProxyScrape (Country-Aware)
**Free Public Proxies | Auto-Detected Country**

API: https://api.proxyscrape.com/v4/

```bash
# Automatic (uses detected country)
origindive -d example.com --proxy-auto
```

origindive automatically:
1. Detects your country from Cloudflare CDN trace
2. Fetches proxies from ProxyScrape for your country
3. Filters by timeout ≤1000ms (faster proxies only)

**Example for Philippines (PH):**
```
https://api.proxyscrape.com/v4/free-proxy-list/get?request=display_proxies&country=ph&protocol=http&timeout=1000&format=text
```

**Protocols:** HTTP, HTTPS, SOCKS4, SOCKS5

---

### 3. GeoNode (Country-Aware + Uptime Filter)
**Free Public Proxies | 90% Uptime Guarantee**

API: https://proxylist.geonode.com/

```bash
# Automatic (uses detected country + 90% uptime filter)
origindive -d example.com --proxy-auto
```

**Filters Applied:**
- Country: Auto-detected (e.g., PH for Philippines)
- Uptime: ≥90% (reliable proxies only)
- Limit: 500 proxies per request

**Example for Philippines:**
```
https://proxylist.geonode.com/api/proxy-list?limit=500&page=1&sort_by=lastChecked&sort_type=desc&country=PH&filterUpTime=90
```

---

## Country Auto-Detection

origindive automatically detects your country using Cloudflare's CDN trace endpoint:

```
https://cloudflare.com/cdn-cgi/trace
```

**Response:**
```
fl=123f45
h=cloudflare.com
ip=203.160.187.1
ts=1638360000.123
visit_scheme=https
uag=origindive/3.1.0
colo=MNL
sliver=none
http=http/2
loc=PH  ← Detected country
tls=TLSv1.3
sni=plaintext
warp=off
gateway=off
rbi=off
kex=X25519
```

**Supported Countries:** All ISO 3166-1 alpha-2 codes (US, GB, PH, JP, etc.)

---

## Proxy Validation

### Multi-Endpoint Validation

origindive validates proxies using 6 IP check services with automatic fallback:

1. **api.ipify.org** - Fast, plain IP response
2. **checkip.amazonaws.com** - AWS service, plain IP
3. **icanhazip.com** - Classic service, plain IP
4. **ipv4.webshare.io** - Webshare endpoint, plain IP
5. **checkip.dyndns.org** - Legacy service, HTML format
6. **cloudflare.com/cdn-cgi/trace** - Key-value format

**Validation Logic:**
```go
1. Send HTTP GET request through proxy
2. Try first endpoint (ipify)
3. If timeout/error, try next endpoint
4. Parse response (plain text, HTML, or key-value)
5. Compare proxy IP vs. our real IP
6. If different → proxy working ✓
7. If same → proxy failed ✗
```

### Smart Sampling

For large proxy lists (500+ proxies), origindive uses intelligent sampling:

```
Total proxies: 674
├─ First 50: Always validated (includes premium Webshare)
├─ Remaining 624: 20% random sample (max 2,000)
└─ Total validated: 175 proxies (26%)

Validation results:
├─ Working: 13 proxies (7.4%)
├─ Failed: 162 proxies (92.6%)
└─ Performance: 74% fewer validations, 3x better quality
```

**Why this works:**
- Webshare premium proxies (first in list) always tested
- Random sampling finds quality proxies across entire list
- Reduces validation time from minutes to seconds
- Better quality (5.75% success vs 1.90% without sampling)

---

## Configuration

### Global Configuration

`~/.config/origindive/config.yaml`:

```yaml
# Webshare.io API keys (FREE tier: 10 proxies)
webshare_keys:
  - "YOUR_API_KEY_HERE"
  - "BACKUP_KEY"  # Optional: automatic rotation

# Proxy settings
proxy_auto: true
proxy_test_timeout: 60  # seconds
proxy_workers: 50  # parallel validation workers

# Proxy sources priority
proxy_sources:
  - webshare    # Premium (if API key provided)
  - proxyscrape # Country-aware public
  - geonode     # Country-aware with uptime filter
```

### Per-Scan Configuration

```yaml
# scan-config.yaml
domain: "example.com"
cidr: "192.168.1.0/24"
proxy_auto: true
proxy_rotation: true
workers: 20
```

```bash
origindive --config scan-config.yaml
```

---

## Advanced Usage

### Proxy Rotation

```bash
# Enable automatic rotation (default)
origindive -d example.com --proxy-auto --proxy-rotation

# Disable rotation (use same proxy for all requests)
origindive -d example.com --proxy-auto --no-proxy-rotation
```

### Custom Proxy File

Create `proxies.txt`:
```
http://proxy1.example.com:8080
https://proxy2.example.com:3128
socks5://proxy3.example.com:1080
socks4://proxy4.example.com:1080
# Comments are ignored
http://user:pass@authenticated-proxy.com:8080
```

```bash
origindive -d example.com --proxy-file proxies.txt
```

**Supported formats:**
- `http://host:port`
- `https://host:port`
- `socks4://host:port`
- `socks5://host:port`
- `protocol://user:pass@host:port` (authenticated)

### Proxy Testing

```bash
# Test proxies without scanning
origindive --test-proxies --proxy-auto

# Test specific proxy
origindive --test-proxies -P http://proxy:8080

# Test from file
origindive --test-proxies --proxy-file proxies.txt
```

**Output:**
```
Testing proxies...
✓ http://45.195.136.212:8080 (US) - 234ms
✗ http://103.152.112.162:80 (PH) - timeout
✓ http://185.217.143.96:3128 (PL) - 567ms
✓ socks5://198.12.66.87:1080 (US) - 123ms

Results:
├─ Working: 12/50 (24%)
├─ Failed: 38/50 (76%)
└─ Average latency: 341ms
```

---

## Performance Optimization

### Increase Validation Workers

```bash
# Default: 50 workers
origindive -d example.com --proxy-auto --proxy-workers 100

# Conservative (slower but safer)
origindive -d example.com --proxy-auto --proxy-workers 20
```

### Adjust Timeout

```bash
# Longer timeout for slow proxies (default: 60s)
origindive -d example.com --proxy-auto --proxy-test-timeout 120

# Shorter timeout for fast proxies only
origindive -d example.com --proxy-auto --proxy-test-timeout 30
```

### Disable Proxy Validation

```bash
# Skip validation, use all proxies (not recommended)
origindive -d example.com --proxy-auto --no-proxy-test
```

---

## Troubleshooting

### No Working Proxies Found

**Problem:**
```
Fetching proxies...
├─ Webshare: 10 proxies
├─ ProxyScrape (PH): 82 proxies
└─ GeoNode (PH): 92 proxies
Total fetched: 184 proxies

Validating proxies (60s timeout, 50 workers)...
Progress: [████████████████████] 100% (175/175) | Rate: 45/s

Error: no working proxies found after validation
```

**Solutions:**

1. **Use Webshare Premium:**
   ```bash
   origindive -d example.com --proxy-auto --webshare-key YOUR_KEY
   ```
   90%+ success rate vs. 5% for free proxies

2. **Increase Timeout:**
   ```bash
   origindive -d example.com --proxy-auto --proxy-test-timeout 120
   ```
   Slow proxies need more time

3. **Try Different Country:**
   ```bash
   # Override auto-detection
   origindive -d example.com --proxy-auto --proxy-country US
   ```

4. **Use Custom Proxy List:**
   ```bash
   # Known-working proxies
   origindive -d example.com --proxy-file working-proxies.txt
   ```

5. **Skip Validation (Use With Caution):**
   ```bash
   origindive -d example.com --proxy-auto --no-proxy-test
   ```

---

### Proxy Connection Timeouts During Scan

**Problem:**
```
[+] 192.168.1.10 --> Proxy timeout
[+] 192.168.1.11 --> Proxy timeout
```

**Solutions:**

1. **Increase Scan Timeout:**
   ```bash
   origindive -d example.com -P http://proxy:8080 -t 15
   ```

2. **Use Faster Proxies:**
   ```bash
   # ProxyScrape filters by timeout=1000ms
   origindive -d example.com --proxy-auto
   ```

3. **Reduce Concurrency:**
   ```bash
   # Fewer parallel requests
   origindive -d example.com --proxy-auto -j 10
   ```

---

### 0 Results with Proxy (Works Without)

**Problem:** Direct scan finds 58 IPs, proxy scan finds 0.

**Cause:** Target may be blocking proxy IPs or rate limiting.

**Solutions:**

1. **Test Proxy Manually:**
   ```bash
   curl -x http://proxy:8080 http://192.168.1.10 -H "Host: example.com"
   ```

2. **Try Premium Proxies:**
   ```bash
   origindive -d example.com --proxy-auto --webshare-key YOUR_KEY
   ```
   Premium IPs less likely to be blocked

3. **Disable Proxy for Verification:**
   ```bash
   # Scan with proxy
   origindive -d example.com --proxy-auto -n 192.168.1.0/24 -o proxy-results.txt
   
   # Verify without proxy
   origindive -d example.com -i proxy-results.txt --verify
   ```

---

### Webshare API Errors

**Problem:**
```
Error: failed to fetch Webshare proxies: 401 Unauthorized
```

**Solutions:**

1. **Check API Key:**
   ```bash
   # Test key
   curl -H "Authorization: Token YOUR_KEY" https://proxy.webshare.io/api/v2/proxy/list/
   ```

2. **Verify Account:**
   - Login: https://proxy.webshare.io/
   - Check quota: https://proxy.webshare.io/userapi/

3. **Update Key:**
   ```bash
   # Regenerate key if expired
   origindive -d example.com --webshare-key NEW_KEY
   ```

---

## Country-Aware Proxy Statistics

Performance comparison for Philippine (PH) users:

### Before Country-Awareness (v3.0)
```
Sources: 6 GitHub repos (mixed countries)
Total proxies: 675
Working: 13 (1.90%)
Validation time: ~45s
```

### After Country-Awareness (v3.1)
```
Sources: 2 APIs (PH-filtered) + Webshare
Total proxies: 184
Validated: 175 (smart sampling)
Working: 13 (7.4% of validated, 5.75% of raw)
Validation time: ~12s (74% faster)
```

**Benefits:**
- ✅ 74% fewer proxies to validate
- ✅ 3x better quality (5.75% vs 1.90%)
- ✅ Lower latency (geo-local proxies)
- ✅ Faster validation (smart sampling)
- ✅ Same or better success rate

---

## Protocol Support

### HTTP/HTTPS Proxies

```bash
# HTTP proxy
origindive -d example.com -P http://proxy:8080

# HTTPS proxy (CONNECT tunnel)
origindive -d example.com -P https://proxy:3128
```

### SOCKS Proxies

```bash
# SOCKS5 (recommended)
origindive -d example.com -P socks5://proxy:1080

# SOCKS4
origindive -d example.com -P socks4://proxy:1080
```

### Authenticated Proxies

```bash
# Basic authentication
origindive -d example.com -P http://username:password@proxy:8080

# Webshare uses token authentication (automatic)
origindive -d example.com --proxy-auto --webshare-key YOUR_TOKEN
```

---

## Best Practices

### 1. Start with Webshare FREE
```bash
# Sign up: https://www.webshare.io/ (no credit card)
# Get 10 premium proxies
origindive -d example.com --proxy-auto --webshare-key YOUR_KEY
```

### 2. Use Country-Aware for Better Performance
```bash
# Automatic country detection + geo-local proxies
origindive -d example.com --proxy-auto
```

### 3. Enable Proxy Rotation
```bash
# Distribute load across proxies
origindive -d example.com --proxy-auto --proxy-rotation
```

### 4. Adjust Concurrency
```bash
# More workers for large scans
origindive -d example.com --proxy-auto -j 50
```

### 5. Verify Results Without Proxy
```bash
# Initial scan with proxy
origindive -d example.com --proxy-auto -n 192.0.2.0/24 -o results.txt

# Verify hits directly
origindive -d example.com -i results.txt --verify
```

---

## See Also

- [README.md](../README.md) - Main usage guide
- [EXTERNAL_URLS.md](EXTERNAL_URLS.md) - API endpoint documentation
- [Webshare.io](https://www.webshare.io/) - FREE proxy service
- [ProxyScrape API](https://api.proxyscrape.com/) - Public proxy API
- [GeoNode API](https://proxylist.geonode.com/) - Geo-filtered proxies
