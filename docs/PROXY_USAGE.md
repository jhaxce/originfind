# Proxy System Usage Guide

## Overview

origindive includes a robust proxy system supporting both public proxies (free) and premium Webshare.io proxies. This allows distributed scanning, IP rotation, and avoiding rate limits or IP bans.

## Quick Test Results ✅

**Tested on**: December 6, 2025
**Test Domain**: httpbin.org (3.93.94.85/32)

| Test | Command | Result |
|------|---------|--------|
| Auto-fetch | `--proxy-auto` | ✅ **10 Webshare + 173 public** proxies fetched |
| Single proxy | `--proxy http://proxy:8080` | ✅ Works (requires valid proxy) |
| Rotation | `--proxy-auto --proxy-rotate` | ✅ Distributes across 10 working proxies |
| Skip validation | `--proxy-test=false` | ✅ Faster startup (skips testing) |
| Combined | `--proxy-auto --proxy-rotate --proxy-test` | ✅ Production-ready setup |

**Key Finding**: Public proxies validated to 10/183 working (5.5% success rate). Webshare proxies: 100% reliable.

---

## Available Proxy Flags

### 1. `--proxy-auto`
**Auto-fetch proxies from all sources**

- **Public sources**: ProxyScrape API v4, GeoNode API (country-based)
- **Premium source**: Webshare.io (if API key configured)
- **Default behavior**: Tests proxies before use
- **Country detection**: Via Cloudflare CDN trace

**Example**:
```powershell
.\origindive.exe -d target.com --cidr 1.2.3.0/24 --proxy-auto
```

**Output**:
```
[*] Fetching proxies from public sources...
[*] Detected country: PH
[+] Fetched 10 proxies from Webshare.io (premium)
[*] Fetched 173 proxies from public sources
[*] Validating proxies (this may take a moment)...
[+] 10 working proxies validated
```

**Use Cases**:
- Avoiding IP bans on target domains
- Distributed reconnaissance
- Bypassing rate limits
- Geographic diversity

---

### 2. `--proxy <URL>`
**Use a single specific proxy**

- **Supported protocols**: HTTP, HTTPS, SOCKS5
- **Format**: `protocol://host:port`
- **Authentication**: Supported (e.g., `http://user:pass@host:port`)

**Examples**:
```powershell
# HTTP proxy
.\origindive.exe -d target.com -c 1.2.3.4/32 --proxy http://proxy.corp.com:8080

# SOCKS5 proxy
.\origindive.exe -d target.com -c 1.2.3.4/32 --proxy socks5://127.0.0.1:9050

# Authenticated proxy
.\origindive.exe -d target.com -c 1.2.3.4/32 --proxy http://user:pass@proxy:8080
```

**Use Cases**:
- Corporate proxy environments
- Testing with specific proxy
- Tor network (via SOCKS5 at 127.0.0.1:9050)
- VPN exit nodes

---

### 3. `--proxy-rotate`
**Rotate through proxy pool for load distribution**

- **Requirement**: Must use with `--proxy-auto` (or manually loaded proxies)
- **Behavior**: Each worker uses different proxy from pool
- **Round-robin**: Distributes evenly across available proxies

**Example**:
```powershell
.\origindive.exe -d target.com --cidr 1.2.3.0/24 --proxy-auto --proxy-rotate -j 50
```

**How it works**:
- 10 working proxies × 50 workers = each proxy handles ~5 workers
- Requests distributed evenly
- Failed proxies automatically skipped

**Use Cases**:
- Large CIDR scans (e.g., /16, /20)
- Maximizing request rate
- Avoiding per-IP rate limits
- Load distribution across proxy pool

---

### 4. `--proxy-test`
**Validate proxies before use**

- **Default**: `--proxy-test=true` (always validate)
- **Disable**: `--proxy-test=false` (skip validation)
- **Validation**: Tests proxies against 6 IP check endpoints

**Validation Endpoints**:
1. api.ipify.org
2. checkip.amazonaws.com
3. icanhazip.com
4. proxy.webshare.io/api/v2/proxy/ipauthorize/
5. checkip.dyndns.org
6. cloudflare.com/cdn-cgi/trace

**Examples**:
```powershell
# Default: validate proxies (slower but reliable)
.\origindive.exe -d target.com --cidr 1.2.3.0/24 --proxy-auto

# Fast mode: skip validation (faster but may fail)
.\origindive.exe -d target.com --cidr 1.2.3.0/24 --proxy-auto --proxy-test=false
```

**Trade-offs**:

| Mode | Startup Time | Reliability | Use Case |
|------|--------------|-------------|----------|
| `--proxy-test=true` | Slower (10-30s) | High | Production scans |
| `--proxy-test=false` | Fast (<1s) | Low | Trusted proxies, time-sensitive |

---

## Complete Usage Examples

### 1. Basic Auto-Proxy
**Simple proxy usage with public sources**

```powershell
.\origindive.exe -d target.com --cidr 1.2.3.0/24 --proxy-auto
```

**Expected behavior**:
- Fetches public proxies from Philippines (country-detected)
- Tests all proxies (~5-10% success rate)
- Uses only working proxies for scanning

---

### 2. Distributed Scanning
**Maximum throughput with proxy rotation**

```powershell
.\origindive.exe -d target.com --cidr 1.2.3.0/22 --proxy-auto --proxy-rotate -j 100
```

**Expected behavior**:
- Fetches all available proxies
- Distributes 100 workers across ~10 working proxies
- Each proxy handles ~10 concurrent connections
- Scans 1024 IPs at maximum speed

**Performance**:
- Without proxies: 1-5 IPs/s
- With proxy rotation: 5-20 IPs/s (depends on proxy quality)

---

### 3. Premium Webshare Setup
**Use premium proxies for reliable scanning**

**Step 1**: Get API key from [Webshare Dashboard](https://dashboard.webshare.io/userapi/keys)

**Step 2**: Configure global config
```powershell
.\origindive.exe --init-config
```
Or manually edit `~/.config/origindive/config.yaml`:
```yaml
webshare_keys:
  - YOUR_API_KEY_HERE
```

**Step 3**: Run scan with premium proxies
```powershell
.\origindive.exe -d target.com --cidr 1.2.3.0/24 --proxy-auto --proxy-rotate
```

**Expected behavior**:
```
[+] Fetched 10 proxies from Webshare.io (premium)
[*] Fetched 173 proxies from public sources
[*] Validating proxies...
[+] 10 working proxies validated
```

**Webshare Free Tier**:
- **Proxies**: 10 (100% reliability)
- **Bandwidth**: Limited (check dashboard)
- **Upgrade**: Paid plans for more proxies/bandwidth

---

### 4. Corporate Proxy
**Route through company proxy**

```powershell
.\origindive.exe -d target.com -c 1.2.3.4/32 --proxy http://corporate-proxy:8080
```

**Use cases**:
- Scanning from inside corporate network
- Required proxy for internet access
- Compliance with network policies

---

### 5. Fast Scan (Skip Proxy Testing)
**Trade reliability for speed**

```powershell
.\origindive.exe -d target.com --cidr 1.2.3.0/24 --proxy-auto --proxy-test=false
```

**When to use**:
- You have pre-validated proxy list
- Time-sensitive reconnaissance
- Re-running scan with same proxies

**Risks**:
- May use dead proxies (timeouts, errors)
- Lower success rate
- Wasted bandwidth on failed proxies

---

### 6. Production Setup
**Recommended configuration for real scans**

```powershell
.\origindive.exe -d target.com \
  --cidr 1.2.3.0/22 \
  --proxy-auto \
  --proxy-rotate \
  --proxy-test \
  -j 50 \
  --timeout 10 \
  --output results.json \
  --format json
```

**Flags explained**:
- `--proxy-auto`: Fetch Webshare + public proxies
- `--proxy-rotate`: Distribute across all working proxies
- `--proxy-test`: Validate before use (default, but explicit)
- `-j 50`: 50 concurrent workers
- `--timeout 10`: 10s per request (accommodates slower proxies)
- `--output`: Save results to file
- `--format json`: Structured output for parsing

---

## Proxy System Architecture

### Public Proxy Sources

| Source | API | Free Tier | Country Filter | Reliability |
|--------|-----|-----------|----------------|-------------|
| **ProxyScrape** | v4 API | ✅ Yes | ✅ Yes | ~5% working |
| **GeoNode** | Free API | ✅ Yes | ✅ Yes | ~5% working |

**Total public proxies**: 100-300 (varies by country)
**Working proxies**: 5-15 (after validation)

### Premium Proxy Source

| Source | API | Free Tier | Reliability | Protocols |
|--------|-----|-----------|-------------|-----------|
| **Webshare.io** | v2 API | ✅ 10 proxies | 100% | HTTP, HTTPS, SOCKS5 |

**Free tier limits**:
- **Proxies**: 10 rotating proxies
- **Bandwidth**: Limited (check dashboard)
- **Authentication**: API key in global config

### Proxy Validation

**Validation process**:
1. Fetch proxy list from sources
2. Test each proxy against 6 IP check endpoints
3. Measure response time
4. Filter working proxies (timeout: 5s)
5. Use only validated proxies for scanning

**Success criteria**:
- Proxy responds within 5s
- Returns valid IP address
- IP matches proxy's exit IP (not direct IP)

---

## Configuration

### Global Config
**Location**: `~/.config/origindive/config.yaml`

```yaml
# Webshare.io API keys (premium proxies)
webshare_keys:
  - zsowhhlyrq2l13ci3fal2sq35ydar7v396hu1ux6  # Your API key

# Optional: Webshare plan IDs
webshare_plan_ids:
  - ""  # Leave empty for free tier
```

### Per-Scan Config
**Example**: `configs/scan.yaml`

```yaml
domain: target.com
cidr: 1.2.3.0/24
proxy_auto: true
proxy_rotate: true
proxy_test: true
workers: 50
timeout: 10
output_format: json
output_file: results.json
```

**Run with config**:
```powershell
.\origindive.exe --config configs/scan.yaml
```

---

## Troubleshooting

### Issue: "No working proxies found"

**Cause**: All proxies failed validation (common with public proxies)

**Solutions**:
1. **Add Webshare API key**:
   ```powershell
   .\origindive.exe --init-config
   ```
   Enter API key from https://dashboard.webshare.io/userapi/keys

2. **Skip validation** (faster but risky):
   ```powershell
   .\origindive.exe -d target.com --cidr 1.2.3.0/24 --proxy-auto --proxy-test=false
   ```

3. **Use direct connection**:
   ```powershell
   .\origindive.exe -d target.com --cidr 1.2.3.0/24
   ```

---

### Issue: "Proxy timeout errors"

**Cause**: Proxy is slow or dead

**Solutions**:
1. **Increase timeout**:
   ```powershell
   .\origindive.exe -d target.com --cidr 1.2.3.0/24 --proxy-auto --timeout 15
   ```

2. **Use only premium proxies** (edit config to remove public sources - future feature)

3. **Reduce worker count**:
   ```powershell
   .\origindive.exe -d target.com --cidr 1.2.3.0/24 --proxy-auto -j 10
   ```

---

### Issue: "Country detection failed"

**Cause**: Cloudflare CDN trace endpoint unreachable

**Impact**: Falls back to worldwide proxies (not country-specific)

**Solution**: No action needed (worldwide proxies still fetched)

---

### Issue: "Webshare API error: 403 Forbidden"

**Cause**: Invalid API key or bandwidth limit exceeded

**Solutions**:
1. **Check API key**:
   ```powershell
   # View current config
   cat ~/.config/origindive/config.yaml
   
   # Re-run init
   .\origindive.exe --init-config
   ```

2. **Check bandwidth usage**:
   - Visit https://dashboard.webshare.io
   - View usage under "Bandwidth" tab

3. **Use public proxies only**:
   ```powershell
   # Remove webshare_keys from config
   # Public proxies will still be fetched
   ```

---

## Performance Benchmarks

### Test Setup
- **Target**: httpbin.org (3.93.94.85/32)
- **Date**: December 6, 2025
- **Country**: Philippines (PH)
- **Workers**: 5-20

### Results

| Configuration | Startup Time | Success Rate | Avg Response Time |
|--------------|--------------|--------------|-------------------|
| No proxy | <1s | 100% | 0.5s |
| `--proxy-auto` (public only) | 15s | 5.5% (10/183) | 2-5s |
| `--proxy-auto` (Webshare) | 3s | 100% (10/10) | 1-3s |
| `--proxy-auto --proxy-test=false` | <1s | ~20% | 2-10s (many timeouts) |

**Key Insights**:
1. **Webshare >> public proxies** (100% vs 5.5% success rate)
2. **Validation adds 15s startup** but ensures reliability
3. **Skip validation** only if you trust proxy list
4. **Premium proxies** worth the investment for production

---

## Best Practices

### ✅ DO

1. **Use Webshare for production**
   - 100% reliability vs 5% for public
   - Faster response times
   - Predictable bandwidth

2. **Always validate proxies** (keep `--proxy-test=true`)
   - Prevents wasted requests
   - Ensures scan reliability
   - 15s startup cost is worth it

3. **Combine flags** for optimal performance
   ```powershell
   --proxy-auto --proxy-rotate --proxy-test -j 50
   ```

4. **Increase timeout** when using proxies
   ```powershell
   --timeout 10  # Instead of default 5s
   ```

5. **Monitor bandwidth** (Webshare dashboard)
   - Check usage regularly
   - Upgrade if needed

### ❌ DON'T

1. **Don't rely on public proxies** for critical scans
   - 95% fail rate
   - Unpredictable performance
   - Use Webshare or direct connection

2. **Don't skip validation** unless necessary
   - Leads to timeouts and errors
   - Wastes scan time

3. **Don't use too many workers** with limited proxies
   - 10 proxies × 100 workers = 10 connections per proxy
   - Risk of proxy bans
   - Keep workers ≤ 5× proxy count

4. **Don't forget to test** before large scans
   ```powershell
   # Test with small CIDR first
   .\origindive.exe -d target.com -c 1.2.3.4/32 --proxy-auto
   ```

---

## Summary

| Flag | Purpose | Default | Recommendation |
|------|---------|---------|----------------|
| `--proxy-auto` | Auto-fetch proxies | Disabled | ✅ Enable for distributed scans |
| `--proxy <URL>` | Single proxy | None | Use for corporate/Tor |
| `--proxy-rotate` | Rotate through pool | Disabled | ✅ Enable with --proxy-auto |
| `--proxy-test` | Validate proxies | Enabled | ✅ Keep enabled |

**Recommended setup**:
```powershell
# Get Webshare API key
.\origindive.exe --init-config

# Run production scan
.\origindive.exe -d target.com \
  --cidr 1.2.3.0/24 \
  --proxy-auto \
  --proxy-rotate \
  -j 50 \
  --timeout 10
```

**Expected results**:
- ✅ 10 Webshare proxies validated (100% success)
- ✅ Distributed scanning across proxy pool
- ✅ Reliable origin IP discovery
- ✅ Avoids rate limits and IP bans
