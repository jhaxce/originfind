# Passive Reconnaissance Guide

## Overview

origindive v3.1+ includes comprehensive passive reconnaissance capabilities through 9 OSINT intelligence sources. This guide explains how to use passive mode to discover potential origin IPs without directly scanning targets.

## Quick Start

```bash
# Enable passive mode only (no active scanning)
origindive -d example.com --passive --scan-mode passive

# Combined passive + active (recommended)
origindive -d example.com --passive --scan-mode auto -n 192.168.1.0/24

# Use specific sources only
origindive -d example.com --passive-sources ct,virustotal,shodan

# Filter by confidence score
origindive -d example.com --passive --min-confidence 0.7
```

## Intelligence Sources

### 1. Certificate Transparency (CT Logs)
**Free | No API Key Required**

Searches certificate transparency logs for SSL certificates issued to your domain.

```bash
origindive -d example.com --passive-sources ct
```

**What it finds:**
- IP addresses from certificate Subject Alternative Names
- Historical IPs from old certificates
- Subdomain IPs that might share infrastructure

**Coverage:** Excellent for modern domains with HTTPS

---

### 2. SecurityTrails
**Requires API Key** | [Get Free Key](https://securitytrails.com/corp/api)

Premium DNS intelligence platform with historical DNS records.

```bash
origindive -d example.com --passive-sources securitytrails --securitytrails-key YOUR_KEY
```

**What it finds:**
- Current and historical A/AAAA records
- DNS changes over time
- IP changes that might reveal origin

**API Limits:** 50 requests/month (free tier)

---

### 3. VirusTotal
**Requires API Key** | [Get Free Key](https://www.virustotal.com/gui/my-apikey)

File and URL analysis platform with passive DNS data.

```bash
origindive -d example.com --passive-sources virustotal --virustotal-key YOUR_KEY
```

**What it finds:**
- DNS resolutions seen by VirusTotal
- IPs from malware analysis
- Historical DNS records

**API Limits:** 4 requests/minute (free tier)

---

### 4. Shodan
**Requires API Key** | [Get API Key](https://account.shodan.io/)

Internet-connected device search engine.

```bash
origindive -d example.com --passive-sources shodan --shodan-key YOUR_KEY
```

**What it finds:**
- Servers responding with your domain in headers
- SSL certificate matches
- HTTP redirect chains

**API Limits:** 100 queries/month (membership plan required for hostname search)

---

### 5. Censys
**Requires API Credentials** | [Get Free Account](https://search.censys.io/account/api)

Internet-wide scanning and certificate database.

```bash
origindive -d example.com --passive-sources censys --censys-token YOUR_PAT --censys-org-id YOUR_ORG_ID
```

**What it finds:**
- Certificate subject name matches
- HTTP virtual host configurations
- Historical scan results

**API Limits:** Varies by plan (organization ID required for v3 API)

---

### 6. ViewDNS
**Free | No API Key Required**

Simple DNS tools and IP history service.

```bash
origindive -d example.com --passive-sources viewdns
```

**What it finds:**
- IP history from DNS records
- Domain neighborhood analysis
- Reverse IP lookup results

**API Limits:** Rate limited (use with caution)

---

### 7. DNSDumpster
**Free | No API Key Required**

DNS reconnaissance and subdomain enumeration.

```bash
origindive -d example.com --passive-sources dnsdumpster
```

**What it finds:**
- Subdomain IPs
- DNS server IPs
- Mail server IPs
- Related infrastructure

**API Limits:** Rate limited per IP

---

### 8. Wayback Machine (Internet Archive)
**Free | No API Key Required**

Historical snapshots of web pages and DNS records.

```bash
origindive -d example.com --passive-sources wayback
```

**What it finds:**
- Historical IP addresses from archived pages
- IPs before CDN migration
- Long-term DNS history

**Coverage:** Depends on archive availability

---

### 9. ZoomEye
**Requires API Key** | [Get Free Account](https://www.zoomeye.org/api/login)

Cyberspace search engine for internet-connected devices.

```bash
origindive -d example.com --passive-sources zoomeye --zoomeye-key YOUR_KEY
```

**What it finds:**
- Web servers with matching certificates
- Services responding to domain name
- Port scan results

**API Limits:** Requires credits (check account for details)

---

## Configuration

### Global Configuration File

Store API keys persistently in `~/.config/origindive/config.yaml`:

```yaml
# Passive reconnaissance API keys
shodan_keys:
  - "YOUR_SHODAN_KEY"
  - "BACKUP_KEY"  # Optional: automatic rotation

censys_tokens:
  - "YOUR_CENSYS_PAT"
  
censys_org_id: "YOUR_ORG_ID"

securitytrails_key: "YOUR_ST_KEY"
virustotal_key: "YOUR_VT_KEY"
zoomeye_key: "YOUR_ZE_KEY"

# Passive source configuration
passive_sources:
  - ct
  - dns
  - shodan
  - censys
  - securitytrails
  - virustotal
  - viewdns
  - dnsdumpster
  - wayback
  - zoomeye
  
min_confidence: 0.7  # Filter low-confidence results
```

### Per-Scan Configuration

Override global settings with CLI flags or YAML config:

```yaml
# scan-config.yaml
domain: "example.com"
scan_mode: "passive"
passive_sources:
  - ct
  - virustotal
  - shodan
min_confidence: 0.8
output_format: "json"
output_file: "passive-results.json"
```

```bash
origindive --config scan-config.yaml
```

---

## Confidence Scoring

Each passive source returns IPs with confidence scores (0.0 - 1.0) based on:

1. **Source Reliability** - How trustworthy is the source?
2. **Data Freshness** - How recent is the information?
3. **Record Type** - A records vs. CNAME vs. certificate data
4. **Verification** - Cross-referenced across multiple sources?
5. **ASN Consistency** - Does IP belong to expected network?
6. **Geographic Consistency** - Expected location for target?
7. **Port Validation** - Does IP respond on expected ports?
8. **Response Similarity** - Does content match target domain?

See [SCORING_ALGORITHMS.md](SCORING_ALGORITHMS.md) for detailed scoring logic.

### Filtering Results

```bash
# High confidence only (0.8+)
origindive -d example.com --passive --min-confidence 0.8

# Medium confidence (0.5+)
origindive -d example.com --passive --min-confidence 0.5

# All results (including low confidence)
origindive -d example.com --passive --min-confidence 0.0
```

---

## Output Examples

### Text Output

```
[PASSIVE] Certificate Transparency
  ├─ 192.0.2.10 (confidence: 0.92) - Recent A record
  ├─ 192.0.2.15 (confidence: 0.85) - Certificate SAN
  └─ 192.0.2.20 (confidence: 0.78) - Historical record

[PASSIVE] Shodan
  ├─ 192.0.2.10 (confidence: 0.95) - HTTP header match
  └─ 192.0.2.25 (confidence: 0.70) - SSL certificate

[PASSIVE] VirusTotal
  ├─ 192.0.2.10 (confidence: 0.88) - Passive DNS
  └─ 192.0.2.30 (confidence: 0.65) - Old resolution

Unique IPs discovered: 5
Cross-verified (2+ sources): 1 (192.0.2.10)
High confidence (≥0.8): 3
```

### JSON Output

```json
{
  "target": "example.com",
  "scan_mode": "passive",
  "passive_ips": [
    {
      "ip": "192.0.2.10",
      "sources": ["ct", "shodan", "virustotal"],
      "confidence": 0.95,
      "first_seen": "2025-01-15T10:30:00Z",
      "last_seen": "2025-12-01T14:20:00Z",
      "asn": "AS13335",
      "asn_org": "Cloudflare, Inc.",
      "country": "US"
    }
  ]
}
```

---

## Best Practices

### 1. Start with Free Sources

```bash
# Free sources first
origindive -d example.com --passive-sources ct,viewdns,dnsdumpster,wayback
```

### 2. Use API Keys Wisely

```bash
# Paid sources for confirmed targets
origindive -d example.com --passive-sources shodan,censys,securitytrails --min-confidence 0.8
```

### 3. Cross-Verification

```bash
# Require multiple sources
origindive -d example.com --passive --min-sources 2
```

### 4. Combined Mode (Recommended)

```bash
# Passive discovery → Active validation
origindive -d example.com --passive --scan-mode auto
```

This will:
1. Query all passive sources
2. Extract unique IPs
3. Actively scan discovered IPs
4. Verify with HTTP requests

### 5. Rate Limiting

```bash
# Respect API limits with delays
origindive -d example.com --passive --api-delay 2s
```

---

## Troubleshooting

### No Results from Shodan

**Problem:** Free Shodan API only supports IP lookups, not hostname search.

**Solution:** Upgrade to membership plan or use other sources.

### Censys Returns Errors

**Problem:** Free tier requires organization ID for v3 API.

**Solution:** 
```bash
# Get org ID from https://search.censys.io/account/organization
origindive -d example.com --censys-org-id YOUR_ORG_ID
```

### Rate Limit Errors

**Problem:** Too many requests to free APIs.

**Solution:**
```bash
# Enable failover and skip on rate limit
origindive -d example.com --passive --api-failover --skip-on-rate-limit
```

### Low Confidence Results

**Problem:** Many results with confidence < 0.5.

**Solution:**
```bash
# Increase minimum confidence
origindive -d example.com --passive --min-confidence 0.7

# Or require multiple sources
origindive -d example.com --passive --min-sources 3
```

---

## API Key Management

### Multiple Keys (Rotation)

```yaml
# config.yaml
shodan_keys:
  - "KEY_1"
  - "KEY_2"
  - "KEY_3"
```

origindive automatically rotates through keys when:
- Rate limit reached
- API returns 429 Too Many Requests
- Previous key exhausted

### Key Validation

```bash
# Test API keys before scanning
origindive --test-apis
```

Output:
```
[✓] Shodan: Valid (100/100 queries remaining)
[✓] Censys: Valid (250/250 searches remaining)
[✓] VirusTotal: Valid (Rate: 4 req/min)
[✗] SecurityTrails: Invalid API key
```

---

## Advanced Usage

### Subdomain Enumeration

```bash
# Find all subdomain IPs
origindive -d example.com --passive --subdomain-enum --passive-sources dnsdumpster,ct
```

### Historical Analysis

```bash
# Focus on historical data
origindive -d example.com --passive-sources wayback,securitytrails --min-age 30d
```

### ASN Expansion

```bash
# Discover IPs → Identify ASNs → Scan full ASN
origindive -d example.com --passive --expand-asn --scan-mode auto
```

---

## See Also

- [SCORING_ALGORITHMS.md](SCORING_ALGORITHMS.md) - Detailed confidence scoring
- [ASN_LOOKUP.md](ASN_LOOKUP.md) - ASN enumeration guide
- [EXTERNAL_URLS.md](EXTERNAL_URLS.md) - API endpoint documentation
- [README.md](../README.md) - Main usage guide
