# ASN Lookup Integration

## Overview

The `--asn` flag allows you to automatically fetch IP ranges for any Autonomous System Number (ASN) from the ipapi.is API and use them for **active scanning only** (no passive reconnaissance).

**Finding ASN Codes**: Use [whois.ipinsight.io/countries](https://whois.ipinsight.io/countries) to find ASN codes by country and organization.

**Note**: ASN scans go directly to active HTTP scanning. This is not passive reconnaissance.

## Usage

### Basic ASN Scan

```bash
# Using full ASN format
origindive -d example.com --asn AS18233

# Using numeric format (AS prefix added automatically)
origindive -d example.com --asn 18233

# Multiple ASNs (comma-separated)
origindive -d example.com --asn AS4775,AS9299,AS10139
origindive -d example.com --asn 4775,9299,17639  # Numeric format
```

### Combined with Other Flags

```bash
# ASN scan with WAF filtering
origindive -d example.com --asn AS4775 --skip-waf

# ASN scan with custom workers
origindive -d example.com --asn 9299 -j 50

# ASN scan with JSON output
origindive -d example.com --asn AS10139 -f json -o results.json
```

## How It Works

1. **API Lookup**: Queries `https://api.ipapi.is/?asn=AS18233` for IP ranges
2. **Caching**: Saves response to `~/.cache/origindive/asn/AS18233.json`
3. **Cache Duration**: Permanent (until manually deleted)
4. **Scanning**: Uses all CIDR ranges from ASN for active HTTP scanning
5. **Multiple ASNs**: When comma-separated ASNs provided, fetches and merges all ranges

## Cache Location

**Linux/macOS**: `~/.cache/origindive/asn/`  
**Windows**: `%USERPROFILE%\.cache\origindive\asn\`

## Examples

### Finding ASN Codes

Visit [whois.ipinsight.io/countries](https://whois.ipinsight.io/countries) to browse ASN codes by:
- **Country**: Filter by country code (e.g., PH for Philippines, US for United States)
- **Organization**: Search by ISP/company name
- **ASN Range**: Browse ASN allocations

### Philippine ISP ASNs

```bash
# Globe Telecoms
origindive -d example.com --asn AS4775 --skip-waf

# PLDT
origindive -d example.com --asn AS9299 --skip-waf

# Smart Broadband
origindive -d example.com --asn AS10139 --skip-waf

# Converge ICT
origindive -d example.com --asn AS17639 --skip-waf

# Scan all Philippine major ISPs at once
origindive -d example.com --asn AS4775,AS9299,AS10139,AS17639 --skip-waf -j 50
```

### View Cached Data

```bash
# Linux/macOS
cat ~/.cache/origindive/asn/AS4775.json

# Windows
type %USERPROFILE%\.cache\origindive\asn\AS4775.json
```

## Cache File Format

```json
{
  "asn": "AS4775",
  "asn_org": "Globe Telecoms",
  "asn_ranges": [
    "180.190.0.0/15",
    "1.37.0.0/16",
    "112.198.0.0/16"
  ]
}
```

**Note**: Cache is permanent. To refresh ASN data, manually delete the cache file.

## Error Handling

- **Invalid ASN**: Returns error if ASN not found
- **Network Error**: Falls back to cache if available
- **No Ranges**: Returns error if ASN has no IP ranges
- **Cache Failure**: Non-fatal, continues without caching

## Performance

- **First Run**: ~1-3 seconds (API fetch + cache save)
- **Cached Run**: <100ms (local file read)
- **Cache Refresh**: Delete cache file manually to re-fetch from API
- **Large ASNs**: Automatically deduplicates overlapping ranges

