# origindive v3.2.0 Release Notes

**Release Date**: December 5, 2025

## 🔗 Smart Redirect Following & False Positive Detection

This release introduces intelligent redirect chain following with Host header validation, enabling accurate distinction between real origin servers and shared hosting false positives.

---

## 🌟 Highlights

### 1. Redirect Chain Following (`--follow-redirect`)

Track complete HTTP redirect chains while preserving IP testing:

```bash
# Follow up to 10 redirects (default)
origindive -d example.com -i ips.txt --follow-redirect

# Custom max redirects
origindive -d example.com -i ips.txt --follow-redirect=5
```

**Features**:
- ✅ IP-preserving: Tests same IP through entire redirect chain
- ✅ Full tracking: Records 301/302 → HTTPS → final destination
- ✅ Inline display: Shows redirect chain with each result
- ✅ Smart handling: Doesn't jump to different servers

**Example Output**:
```
[+] 203.0.113.10 --> 200 OK (1.4s) | "Example Site" [hash]
    Redirect chain:
      1. 301 http://203.0.113.10 -> https://example.com:443/
```

### 2. False Positive Detection via Host Header Validation

Automatically identifies shared hosting false positives:

```bash
# Validation runs automatically when --follow-redirect is enabled
origindive -d example.com -i ips.txt --follow-redirect
```

**How It Works**:
1. Main scan: Tests IPs WITH `Host: example.com` header (fast)
2. Validation: Re-tests successful IPs WITHOUT Host header  
3. Comparison: Detects IPs that behave differently
4. Flagging: Adds ⚠️ warning to redirect chain

**Example - False Positive Detected**:
```
[+] 203.0.113.20 --> 200 OK (545ms) [hash]
    Redirect chain:
      1. 301 http://203.0.113.20 -> https://example.com:443/
      2. ⚠ Without Host header: https://203.0.113.20:443/ (different from https://example.com:443/)
```

**Why This Matters**:
- Cloud load balancers (GCP, AWS, Azure) honor Host headers
- Shared hosting servers respond based on requested domain
- Without validation: 15/16 IPs appear to serve target domain
- With validation: Only 1/16 is real origin, rest flagged as suspicious

### 3. Enhanced Summary Display

Clear separation between verified origins and potential false positives:

```
═══════════════════════════════════════════════════════════════
Scan Results Summary
═══════════════════════════════════════════════════════════════
[+] Found: 203.0.113.10
[+] 200 OK: 6 (203.0.113.15, 203.0.113.20, 203.0.113.25, 203.0.113.30, 203.0.113.35, 203.0.113.10)
[*] Total Scanned: 27
[T] Duration: 12.39s
[R] Scan Rate: 2.18 IPs/s
═══════════════════════════════════════════════════════════════
```

**Summary Lines**:
- `[+] Found:` - Verified origins without warnings (real origin servers)
- `[+] 200 OK:` - All responses including potential false positives
- Line only appears if verified origins exist

---

## 📊 Performance Metrics

**Validation Overhead**:
- Main scan: ~7 seconds (27 IPs)
- Validation: ~5 seconds (6 successful IPs)
- **Total**: ~12 seconds (71% overhead)

**Trade-off**: Extra time identifies false positives accurately!

**Example Results**:
- 6 IPs returned 200 OK
- 5 flagged as false positives (83%)
- **1 verified origin found** (the real server!)

---

## 🚀 Usage Examples

### Basic Redirect Following

```bash
# Default: follow up to 10 redirects
origindive -d example.com -i targets.txt --follow-redirect

# Custom max: 5 redirects
origindive -d example.com --asn AS4775 --skip-waf --follow-redirect=5
```

### With Content Verification

```bash
# Redirect + content hash + title extraction
origindive -d example.com -i ips.txt --follow-redirect --verify

# Show only unique responses
origindive -d example.com -i ips.txt --follow-redirect --verify --filter-unique
```

### Large ASN Scans

```bash
# Comprehensive scan with all features
origindive -d example.com \
  --asn AS18233 \
  --skip-waf \
  --follow-redirect=3 \
  --verify \
  --filter-unique \
  -j 20
```

---

## 🔧 Technical Details

### Redirect Handling

**Location**: `pkg/scanner/scanner.go`

**Implementation**:
```go
CheckRedirect: func(req *http.Request, via []*http.Request) error {
    // Record redirect in chain
    redirectURL := req.URL.String()
    entry := fmt.Sprintf("%d %s -> %s", statusCode, originalURL, redirectURL)
    
    // Preserve IP: rewrite URL but keep Host header
    originalIP := via[0].URL.Host
    req.URL.Host = originalIP
    req.Host = redirectedDomain
    
    return nil
}
```

### Validation Logic

**Location**: `pkg/scanner/scanner.go:validateSuccessfulIPs()`

**Process**:
1. Create HTTP client without Host header manipulation
2. Test each successful IP naturally (no Host header set)
3. Follow redirects to final destination
4. Compare natural destination vs Host-header destination
5. Flag mismatches as potential false positives

**Smart Comparison**:
- ✅ Ignores HTTP→HTTPS upgrades (same server, different protocol)
- ✅ Ignores IP vs domain in URL (e.g., `203.0.113.10` vs `example.com`)
- ⚠️ Flags different paths/domains (e.g., `/cbs/a/login` vs `/`)

---

## 🔄 Migration from v3.1.0

**Breaking Changes**: None! All v3.1.0 commands work in v3.2.0.

**New Features (Optional)**:

```bash
# v3.1.0 (still works)
origindive -d example.com -i ips.txt

# v3.2.0 (with new features)
origindive -d example.com -i ips.txt --follow-redirect
```

**Output Changes** (non-breaking):
- Redirect chains may appear under 200 OK results
- Summary includes `[+] Found:` line for verified origins
- Warnings (⚠️) appear as redirect chain entries

---

## 📦 Installation

### Download Pre-built Binary

```bash
# Linux AMD64
wget https://github.com/jhaxce/origindive/releases/download/v3.2.0/origindive-linux-amd64-v3.2.0.tar.gz
tar xzf origindive-linux-amd64-v3.2.0.tar.gz
sudo mv origindive /usr/local/bin/

# Windows AMD64
# Download: https://github.com/jhaxce/origindive/releases/download/v3.2.0/origindive-windows-amd64-v3.2.0.zip
```

### Build from Source

```bash
git clone https://github.com/jhaxce/origindive.git
cd origindive
git checkout v3.2.0
go build -ldflags="-s -w" -o origindive cmd/origindive/main.go
```

### Update from v3.1.0

```bash
# Using built-in updater
origindive --update

# Or download manually
# https://github.com/jhaxce/origindive/releases/tag/v3.2.0
```

---

## 🐛 Known Issues

**1. Validation adds 3-5 seconds per 6 successful IPs**
- Expected behavior for thorough validation
- Only validates 200 OK responses (not all scanned IPs)
- Minimal overhead for typical scans

**2. HTTP→HTTPS redirects show IP vs domain difference**
- Not a bug: Natural HTTPS redirect uses IP in URL
- Validation checks final destination, not intermediate URLs
- Real origins: Natural destination matches target domain
- False positives: Natural destination goes elsewhere

---

## 📝 Changelog

See [CHANGELOG.md](CHANGELOG.md) for complete version history.

**Key Changes in v3.2.0**:
- Added `--follow-redirect[=N]` flag for redirect chain following
- Added automatic Host header validation for false positive detection
- Added verified origins display in summary (`[+] Found:`)
- Enhanced redirect chain display (inline with results)
- Improved summary formatting (verified vs all 200 OK)

---

## 🙏 Credits

- **Author**: [jhaxce](https://github.com/jhaxce)
- **Contributors**: Community testers and feedback providers
- **Inspiration**: Security research community

---

## 📄 License

MIT License - see [LICENSE](LICENSE) for details.

---

## 🔗 Links

- **Repository**: https://github.com/jhaxce/origindive
- **Release**: https://github.com/jhaxce/origindive/releases/tag/v3.2.0
- **Issues**: https://github.com/jhaxce/origindive/issues
- **Documentation**: https://github.com/jhaxce/origindive#readme

---

**Made with ❤️ for the security research community**

Enjoy accurate origin discovery with v3.2.0! 🎉
