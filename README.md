# originfind

```
              _       _       _____           __
  ____  _____(_)___ _(_)___  / __(_)___  ____/ /
 / __ \/ ___/ / __ `/ / __ \/ /_/ / __ \/ __  / 
/ /_/ / /  / / /_/ / / / / / __/ / / / / /_/ /  
\____/_/  /_/\__, /_/_/ /_/_/ /_/_/ /_/\__,_/   
            /____/
```

A powerful security analysis tool for discovering real origin server IPs hidden behind CDN/WAF services like Cloudflare, Akamai, and others.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Go Version](https://img.shields.io/badge/Go-1.16+-blue.svg)](https://golang.org/)
[![Go Report Card](https://goreportcard.com/badge/github.com/jhaxce/originfind)](https://goreportcard.com/report/github.com/jhaxce/originfind)

## 📋 Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
  - [Basic Examples](#basic-examples)
  - [Advanced Usage](#advanced-usage)
- [Options](#options)
- [Input Methods](#input-methods)
- [CIDR Reference](#cidr-reference)
- [Use Cases](#use-cases)
- [Performance Tips](#performance-tips)
- [Legal Disclaimer](#legal-disclaimer)
- [Contributing](#contributing)
- [License](#license)

## 🎯 Overview

**originfind** helps security researchers and penetration testers discover the real IP addresses of web servers that are protected by Content Delivery Networks (CDN) or Web Application Firewalls (WAF). By scanning IP ranges with custom HTTP Host headers, it identifies which servers respond to requests for a specific domain, effectively bypassing CDN protection layers.

### How It Works

When a website uses a CDN like Cloudflare:
1. DNS points to the CDN's IP addresses
2. The CDN forwards requests to the origin server
3. The origin server often has a different IP address

This tool sends HTTP requests directly to IP addresses with your target domain in the Host header. If the server responds with a 200 OK, it's likely the real origin server.

## ✨ Features

### Input Flexibility
- **IP Range**: Scan from start IP to end IP (e.g., `192.168.1.1` - `192.168.1.254`)
- **CIDR Notation**: Scan entire subnets (e.g., `192.168.1.0/24`)
- **Input File**: Load multiple IPs and CIDR ranges from a text file
- **CIDR Mask Application**: Apply CIDR masks to single IPs in input files (e.g., `-i ips.txt -n /24`)

### Advanced Features
- ⚡ **Multi-threaded scanning** for faster results
- 🎨 **Colored terminal output** (with plain-text mode for scripts)
- 📁 **Save results to file** for later analysis
- 🔧 **Custom HTTP headers** and methods
- ⏱️ **Configurable timeouts** for both connection and requests
- 📊 **Detailed scan statistics** including success rate and timing
- 🔍 **Response filtering** (show all responses or just 200 OK)
- 🤫 **Quiet mode** for minimal output

## 🚀 Installation

### Prerequisites
- Go 1.16 or higher

### Build from Source
```bash
# Clone the repository
git clone https://github.com/jhaxce/originfind.git
cd originfind

# Build the binary
go build -o originfind originfind.go

# Optional: Install system-wide (Linux/macOS)
sudo mv originfind /usr/local/bin/

# Windows
# Move originfind.exe to a directory in your PATH
```

### Install with Go

```bash
# Install directly from GitHub (requires Go)
go install github.com/jhaxce/originfind@latest

# The binary will be in $GOPATH/bin or ~/go/bin
```

## 📖 Usage

### Basic Examples

#### Scan an IP Range
```bash
./originfind example.com 192.168.1.1 192.168.1.254

# Or with flags
./originfind -d example.com -s 192.168.1.1 -e 192.168.1.254
```

#### Scan a CIDR Subnet
```bash
# Scan entire /24 subnet (256 IPs)
./originfind -d example.com -n 192.168.1.0/24

# Scan smaller subnet (16 IPs)
./originfind -d example.com -n 192.168.1.0/28
```

#### Use an Input File
```bash
# Create input file with IPs and CIDRs
cat > targets.txt << EOF
# Cloudflare ranges
104.16.0.0/24
104.17.0.0/24

# Single IPs
192.168.1.100
192.168.1.200
EOF

# Scan from file
./originfind -d example.com -i targets.txt
```

### Advanced Usage

#### Fast Scanning with Multiple Threads
```bash
# Use 10 parallel workers (10x faster)
./originfind -d example.com -n 23.192.228.0/24 -j 10

# Aggressive scanning with 20 threads
./originfind -d example.com -i large-list.txt -j 20
```

#### Apply CIDR Mask to Input File IPs
```bash
# If you have individual IPs and want to scan their /24 subnets
cat > single-ips.txt << EOF
104.16.132.5
104.17.84.12
23.192.228.100
EOF

# Apply /24 mask to each IP (scans 3 full /24 subnets = 768 IPs total)
./originfind -d example.com -i single-ips.txt -n /24 -j 15

# Smaller subnet with /28 mask (16 IPs per entry)
./originfind -d example.com -i single-ips.txt -n /28 -j 10
```

#### Save Results and Show All Responses
```bash
# Save all findings to file and show redirects/errors
./originfind -d example.com -n 192.168.0.0/24 -a -o results.txt

# Quiet mode with file output only
./originfind -d example.com -n 10.0.0.0/24 -q -o origin-ips.txt
```

#### Custom Headers and Methods
```bash
# Add custom header
./originfind -d example.com -n 192.168.1.0/24 -H "X-Forwarded-For: 1.2.3.4"

# Use HEAD method instead of GET
./originfind -d example.com -n 192.168.1.0/24 -m HEAD

# Combine with increased timeout
./originfind -d example.com -n 192.168.1.0/24 -t 10 -c 5
```

#### Plain Text Output (for WSL/Piping)
```bash
# Disable colors for better compatibility
./originfind -d example.com -n 192.168.1.0/24 -p -j 10

# Pipe to grep for filtering
./originfind -d example.com -i targets.txt -p | grep "200 OK"
```

## ⚙️ Options

| Flag | Long Form | Description | Default |
|------|-----------|-------------|---------|
| `-d` | `--domain` | Target domain (required) | - |
| `-s` | `--start` | Start IP address | - |
| `-e` | `--end` | End IP address | - |
| `-n` | `--subnet` | CIDR subnet notation | - |
| `-i` | `--input` | Input file with IPs/CIDRs | - |
| `-j` | `--threads` | Number of parallel workers | 1 |
| `-t` | `--timeout` | Request timeout (seconds) | 5 |
| `-c` | `--connect-timeout` | Connection timeout (seconds) | 3 |
| `-o` | `--output` | Save results to file | - |
| `-H` | `--header` | Add custom HTTP header | - |
| `-m` | `--method` | HTTP method (GET, HEAD, POST) | GET |
| `-a` | `--show-all` | Show all responses (not just 200) | false |
| `-v` | `--verbose` | Verbose output | false |
| `-q` | `--quiet` | Quiet mode (minimal output) | false |
| `-p` | `--plain` | Plain text (no colors) | false |
| | `--no-color` | Disable colored output | false |
| `-V` | `--version` | Show version information | - |
| `-h` | `--help` | Show help message | - |

## 📝 Input Methods

### 1. IP Range Mode
Scan from a start IP to an end IP (inclusive):
```bash
./originfind -d example.com -s 192.168.1.1 -e 192.168.1.100
```

### 2. CIDR Mode
Scan an entire subnet using CIDR notation:
```bash
./originfind -d example.com -n 192.168.1.0/24
```

### 3. Input File Mode
Create a text file with IPs and/or CIDR ranges (one per line):

**targets.txt:**
```
# Cloudflare IP ranges
104.16.0.0/24
104.17.0.0/25

# Akamai ranges
23.192.228.0/24

# Single IPs to check
192.168.1.100
10.0.0.50

# Comments and empty lines are ignored
```

Then run:
```bash
./originfind -d example.com -i targets.txt -j 10
```

### 4. Input File with CIDR Mask
Apply a CIDR mask to all single IPs in an input file. This is useful when you have a list of individual IPs and want to scan their surrounding subnets.

**single-ips.txt:**
```
192.168.1.100
10.0.0.50
172.16.5.200
```

Apply /24 mask to each IP (scans entire /24 subnet for each):
```bash
# This will scan:
# - 192.168.1.0/24 (256 IPs)
# - 10.0.0.0/24 (256 IPs)
# - 172.16.5.0/24 (256 IPs)
./originfind -d example.com -i single-ips.txt -n /24 -j 10
```

**How it works:**
- Single IPs in the file get the mask applied (e.g., `192.168.1.100` + `/24` = `192.168.1.0/24`)
- Existing CIDR ranges in the file remain unchanged
- Invalid IPs or formats are skipped with warnings
- Network and broadcast addresses are automatically excluded

## 📊 CIDR Reference

Understanding CIDR notation for subnet scanning:

| CIDR | Netmask | Total IPs | Usable IPs | Use Case |
|------|---------|-----------|------------|----------|
| /32 | 255.255.255.255 | 1 | 1 | Single host |
| /31 | 255.255.255.254 | 2 | 2 | Point-to-point |
| /30 | 255.255.255.252 | 4 | 2 | Small subnet |
| /29 | 255.255.255.248 | 8 | 6 | Tiny network |
| /28 | 255.255.255.240 | 16 | 14 | Small network |
| /27 | 255.255.255.224 | 32 | 30 | Medium network |
| /26 | 255.255.255.192 | 64 | 62 | Larger network |
| /25 | 255.255.255.128 | 128 | 126 | Half class C |
| /24 | 255.255.255.0 | 256 | 254 | Full class C |
| /23 | 255.255.254.0 | 512 | 510 | 2x class C |
| /22 | 255.255.252.0 | 1024 | 1022 | 4x class C |
| /21 | 255.255.248.0 | 2048 | 2046 | Large subnet |
| /16 | 255.255.0.0 | 65536 | 65534 | Class B network |

**Note**: The tool automatically excludes network and broadcast addresses for /24 and larger subnets.

## 🎯 Use Cases

### 1. Bug Bounty & Security Research
Find origin IPs to test for:
- Rate limiting bypass
- WAF bypass techniques
- Direct access vulnerabilities
- Information disclosure

```bash
# Check if Cloudflare-protected site has exposed origin
./originfind -d target.com -n 104.16.0.0/16 -j 20 -o findings.txt
```

### 2. Penetration Testing
During authorized security assessments:
- Map infrastructure behind CDN
- Identify unprotected admin panels
- Test origin server security

```bash
# Comprehensive scan with verbose output
./originfind -d client-site.com -i ip-ranges.txt -j 15 -v -a
```

### 3. Infrastructure Mapping
Document your own infrastructure:
- Verify CDN configuration
- Ensure origin servers aren't exposed
- Monitor for configuration drift

```bash
# Regular scan with results archive
./originfind -d mysite.com -n 10.0.0.0/24 -o scan-$(date +%Y%m%d).txt
```

### 4. Historical IP Discovery
Combined with services like SecurityTrails or Shodan:
```bash
# Create input file from historical DNS records
# Then scan to verify if IPs still respond
./originfind -d target.com -i historical-ips.txt
```

## ⚡ Performance Tips

### Thread Recommendations

| IPs to Scan | Recommended Threads | Scan Time (est.) |
|-------------|---------------------|------------------|
| < 50 | 1-5 | Seconds |
| 50-256 | 5-10 | 1-2 minutes |
| 256-1024 | 10-20 | 2-5 minutes |
| 1024+ | 20-50 | 5+ minutes |

**Warning**: Using too many threads may:
- Trigger rate limiting
- Get your IP blocked
- Overwhelm the target network
- Produce false negatives

### Optimization Examples

```bash
# Fast scan for small range
./originfind -d example.com -n 192.168.1.0/26 -j 5 -t 3

# Balanced scan for /24
./originfind -d example.com -n 192.168.1.0/24 -j 10 -t 5

# Conservative scan for large range
./originfind -d example.com -n 192.168.0.0/16 -j 5 -t 10
```

### Network Considerations

- **High latency networks**: Increase `-t` and `-c` timeouts
- **Rate-limited targets**: Reduce thread count (`-j`)
- **Local networks**: Can use higher thread counts safely
- **Internet targets**: Be conservative with threads (5-10)

## 🔒 Legal Disclaimer

**IMPORTANT**: This tool is provided for educational and authorized security testing purposes only.

### Authorized Use Only
- ✅ Your own infrastructure and domains
- ✅ With explicit written permission from the target owner
- ✅ During authorized penetration testing engagements
- ✅ Bug bounty programs that permit such testing
- ✅ Educational purposes in controlled lab environments

### Prohibited Use
- ❌ Unauthorized scanning of third-party systems
- ❌ Malicious intent or illegal activities
- ❌ Violating terms of service or laws
- ❌ Causing harm or disruption to services

### Your Responsibility
By using this tool, you agree to:
1. Comply with all applicable laws and regulations
2. Obtain proper authorization before scanning
3. Use the tool responsibly and ethically
4. Accept full responsibility for your actions

**The authors and contributors are not responsible for misuse or any damage caused by this tool.**

## 🛡️ Detection and Mitigation

### For Defenders
If you want to prevent origin IP discovery:

1. **Firewall Rules**: Only allow traffic from CDN IP ranges
2. **Different Origin Headers**: Use unique internal hostnames
3. **Certificate Validation**: Ensure SSL/TLS is properly configured
4. **Rate Limiting**: Implement strict rate limiting on origin
5. **Monitoring**: Alert on direct origin access attempts

### Detection Signatures
This tool can be detected by:
- Multiple requests with identical Host headers
- Sequential IP scanning patterns
- Unusual user-agent strings
- Failed connection attempts

## 🤝 Contributing

Contributions are welcome! Here's how you can help:

### Reporting Issues
- Check existing issues first
- Provide detailed reproduction steps
- Include version information and OS

### Pull Requests
1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Development Guidelines
- Follow existing code style
- Add comments for complex logic
- Test on multiple platforms
- Update documentation as needed

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 👤 Author

**jhaxce**
- GitHub: [@jhaxce](https://github.com/jhaxce)

## 🙏 Acknowledgments

- Inspired by various CDN bypass techniques
- Built for the security research community
- Thanks to all contributors and testers

## 📚 Additional Resources

### Related Tools
- [CloudFlair](https://github.com/christophetd/CloudFlair) - Find origin servers of websites behind CloudFlare
- [CrimeFlare](http://www.crimeflare.org:82/cfs.html) - CloudFlare IP database
- [SecurityTrails](https://securitytrails.com/) - Historical DNS data

### Learning Resources
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [Bug Bounty Methodology](https://github.com/jhaddix/tbhm)
- [CDN Bypass Techniques](https://www.secjuice.com/finding-real-ips-of-origin-servers/)

## 📞 Support

- 🐛 **Bug Reports**: [GitHub Issues](https://github.com/jhaxce/originfind/issues)
- 📧 **Security Issues**: Report privately via GitHub Security Advisories

---

**⭐ If you find this tool useful, please consider giving it a star on GitHub!**

