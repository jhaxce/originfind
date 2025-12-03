# origindive

```
              _       _           ___          
  ____  _____(_)___ _(_)___  ____/ (_)   _____ 
 / __ \/ ___/ / __ `/ / __ \/ __  / / | / / _ \
/ /_/ / /  / / /_/ / / / / / /_/ / /| |/ /  __/
\____/_/  /_/\__, /_/_/ /_/\__,_/_/ |___/\___/ 
            /____/
```

**Dive deep to discover origin servers** - A powerful security analysis tool for discovering real origin server IPs hidden behind CDN/WAF services through both passive reconnaissance and active scanning.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Go Version](https://img.shields.io/badge/Go-1.23+-blue.svg)](https://golang.org/)
[![Release](https://img.shields.io/github/v/release/jhaxce/origindive)](https://github.com/jhaxce/origindive/releases)
[![Go Report Card](https://goreportcard.com/badge/github.com/jhaxce/origindive/v3)](https://goreportcard.com/report/github.com/jhaxce/origindive/v3)
[![codecov](https://codecov.io/gh/jhaxce/origindive/branch/main/graph/badge.svg)](https://codecov.io/gh/jhaxce/origindive)
[![Go Reference](https://pkg.go.dev/badge/github.com/jhaxce/origindive/v3.svg)](https://pkg.go.dev/github.com/jhaxce/origindive/v3)

## 📋 Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Usage](#usage)
- [WAF Filtering](#waf-filtering)
- [Configuration](#configuration)
- [Output Formats](#output-formats)
- [Migration from v2.x](#migration-from-v2x)
- [Contributing](#contributing)
- [License](#license)

## 🎯 Overview

**origindive** (formerly originfind) helps security researchers and penetration testers discover the real IP addresses of web servers that are protected by Content Delivery Networks (CDN) or Web Application Firewalls (WAF). 

### Key Capabilities

- **Active Scanning**: Test IP ranges with custom Host headers to identify origin servers
- **WAF Filtering**: Automatically skip known CDN/WAF IP ranges (Cloudflare, AWS, Fastly, Akamai, etc.)
- **Passive Reconnaissance**: Discover potential IPs through OSINT sources (coming soon)
- **Multi-Format Output**: Export results as text, JSON, or CSV

### How It Works

When a website uses a CDN like Cloudflare:
1. DNS points to the CDN's IP addresses  
2. The CDN forwards requests to the origin server
3. The origin server often has a different, hidden IP address

origindive sends HTTP requests directly to IP addresses with your target domain in the Host header. If the server responds with a 200 OK, it's likely the real origin server.

## ✨ Features

### v3.0 New Features

- **⭐ WAF/CDN IP Filtering** - Automatically skip 108+ known CDN/WAF ranges
  - Saves massive time by filtering Cloudflare, AWS CloudFront, Fastly, Akamai, Incapsula, Sucuri
  - Auto-updates from official provider APIs
  - Custom WAF ranges support (JSON or plain text)
  - Per-provider statistics
  
- **📁 Flexible Input** - Multiple ways to specify targets
  - Single IP ranges (`-s start -e end`)
  - CIDR notation (`-n 192.168.1.0/24`)
  - Input files with mixed formats (IPs, CIDRs, ranges)
  - Comments and blank lines supported in files
  
- **⚙️ YAML Configuration** - Save your scan preferences
  - Load settings from config file (`--config config.yaml`)
  - CLI flags override config file values
  - Shareable configs across team
  
- **🔄 Self-Update** - Stay up to date effortlessly
  - Check and install latest release (`--update`)
  - Downloads from GitHub releases
  - Automatic binary replacement
  
- **Modular Architecture** - Clean, maintainable codebase
  - Separated packages for core, scanner, WAF, IP utilities, output
  - Easy to extend and customize
  
- **Enhanced Output** - Multiple export formats
  - Colored text output
  - JSON for programmatic use
  - CSV for spreadsheets

### Core Features

- ✅ Multi-threaded IP range scanning with configurable workers
- ✅ CIDR notation support (`192.168.1.0/24`)
- ✅ Input file support (mixed IPs, CIDRs, and ranges)
- ✅ Custom WAF ranges (JSON or text format)
- ✅ Real-time progress bar with ETA
- ✅ Custom HTTP headers and methods
- ✅ Configurable timeouts
- ✅ Private/reserved IP detection
- ✅ Cross-platform (Windows, Linux, macOS)
- ✅ Auto-update functionality

## 🚀 Installation

### Prerequisites
- Go 1.23 or higher

### Download Pre-built Binary

Download the latest release for your platform:

```bash
# Linux/macOS
curl -L https://github.com/jhaxce/origindive/releases/latest/download/origindive-linux-amd64.tar.gz | tar xz
sudo mv origindive /usr/local/bin/

# Or download from releases page
# https://github.com/jhaxce/origindive/releases
```

### Build from Source

```bash
# Clone the repository
git clone https://github.com/jhaxce/origindive.git
cd origindive

# Build
go build -o origindive cmd/origindive/main.go

# Install system-wide (optional)
sudo mv origindive /usr/local/bin/

# Windows
# Move origindive.exe to a directory in your PATH
```

### Install with Go

```bash
go install github.com/jhaxce/origindive/v3/cmd/origindive@latest

# The binary will be in $GOPATH/bin or ~/go/bin
```

## 🏃 Quick Start

```bash
# Basic IP range scan
origindive -d example.com -s 192.168.1.1 -e 192.168.1.254

# CIDR subnet with 10 workers
origindive -d example.com -n 192.168.1.0/24 -j 10

# Scan with WAF filtering enabled
origindive -d example.com -n 23.0.0.0/16 --skip-waf -j 20

# Scan IPs from a file
origindive -d example.com -i ips.txt --skip-waf

# Use configuration file
origindive --config config.yaml

# Check for updates
origindive --update
```

## 📖 Usage

### Basic Usage

```bash
# Scan IP range
origindive -d example.com -s 23.192.228.1 -e 23.192.228.254

# Scan CIDR
origindive -d example.com -n 23.192.228.0/24

# Scan from file (supports IPs, CIDRs, ranges, comments)
origindive -d example.com -i targets.txt

# Use YAML config file
origindive --config myconfig.yaml
```

### Input File Format

The `-i/--input` flag accepts files with mixed IP formats:

```text
# Single IPs
192.168.1.1
10.0.0.5

# CIDR notation
192.168.1.0/24
10.0.0.0/16

# IP ranges
192.168.1.1-192.168.1.254

# Comments and blank lines are ignored
```

### Configuration File

Create a `config.yaml` file (see `configs/example.yaml`):

```yaml
domain: "example.com"
cidr: "192.168.1.0/24"
skip_waf: true
workers: 20
timeout: "10s"
format: "json"
output_file: "results.json"
```

Then run:

```bash
origindive --config config.yaml

# Override config file settings with CLI flags
origindive --config config.yaml -d different.com -j 50
```

### Self-Update

```bash
# Check for and install latest release
origindive --update
```

### Active Scanning

#### IP Range Mode
```bash
# Scan from start to end IP
origindive -d example.com -s 23.192.228.1 -e 23.192.228.254
```

#### CIDR Mode
```bash
# Scan a /24 subnet
origindive -d example.com -n 23.192.228.0/24

# Larger subnet with more workers
origindive -d example.com -n 10.0.0.0/16 -j 50
```

#### Input File Mode
```bash
# File with IPs and CIDRs
origindive -d example.com -i targets.txt -j 20

# Apply /24 mask to single IPs in file
origindive -d example.com -i ips.txt -n /24
```

**targets.txt example:**
```
# Cloudflare bypass attempt
104.16.0.0/24
104.17.0.0/24

# Single IPs
192.168.1.100
10.0.0.50

# Comments are ignored
```

### Common Flags

```
Target:
  -d, --domain string       Target domain (required)
  
IP Range (choose one):
  -s, --start-ip string     Start IP address
  -e, --end-ip string       End IP address
  -n, --cidr string         CIDR notation (e.g., 192.168.0.0/24)
  -i, --input string        Input file with IPs/CIDRs/ranges
  
Configuration:
  --config string           Load settings from YAML file
  --update                  Check and install latest version
  
Performance:
  -j, --threads int         Parallel workers (default: 10)
  -t, --timeout int         HTTP timeout in seconds (default: 5)
  -c, --connect-timeout int TCP connect timeout (default: 3)
  
WAF Filtering:
  --skip-waf                Skip all known WAF/CDN IPs
  --skip-providers string   Skip specific providers (comma-separated)
  --custom-waf-file string  Custom WAF ranges file (JSON or text)
  --show-skipped            Display skipped IPs
  --no-waf-update           Disable WAF database auto-update
  
Output:
  -o, --output string       Save results to file
  -f, --format string       Output format: text|json|csv (default: text)
  -q, --quiet               Minimal output
  -a, --show-all            Show all responses (not just 200 OK)
  --no-color                Disable colored output
  --no-progress             Disable progress bar
  
HTTP:
  -m, --method string       HTTP method (default: GET)
  -H, --header string       Custom header (format: "Name: value")
  --no-ua                   Disable User-Agent header
  
Config:
  --config string           Load settings from YAML file
```

## 🛡️ WAF Filtering

One of the killer features of origindive v3 is intelligent WAF/CDN filtering.

### Why WAF Filtering?

When scanning large IP ranges, you'll waste time testing known CDN/WAF IPs that will never be origin servers. origindive maintains a database of 108+ CIDR ranges for major providers.

### Usage

```bash
# Skip all known WAF IPs
origindive -d example.com -n 0.0.0.0/8 --skip-waf -j 50

# Skip only Cloudflare and AWS
origindive -d example.com -i targets.txt --skip-providers cloudflare,aws-cloudfront

# Show what gets skipped
origindive -d example.com -n 23.0.0.0/16 --skip-waf --show-skipped

# Use custom WAF ranges
origindive -d example.com -n 10.0.0.0/8 --custom-waf my-waf-ranges.txt
```

### Supported Providers

- **Cloudflare** - 15 ranges
- **AWS CloudFront** - 44 ranges
- **Fastly** - 18 ranges
- **Akamai** - 12 ranges
- **Incapsula/Imperva** - 12 ranges
- **Sucuri** - 7 ranges

### WAF Management

```bash
# List all known providers
origindive waf list

# Update WAF ranges from official APIs
origindive waf update

# Check when last updated
origindive waf info
```

### Auto-Updates

WAF ranges are automatically updated weekly from official provider APIs:
- Cloudflare: https://www.cloudflare.com/ips-v4
- AWS: https://ip-ranges.amazonaws.com/ip-ranges.json
- Fastly: https://api.fastly.com/public-ip-list

Disable with `--no-waf-update` flag.

## ⚙️ Configuration

### YAML Configuration File

Create `origindive.yaml`:

```yaml
# Target configuration
domain: "example.com"

# IP ranges
cidr: "192.168.1.0/24"
# or use: start_ip / end_ip / input_file

# Performance
workers: 20
timeout: "5s"
connect_timeout: "3s"

# WAF filtering
skip_waf: true
skip_providers:
  - cloudflare
  - aws-cloudfront
show_skipped: false

# Output
output_file: "results.json"
format: "json"
show_all: false

# HTTP
http_method: "GET"
```

Use with:
```bash
origindive --config origindive.yaml
```

See `configs/example.yaml` for all options.

## 📊 Output Formats

### Text (Default)

```
[+] 192.168.1.100 --> 200 OK (23.45ms)
[+] 192.168.1.105 --> 200 OK (19.32ms)
[>] 192.168.1.120 --> HTTP 301 (Redirect)
```

### JSON

```bash
origindive -d example.com -n 192.168.1.0/24 -f json -o results.json
```

```json
{
  "domain": "example.com",
  "mode": "active",
  "success": [
    {
      "ip": "192.168.1.100",
      "status": "200",
      "http_code": 200,
      "response_time": "23.45ms"
    }
  ],
  "summary": {
    "total_ips": 254,
    "scanned_ips": 254,
    "skipped_ips": 0,
    "success_count": 2,
    "duration": "12.5s"
  }
}
```

### CSV

```bash
origindive -d example.com -n 192.168.1.0/24 -f csv -o results.csv
```

```csv
IP,Status,HTTPCode,ResponseTime,Error
192.168.1.100,200,200,23.45ms,
192.168.1.105,200,200,19.32ms,
```

## 🔄 Migration from v2.x

origindive v3.0 is a complete rewrite. Key changes:

### Breaking Changes

| v2.x (originfind) | v3.0 (origindive) |
|-------------------|-------------------|
| `originfind` | `origindive` |
| No WAF filtering | `--skip-waf` flag |
| Text output only | `--format text\|json\|csv` |
| No config files | `--config yaml` support |
| Go 1.16+ | Go 1.23+ required |

### Command Migration

```bash
# v2.x (legacy originfind)
originfind -d example.com -n 192.168.1.0/24 -j 10 -o results.txt

# v3.0 equivalent
origindive -d example.com -n 192.168.1.0/24 -j 10 -o results.txt

# v3.0 with WAF filtering
origindive -d example.com -n 192.168.1.0/24 -j 10 --skip-waf -o results.txt
```

Most flags remain the same. See `MIGRATION.md` for detailed guide.

## 📈 Performance Tips

- **Workers**: 10-20 for internet scans, 50+ for local networks
- **WAF Filtering**: Always use `--skip-waf` for large scans
- **Progress Bar**: Disable with `--no-progress` for scripting
- **Output**: Use JSON format for parsing results programmatically

## 🔒 Legal Disclaimer

**IMPORTANT**: Only scan systems you are authorized to test.

- Unauthorized scanning may be illegal in your jurisdiction
- Always obtain explicit permission before testing
- Use responsibly for security research and penetration testing
- The authors are not responsible for misuse

## 🤝 Contributing

Contributions welcome! Please read [CONTRIBUTING.md](.github/CONTRIBUTING.md).

## 📄 License

MIT License - see [LICENSE](LICENSE) for details.

## 🙏 Acknowledgments

- Built with Go's excellent standard library
- Inspired by the security research community
- WAF ranges sourced from official provider APIs

---

**Made with ❤️ by [jhaxce](https://github.com/jhaxce)**

For issues and feature requests: https://github.com/jhaxce/origindive/issues
