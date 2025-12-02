# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.5.0] - 2025-12-02

### Added
- **CIDR Mask Application**: New feature to apply CIDR masks to single IPs in input files
  - Use `-i <file> -n /24` to scan /24 subnets for each IP in the file
  - Automatically skips network and broadcast addresses
  - Displays colored warnings for invalid entries
- Comprehensive inline code documentation throughout the codebase
- Detailed function documentation for all major functions
- Section headers for better code organization

### Changed
- Complete code reorganization with logical sections
- Enhanced `usage()` function with colored sections and better examples
- Improved help text showing all input modes with practical examples
- README.md updated with CIDR mask feature documentation
- Better terminal color detection for WSL/Kali compatibility

### Fixed
- Color initialization moved before flag parsing to ensure help text displays correctly

## [2.4.0] - 2025-12-02

### Added
- Full colored terminal output support for WSL/Kali Linux environments
- Colored scan results (GREEN for 200, YELLOW for 3xx, BLUE for timeout, RED for errors, CYAN for other)
- Colored summary output with borders and formatted statistics
- Terminal capability detection using `os.ModeCharDevice`

### Changed
- ANSI color codes changed from `\u001b` to `\033` format for better compatibility
- Color initialization happens first in main() before any output

### Fixed
- Colors not displaying in WSL/Kali terminal environments
- Help text displaying without colors

## [2.3.0] - 2025-12-02

### Added
- Positional argument support for convenience
  - `originfind <domain> <start_ip> <end_ip>` for IP range mode
  - `originfind <domain> <CIDR>` for CIDR mode
- Dynamic version constant used in User-Agent header

### Changed
- User-Agent header now uses version constant instead of hardcoded "1.0"

### Removed
- Unused `verbose` flag variable

## [2.2.0] - 2025-12-01

### Added
- Input file parsing functionality (`-i` flag)
- Support for mixed IPs and CIDR ranges in input files
- Comment support in input files (lines starting with `#`)
- Go module file (`go.mod`) with minimum Go 1.16 requirement
- Professional GitHub badges (Go Report Card, pkg.go.dev, License, Go Version)

### Changed
- README.md expanded with comprehensive documentation
- Usage examples updated to include input file mode

## [2.1.0] - 2025-12-01

### Added
- CIDR notation support with automatic subnet expansion
- Automatic network and broadcast address exclusion for /24 and larger subnets
- Special handling for /31 and /32 subnets
- CIDR reference table in README.md

### Changed
- IP range parsing improved to handle CIDR notation
- Documentation updated with CIDR examples

## [2.0.0] - 2025-12-01

### Added
- Comprehensive README.md with detailed documentation
- ASCII art banner for branding
- MIT License badge
- Installation instructions
- Usage examples and advanced scenarios
- Performance tips and use cases
- Legal disclaimer

### Changed
- Naming consistency: removed "Origin IP Finder", using only "originfind" throughout
- Project branding and documentation standardized

## [1.5.0] - 2025-12-01

### Added
- Multi-threaded scanning with worker pool pattern
- Configurable number of parallel workers (`-j` flag)
- Connection timeout configuration (`-c` flag)
- Request timeout configuration (`-t` flag)
- Custom HTTP header support (`-H` flag)
- HTTP method selection (`-m` flag)

### Changed
- Performance significantly improved with concurrent scanning
- HTTP client configuration enhanced with custom timeouts

## [1.0.0] - 2025-12-01

### Added
- Initial release
- Basic IP range scanning (start IP to end IP)
- Domain-based Host header scanning
- HTTP request functionality
- Basic error handling
- Success/failure reporting
- Simple command-line interface with `-d`, `-s`, `-e` flags

### Features
- Sequential IP scanning
- HTTP GET requests with custom Host header
- 200 OK detection for origin discovery
- Basic output formatting

---

## Version History Summary

- **2.5.0**: CIDR mask application + comprehensive documentation
- **2.4.0**: Full color support for WSL/Kali environments
- **2.3.0**: Positional arguments + dynamic versioning
- **2.2.0**: Input file support + Go module + badges
- **2.1.0**: CIDR notation support
- **2.0.0**: Complete documentation + branding
- **1.5.0**: Multi-threading + advanced HTTP configuration
- **1.0.0**: Initial release with basic scanning

[2.5.0]: https://github.com/jhaxce/originfind/releases/tag/v2.5.0
