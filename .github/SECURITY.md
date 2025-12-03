# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 2.6.x   | :white_check_mark: |
| < 2.6   | :x:                |

Only the latest release receives updates. Please upgrade to the most recent version.

## Reporting a Vulnerability

If you discover a security vulnerability, please report it by:

1. **Opening a GitHub Issue** at https://github.com/jhaxce/origindive/issues
   - Label it as "security" if possible
   - Provide clear steps to reproduce

2. **Submit a Pull Request** with a fix
   - Fork the repository
   - Create a branch with your security fix
   - Submit a PR with clear description

As an independent developer, I appreciate community contributions! If you can fix the issue, submitting a PR is the fastest way to get it resolved.

## Response Time

- I'll try to respond within a few days
- Critical issues will be prioritized
- Community PRs are welcome and encouraged

## Security Best Practices

### Safe Usage

- **Only scan systems you own or have permission to test**
- **Use reasonable thread counts** (`-j 5-20`) to avoid network issues
- **Unauthorized scanning may be illegal** - always get permission first

### Tool Limitations

- Uses HTTP by default (not HTTPS)
- TLS verification is disabled (intentional for testing)
- Sends requests with "origindive" User-Agent by default
- High request rates possible with threading

## Legal Notice

This tool is for **authorized security testing only**. You are responsible for:
- Obtaining permission before scanning
- Complying with local laws
- Using the tool ethically

The developer assumes no liability for misuse.

---

**Questions?** Open an issue at https://github.com/jhaxce/origindive/issues
