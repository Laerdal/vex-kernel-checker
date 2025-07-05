# Security Policy

## Supported Versions

We actively support the following versions of VEX Kernel Checker:

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |
| < 1.0   | :x:                |

## Reporting a Vulnerability

We take security vulnerabilities seriously. If you discover a security issue in VEX Kernel Checker, please report it responsibly.

### How to Report

1. **Email**: Send details to <security@laerdal.com>
2. **Subject**: Include "[VEX Kernel Checker Security]" in the subject line
3. **Content**: Provide as much detail as possible:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if available)

### What to Expect

- **Acknowledgment**: We will acknowledge receipt within 48 hours
- **Initial Assessment**: Within 5 business days, we'll provide an initial assessment
- **Updates**: We'll keep you informed of our progress
- **Resolution**: We aim to resolve critical issues within 30 days

### Security Best Practices

When using VEX Kernel Checker:

1. **API Keys**: Store NVD API keys securely, never commit them to version control
2. **Network Access**: Be cautious when allowing the tool network access in production environments
3. **File Permissions**: Ensure configuration files have appropriate permissions
4. **Updates**: Keep the tool updated to the latest version
5. **Validation**: Always validate VEX files from external sources

### Scope

This security policy covers:

- The core VEX Kernel Checker tool
- Configuration parsing and validation
- API interactions with NVD and patch sources
- File system operations

### Out of Scope

- Security issues in dependencies (report to respective maintainers)
- General Linux kernel vulnerabilities (report to kernel security team)
- Issues in external VEX files or data sources

### Responsible Disclosure

We follow responsible disclosure principles:

- We'll work with you to understand and address the issue
- We'll credit you in security advisories (if desired)
- We ask that you don't publicly disclose until we've had a chance to fix the issue

### Security Updates

Security updates will be:

- Released as patch versions (e.g., 1.0.1)
- Documented in security advisories
- Announced through our release channels

Thank you for helping keep VEX Kernel Checker secure!
