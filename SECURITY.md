# Security Policy

## Supported Versions

We actively support security updates for the following versions:

| Version | Supported          |
| ------- | ------------------ |
| 2.2.x   | :white_check_mark: |
| 2.1.x   | :white_check_mark: |
| 2.0.x   | :white_check_mark: |
| < 2.0   | :x:                |

## Reporting a Vulnerability

We take security vulnerabilities seriously. If you discover a security vulnerability, please follow these steps:

### 1. **Do NOT** open a public GitHub issue

Security vulnerabilities should be reported privately to prevent exploitation before a fix is available.

### 2. Report via Email

Send an email to: **essenzenk@outlook.com**

Include the following information:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)
- Your contact information

### 3. What to Expect

- **Initial Response**: Within 48 hours
- **Status Update**: Within 7 days
- **Resolution Timeline**: Depends on severity, typically 30-90 days

### 4. Disclosure Process

We follow a **coordinated disclosure** process:

1. **Report Received**: We acknowledge receipt and begin investigation
2. **Verification**: We verify the vulnerability and assess severity
3. **Fix Development**: We develop and test a fix
4. **Release**: We release the fix in a security update
5. **Public Disclosure**: After the fix is released, we may disclose details (with your permission)

### 5. Severity Levels

We use the following severity classification:

- **Critical**: Remote code execution, authentication bypass, data breach
- **High**: Privilege escalation, sensitive data exposure
- **Medium**: Information disclosure, denial of service
- **Low**: Minor information leakage, best practice violations

## Security Best Practices

### For Users

1. **Keep Dependencies Updated**: Regularly update `icp-py-core` and its dependencies
   ```bash
   pip install --upgrade icp-py-core
   ```

2. **Verify Certificates**: Always enable certificate verification in production
   ```python
   agent.update(canister_id, "method", args, verify_certificate=True)
   ```

3. **Secure Private Keys**: Never commit private keys or PEM files to version control
   - Use environment variables
   - Use secure key management systems
   - Rotate keys regularly

4. **Validate Input**: Always validate and sanitize user input before sending to canisters

5. **Use HTTPS**: Always use HTTPS endpoints (`https://ic0.app`) in production

### For Developers

1. **Dependency Auditing**: Regularly audit dependencies for known vulnerabilities
   ```bash
   pip-audit
   ```

2. **Code Review**: All security-sensitive code changes require review

3. **Testing**: Include security-focused tests in your test suite

4. **Documentation**: Document security considerations in code and documentation

## Known Security Considerations

### Certificate Verification

- **Default Behavior**: Certificate verification is enabled by default for security
- **Disabling Verification**: Only disable in development/testing environments
- **blst Dependency**: Certificate verification requires the `blst` library (optional)

### Private Key Management

- **Storage**: Never store private keys in plain text
- **Transmission**: Never transmit private keys over insecure channels
- **Backup**: Use secure backup methods for key recovery

### Network Security

- **TLS/HTTPS**: Always use HTTPS endpoints
- **Certificate Pinning**: Consider implementing certificate pinning for critical applications
- **Rate Limiting**: Implement rate limiting to prevent abuse

## Security Updates

Security updates are released as:
- **Patch versions** (e.g., 2.1.0 → 2.1.1) for non-breaking security fixes
- **Minor versions** (e.g., 2.1.x → 2.2.0) for security enhancements
- **Major versions** (e.g., 2.x → 3.0) for breaking security changes

Subscribe to GitHub releases to be notified of security updates.

## Responsible Disclosure

We appreciate responsible disclosure of security vulnerabilities. Contributors who report valid security issues will be:

- Acknowledged in security advisories (if desired)
- Listed in the project's security hall of fame
- Eligible for recognition in release notes

## Security Contact

For security-related inquiries:
- **Email**: essenzenk@outlook.com
- **GitHub Security**: Use GitHub's private vulnerability reporting feature (if enabled)

## Additional Resources

- [Internet Computer Security Documentation](https://internetcomputer.org/docs/current/developer-docs/security/)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [Python Security Best Practices](https://python.readthedocs.io/en/stable/library/security.html)

---

**Last Updated**: 2026-02-06
