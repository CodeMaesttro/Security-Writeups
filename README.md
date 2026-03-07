# Security Writeups

A collection of professional vulnerability research writeups covering common web application and smart contract security issues.

## Repository Contents

1. [SQL Injection](./01-sql-injection.md)
2. [Cross-Site Scripting (XSS)](./02-cross-site-scripting.md)
3. [Broken Access Control / IDOR](./03-broken-access-control.md)
4. [Cross-Site Request Forgery (CSRF)](./04-csrf.md)
5. [Server-Side Request Forgery (SSRF)](./05-ssrf.md)
6. [File Upload Vulnerabilities](./06-file-upload.md)
7. [JWT Authentication Attacks](./07-jwt-attacks.md)
8. [API Rate Limit Bypass](./08-rate-limit-bypass.md)
9. [OAuth Misconfiguration](./09-oauth-misconfiguration.md)
10. [Smart Contract Reentrancy Attack](./10-reentrancy-attack.md)

## Purpose

These writeups are intended for security researchers, developers, and penetration testers to understand common vulnerability patterns, their exploitation techniques, and proper mitigation strategies.

## Disclaimer

The information provided in this repository is for educational purposes only. Do not use these techniques against systems you do not own or have explicit permission to test.

## Writeup Structure

Each writeup follows a consistent format:
- Title and Overview (Severity, OWASP/CWE references)
- Technical Explanation
- Attack Scenario
- Proof of Concept
- Impact Assessment
- Mitigation Strategies
- Secure Code Examples
- Security Takeaways
- References

## Technologies Covered

- Web Application Security (Python/Flask, JavaScript, PHP)
- API Security
- Authentication & Authorization
- Smart Contract Security (Solidity)
- Cloud Security

## Contributing

Contributions are welcome! Please read [CONTRIBUTING.md](./CONTRIBUTING.md) for guidelines on submitting new writeups.

## License

This project is licensed under the MIT License - see the [LICENSE](./LICENSE) file for details.
