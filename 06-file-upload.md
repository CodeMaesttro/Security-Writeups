# File Upload Vulnerabilities

## Overview

File upload vulnerabilities allow attackers to upload malicious files leading to RCE, XSS, and DoS.

**Severity**: Critical
**CWE**: CWE-434

## Impact
- Remote Code Execution
- Stored XSS
- Malware Distribution

## Mitigation
1. Validate file types using magic bytes
2. Generate random filenames
3. Store outside web root
4. Implement size limits
5. Scan with antivirus

## References
- OWASP File Upload Cheat Sheet
- CWE-434

