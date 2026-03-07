# Broken Access Control / IDOR

## Overview

Broken Access Control vulnerabilities occur when applications fail to properly enforce authorization checks, allowing users to access resources or perform actions beyond their intended permissions. Insecure Direct Object References (IDOR) is a specific type where attackers can access objects by manipulating identifiers in requests.

**Severity**: High to Critical  
**OWASP Top 10**: A01:2021 - Broken Access Control  
**CWE**: CWE-639, CWE-284

## Technical Explanation

Access control enforces policies that prevent users from acting outside their intended permissions. Failures occur when:

- Missing authorization checks on sensitive endpoints
- Relying solely on client-side access control
- Using predictable or sequential identifiers without validation
- Improper implementation of role-based access control (RBAC)
- Horizontal privilege escalation (accessing other users' data)
- Vertical privilege escalation (accessing admin functions)

### Common Patterns

1. **IDOR (Insecure Direct Object Reference)**: Direct manipulation of object IDs
2. **Missing Function Level Access Control**: Unprotected admin endpoints
3. **Path Traversal**: Accessing files outside intended directory
4. **Forced Browsing**: Accessing pages without proper authentication

## Attack Scenario

Consider a banking application with an account details endpoint:

```python
# Vulnerable code
@app.route('/api/account/<account_id>')
def get_account(account_id):
    # No authorization check!
    account = db.query(f"SELECT * FROM accounts WHERE id = {account_id}")
    return jsonify(account)
```

An attacker authenticated as user with account ID 1234 can access other accounts:

```http
GET /api/account/1235 HTTP/1.1
Authorization: Bearer <attacker_token>
```

The application returns account 1235's data without verifying ownership.

## Proof of Concept

### 1. Horizontal Privilege Escalation (IDOR)

```http
# Attacker's legitimate request
GET /api/user/profile/1001 HTTP/1.1
Authorization: Bearer eyJhbGc...
Host: vulnerable-app.com

# Response
{
  "id": 1001,
  "username": "attacker",
  "email": "attacker@example.com",
  "ssn": "123-45-6789"
}

# Attacker modifies ID to access victim's data
GET /api/user/profile/1002 HTTP/1.1
Authorization: Bearer eyJhbGc...
Host: vulnerable-app.com

# Response - Victim's data exposed!
{
  "id": 1002,
  "username": "victim",
  "email": "victim@example.com",
  "ssn": "987-65-4321"
}
```

### 2. Vertical Privilege Escalation

```http
# Regular user accessing admin endpoint
GET /api/admin/users HTTP/1.1
Authorization: Bearer <regular_user_token>
Host: vulnerable-app.com

# Response - Should be 403, but returns data
{
  "users": [
    {"id": 1, "username": "admin", "role": "admin"},
    {"id": 2, "username": "user1", "role": "user"}
  ]
}
```

### 3. Parameter Manipulation

```http
# POST request with hidden admin parameter
POST /api/user/update HTTP/1.1
Content-Type: application/json
Authorization: Bearer <user_token>

{
  "username": "attacker",
  "email": "attacker@example.com",
  "role": "admin"
}

# If not properly validated, user becomes admin
```

### 4. UUID Enumeration

```python
# Even with UUIDs, poor implementation can be vulnerable
import uuid

# Predictable UUID generation
user_id = uuid.uuid1()  # Time-based, predictable

# Attacker can generate valid UUIDs
GET /api/document/550e8400-e29b-41d4-a716-446655440000
```

### 5. Mass Assignment

```http
POST /api/user/register HTTP/1.1
Content-Type: application/json

{
  "username": "newuser",
  "email": "user@example.com",
  "password": "password123",
  "is_admin": true,
  "account_balance": 1000000
}
```

## Impact

- **Data Breach**: Unauthorized access to sensitive user data (PII, financial records, health information)
- **Account Takeover**: Modification of other users' accounts including credentials
- **Financial Loss**: Unauthorized transactions, balance manipulation
- **Privacy Violations**: Access to private messages, documents, photos
- **Privilege Escalation**: Regular users gaining administrative access
- **Compliance Violations**: GDPR, HIPAA, PCI-DSS breaches
- **Reputation Damage**: Loss of customer trust and brand value

**Real-World Examples**: 
- Facebook Graph API IDOR (2018)
- Instagram IDOR allowing account takeover (2019)
- Parler data breach via IDOR (2021)

## Mitigation

### 1. Implement Proper Authorization Checks

```python
from flask import Flask, request, jsonify, abort
from functools import wraps

def require_ownership(f):
    """Decorator to verify resource ownership"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        resource_id = kwargs.get('resource_id')
        user_id = get_current_user_id()
        
        # Verify ownership
        resource = db.query(
            "SELECT user_id FROM resources WHERE id = ?",
            [resource_id]
        ).fetchone()
        
        if not resource or resource['user_id'] != user_id:
            abort(403, "Access denied")
        
        return f(*args, **kwargs)
    return decorated_function

@app.route('/api/document/<int:resource_id>')
@require_authentication
@require_ownership
def get_document(resource_id):
    document = db.query(
        "SELECT * FROM documents WHERE id = ?",
        [resource_id]
    ).fetchone()
    return jsonify(document)
```

### 2. Use Indirect Object References

```python
import secrets
from datetime import datetime, timedelta

class ResourceAccessToken:
    """Generate temporary access tokens instead of exposing IDs"""
    
    @staticmethod
    def generate(user_id, resource_id, expiry_hours=24):
        token = secrets.token_urlsafe(32)
        expiry = datetime.utcnow() + timedelta(hours=expiry_hours)
        
        db.execute("""
            INSERT INTO access_tokens (token, user_id, resource_id, expiry)
            VALUES (?, ?, ?, ?)
        """, [token, user_id, resource_id, expiry])
        
        return token
    
    @staticmethod
    def validate(token, user_id):
        result = db.query("""
            SELECT resource_id FROM access_tokens
            WHERE token = ? AND user_id = ? AND expiry > ?
        """, [token, user_id, datetime.utcnow()]).fetchone()
        
        return result['resource_id'] if result else None

# Usage
@app.route('/api/document/<token>')
@require_authentication
def get_document(token):
    user_id = get_current_user_id()
    resource_id = ResourceAccessToken.validate(token, user_id)
    
    if not resource_id:
        abort(403, "Invalid or expired token")
    
    document = db.query(
        "SELECT * FROM documents WHERE id = ?",
        [resource_id]
    ).fetchone()
    
    return jsonify(document)
```

### 3. Implement Role-Based Access Control (RBAC)

```python
from enum import Enum

class Role(Enum):
    USER = "user"
    MODERATOR = "moderator"
    ADMIN = "admin"

class Permission(Enum):
    READ = "read"
    WRITE = "write"
    DELETE = "delete"
    ADMIN_ACCESS = "admin_access"

# Role-Permission mapping
ROLE_PERMISSIONS = {
    Role.USER: [Permission.READ, Permission.WRITE],
    Role.MODERATOR: [Permission.READ, Permission.WRITE, Permission.DELETE],
    Role.ADMIN: [Permission.READ, Permission.WRITE, Permission.DELETE, Permission.ADMIN_ACCESS]
}

def require_permission(permission):
    """Decorator to check user permissions"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            user = get_current_user()
            user_role = Role(user['role'])
            
            if permission not in ROLE_PERMISSIONS.get(user_role, []):
                abort(403, "Insufficient permissions")
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator

@app.route('/api/admin/users')
@require_authentication
@require_permission(Permission.ADMIN_ACCESS)
def list_users():
    users = db.query("SELECT id, username, email FROM users").fetchall()
    return jsonify(users)
```

### 4. Attribute-Based Access Control (ABAC)

```python
class AccessPolicy:
    """Define fine-grained access policies"""
    
    @staticmethod
    def can_access_document(user, document):
        # Owner can always access
        if document['owner_id'] == user['id']:
            return True
        
        # Check if document is shared with user
        shared = db.query("""
            SELECT 1 FROM document_shares
            WHERE document_id = ? AND user_id = ?
        """, [document['id'], user['id']]).fetchone()
        
        if shared:
            return True
        
        # Check department access
        if (document['department'] == user['department'] and 
            document['visibility'] == 'department'):
            return True
        
        # Admin override
        if user['role'] == 'admin':
            return True
        
        return False

@app.route('/api/document/<int:doc_id>')
@require_authentication
def get_document(doc_id):
    user = get_current_user()
    document = db.query(
        "SELECT * FROM documents WHERE id = ?",
        [doc_id]
    ).fetchone()
    
    if not document:
        abort(404, "Document not found")
    
    if not AccessPolicy.can_access_document(user, document):
        abort(403, "Access denied")
    
    return jsonify(document)
```

### 5. Use UUIDs with Proper Validation

```python
import uuid

def generate_secure_id():
    """Generate cryptographically secure UUID"""
    return str(uuid.uuid4())

@app.route('/api/resource/<uuid:resource_id>')
@require_authentication
def get_resource(resource_id):
    user_id = get_current_user_id()
    
    # Validate UUID format (Flask does this automatically with uuid: converter)
    # Still need to check ownership
    resource = db.query("""
        SELECT * FROM resources
        WHERE id = ? AND user_id = ?
    """, [str(resource_id), user_id]).fetchone()
    
    if not resource:
        abort(404, "Resource not found")
    
    return jsonify(resource)
```

### 6. Prevent Mass Assignment

```python
from marshmallow import Schema, fields, ValidationError

class UserUpdateSchema(Schema):
    """Define allowed fields for user updates"""
    username = fields.Str(required=False)
    email = fields.Email(required=False)
    bio = fields.Str(required=False)
    
    # Explicitly exclude sensitive fields
    class Meta:
        # These fields cannot be set by users
        exclude = ['id', 'role', 'is_admin', 'account_balance', 'created_at']

@app.route('/api/user/update', methods=['POST'])
@require_authentication
def update_user():
    user_id = get_current_user_id()
    
    # Validate and sanitize input
    schema = UserUpdateSchema()
    try:
        validated_data = schema.load(request.json)
    except ValidationError as err:
        return jsonify({"errors": err.messages}), 400
    
    # Only update allowed fields
    db.execute("""
        UPDATE users
        SET username = COALESCE(?, username),
            email = COALESCE(?, email),
            bio = COALESCE(?, bio)
        WHERE id = ?
    """, [
        validated_data.get('username'),
        validated_data.get('email'),
        validated_data.get('bio'),
        user_id
    ])
    
    return jsonify({"success": True})
```

## Secure Code Example

```python
from flask import Flask, request, jsonify, abort
from functools import wraps
import uuid
from datetime import datetime

app = Flask(__name__)

# Authentication helper
def get_current_user():
    """Extract and validate user from JWT token"""
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    # Validate JWT and extract user info
    user = validate_jwt(token)
    if not user:
        abort(401, "Unauthorized")
    return user

def require_authentication(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        get_current_user()  # Will abort if invalid
        return f(*args, **kwargs)
    return decorated

# Authorization helpers
class AccessControl:
    @staticmethod
    def verify_resource_ownership(user_id, resource_type, resource_id):
        """Verify user owns the resource"""
        query = f"""
            SELECT 1 FROM {resource_type}
            WHERE id = ? AND user_id = ?
        """
        result = db.query(query, [resource_id, user_id]).fetchone()
        return result is not None
    
    @staticmethod
    def has_role(user, required_role):
        """Check if user has required role"""
        role_hierarchy = {'user': 1, 'moderator': 2, 'admin': 3}
        user_level = role_hierarchy.get(user['role'], 0)
        required_level = role_hierarchy.get(required_role, 999)
        return user_level >= required_level

# Secure endpoints
@app.route('/api/account/<uuid:account_id>', methods=['GET'])
@require_authentication
def get_account(account_id):
    """Retrieve account with proper authorization"""
    user = get_current_user()
    
    # Verify ownership
    if not AccessControl.verify_resource_ownership(
        user['id'], 'accounts', str(account_id)
    ):
        abort(403, "Access denied")
    
    # Fetch account data
    account = db.query("""
        SELECT id, account_number, balance, created_at
        FROM accounts
        WHERE id = ? AND user_id = ?
    """, [str(account_id), user['id']]).fetchone()
    
    if not account:
        abort(404, "Account not found")
    
    return jsonify(account)

@app.route('/api/account/<uuid:account_id>/transactions', methods=['GET'])
@require_authentication
def get_transactions(account_id):
    """Retrieve transactions with pagination and authorization"""
    user = get_current_user()
    
    # Verify ownership
    if not AccessControl.verify_resource_ownership(
        user['id'], 'accounts', str(account_id)
    ):
        abort(403, "Access denied")
    
    # Pagination
    page = request.args.get('page', 1, type=int)
    per_page = min(request.args.get('per_page', 20, type=int), 100)
    offset = (page - 1) * per_page
    
    # Fetch transactions
    transactions = db.query("""
        SELECT id, amount, description, created_at
        FROM transactions
        WHERE account_id = ?
        ORDER BY created_at DESC
        LIMIT ? OFFSET ?
    """, [str(account_id), per_page, offset]).fetchall()
    
    return jsonify({
        "transactions": transactions,
        "page": page,
        "per_page": per_page
    })

@app.route('/api/admin/users', methods=['GET'])
@require_authentication
def admin_list_users():
    """Admin endpoint with role verification"""
    user = get_current_user()
    
    # Verify admin role
    if not AccessControl.has_role(user, 'admin'):
        abort(403, "Admin access required")
    
    users = db.query("""
        SELECT id, username, email, role, created_at
        FROM users
        ORDER BY created_at DESC
    """).fetchall()
    
    return jsonify({"users": users})

@app.route('/api/document/share', methods=['POST'])
@require_authentication
def share_document():
    """Share document with another user"""
    user = get_current_user()
    document_id = request.json.get('document_id')
    target_user_id = request.json.get('target_user_id')
    
    # Verify ownership of document
    if not AccessControl.verify_resource_ownership(
        user['id'], 'documents', document_id
    ):
        abort(403, "You can only share your own documents")
    
    # Verify target user exists
    target_user = db.query(
        "SELECT id FROM users WHERE id = ?",
        [target_user_id]
    ).fetchone()
    
    if not target_user:
        abort(404, "Target user not found")
    
    # Create share record
    db.execute("""
        INSERT INTO document_shares (document_id, user_id, shared_by, created_at)
        VALUES (?, ?, ?, ?)
    """, [document_id, target_user_id, user['id'], datetime.utcnow()])
    
    return jsonify({"success": True, "message": "Document shared successfully"})

if __name__ == '__main__':
    app.run()
```

## Security Takeaways

1. **Never trust client-side access control**: Always enforce authorization on the server
2. **Verify ownership**: Check that the authenticated user owns the requested resource
3. **Use indirect references**: Avoid exposing internal IDs; use tokens or UUIDs
4. **Implement RBAC/ABAC**: Use structured access control models
5. **Deny by default**: Require explicit permission grants rather than blacklisting
6. **Validate all parameters**: Check both visible and hidden parameters
7. **Prevent mass assignment**: Explicitly define allowed fields for updates
8. **Log access attempts**: Monitor for suspicious access patterns
9. **Use framework features**: Leverage built-in authorization mechanisms
10. **Regular audits**: Conduct access control reviews and penetration testing

## References

- [OWASP Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)
- [CWE-639: Authorization Bypass](https://cwe.mitre.org/data/definitions/639.html)
- [OWASP Access Control Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Access_Control_Cheat_Sheet.html)
