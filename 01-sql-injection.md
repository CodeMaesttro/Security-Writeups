# SQL Injection

## Overview

SQL Injection (SQLi) is a critical web security vulnerability that allows attackers to interfere with database queries by injecting malicious SQL code through user input fields. This vulnerability occurs when user-supplied data is concatenated directly into SQL queries without proper sanitization or parameterization.

**Severity**: Critical  
**OWASP Top 10**: A03:2021 - Injection  
**CWE**: CWE-89

## Technical Explanation

SQL Injection exploits the lack of input validation and improper query construction in database interactions. When an application builds SQL queries by concatenating user input directly into the query string, attackers can manipulate the query logic by injecting SQL syntax.

### Vulnerability Types

1. **In-band SQLi**: Results are returned directly in the application response
   - Error-based: Exploits database error messages
   - Union-based: Uses UNION operator to combine results

2. **Blind SQLi**: No direct output, attacker infers information from application behavior
   - Boolean-based: Observes true/false responses
   - Time-based: Uses database sleep functions to infer data

3. **Out-of-band SQLi**: Uses alternative channels (DNS, HTTP) to exfiltrate data

## Attack Scenario

Consider an e-commerce application with a user login endpoint:

```python
# Vulnerable code
username = request.form['username']
password = request.form['password']

query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
result = db.execute(query)
```

An attacker submits:
- Username: `admin'--`
- Password: `anything`

The resulting query becomes:
```sql
SELECT * FROM users WHERE username = 'admin'--' AND password = 'anything'
```

The `--` comments out the password check, allowing authentication bypass.

## Proof of Concept

### 1. Authentication Bypass

```http
POST /login HTTP/1.1
Host: vulnerable-app.com
Content-Type: application/x-www-form-urlencoded

username=admin'--&password=irrelevant
```

### 2. Data Extraction (Union-based)

```http
GET /product?id=1' UNION SELECT 1,username,password,4 FROM users-- HTTP/1.1
Host: vulnerable-app.com
```

### 3. Time-based Blind SQLi

```http
GET /search?q=test' AND IF(1=1, SLEEP(5), 0)-- HTTP/1.1
Host: vulnerable-app.com
```

If the response delays by 5 seconds, the injection is successful.

### 4. Database Enumeration

```sql
-- Extract database version
' UNION SELECT NULL,@@version,NULL--

-- List all tables
' UNION SELECT NULL,table_name,NULL FROM information_schema.tables--

-- Extract column names
' UNION SELECT NULL,column_name,NULL FROM information_schema.columns WHERE table_name='users'--
```

## Impact

- **Data Breach**: Unauthorized access to sensitive data (credentials, PII, financial records)
- **Authentication Bypass**: Complete account takeover including admin accounts
- **Data Manipulation**: Modification or deletion of database records
- **Privilege Escalation**: Elevation to administrative privileges
- **Remote Code Execution**: In some cases, execution of OS commands via database features
- **Denial of Service**: Database corruption or resource exhaustion

**Business Impact**: Regulatory fines (GDPR, HIPAA), reputational damage, legal liability, customer trust loss.

## Mitigation

### 1. Parameterized Queries (Prepared Statements)

**Python (SQLAlchemy)**
```python
from sqlalchemy import text

username = request.form['username']
password = request.form['password']

query = text("SELECT * FROM users WHERE username = :username AND password = :password")
result = db.execute(query, {"username": username, "password": password})
```

**PHP (PDO)**
```php
$stmt = $pdo->prepare("SELECT * FROM users WHERE username = ? AND password = ?");
$stmt->execute([$username, $password]);
```

**Java (JDBC)**
```java
String query = "SELECT * FROM users WHERE username = ? AND password = ?";
PreparedStatement stmt = connection.prepareStatement(query);
stmt.setString(1, username);
stmt.setString(2, password);
ResultSet rs = stmt.executeQuery();
```

### 2. ORM Usage

```python
# Using Django ORM
user = User.objects.filter(username=username, password=password).first()

# Using SQLAlchemy ORM
user = session.query(User).filter_by(username=username, password=password).first()
```

### 3. Input Validation

```python
import re

def validate_username(username):
    # Allow only alphanumeric and underscore
    if not re.match(r'^[a-zA-Z0-9_]{3,20}$', username):
        raise ValueError("Invalid username format")
    return username

username = validate_username(request.form['username'])
```

### 4. Least Privilege Principle

```sql
-- Create restricted database user
CREATE USER 'webapp'@'localhost' IDENTIFIED BY 'secure_password';
GRANT SELECT, INSERT, UPDATE ON app_database.* TO 'webapp'@'localhost';
-- Do NOT grant DROP, CREATE, or FILE privileges
```

### 5. Web Application Firewall (WAF)

Deploy WAF rules to detect and block common SQLi patterns:
- Single quotes followed by SQL keywords
- UNION SELECT statements
- Comment sequences (--, /*, #)
- Time-based attack patterns (SLEEP, WAITFOR)

### 6. Error Handling

```python
try:
    result = db.execute(query)
except Exception as e:
    # Log error securely
    logger.error(f"Database error: {str(e)}")
    # Return generic error to user
    return {"error": "An error occurred processing your request"}, 500
```

## Secure Code Example

```python
from flask import Flask, request, jsonify
from sqlalchemy import create_engine, text
import re
import hashlib

app = Flask(__name__)
engine = create_engine('postgresql://webapp:password@localhost/appdb')

def validate_input(value, pattern, max_length):
    """Validate and sanitize user input"""
    if len(value) > max_length:
        raise ValueError("Input too long")
    if not re.match(pattern, value):
        raise ValueError("Invalid input format")
    return value

def hash_password(password):
    """Hash password using SHA-256"""
    return hashlib.sha256(password.encode()).hexdigest()

@app.route('/login', methods=['POST'])
def login():
    try:
        # Validate inputs
        username = validate_input(
            request.form.get('username', ''),
            r'^[a-zA-Z0-9_]{3,20}$',
            20
        )
        password = request.form.get('password', '')
        
        # Hash password
        password_hash = hash_password(password)
        
        # Use parameterized query
        query = text("""
            SELECT id, username, email 
            FROM users 
            WHERE username = :username 
            AND password_hash = :password_hash
            AND active = true
        """)
        
        with engine.connect() as conn:
            result = conn.execute(
                query,
                {"username": username, "password_hash": password_hash}
            ).fetchone()
        
        if result:
            return jsonify({
                "success": True,
                "user_id": result[0],
                "username": result[1]
            })
        else:
            return jsonify({"success": False, "error": "Invalid credentials"}), 401
            
    except ValueError as e:
        return jsonify({"success": False, "error": "Invalid input"}), 400
    except Exception as e:
        # Log error internally, return generic message
        app.logger.error(f"Login error: {str(e)}")
        return jsonify({"success": False, "error": "An error occurred"}), 500

if __name__ == '__main__':
    app.run()
```

## Security Takeaways

1. **Never trust user input**: All user-supplied data must be treated as potentially malicious
2. **Always use parameterized queries**: This is the primary defense against SQL injection
3. **Implement defense in depth**: Combine multiple security layers (input validation, parameterized queries, least privilege, WAF)
4. **Use ORMs when possible**: Modern ORMs handle query parameterization automatically
5. **Validate and sanitize**: Implement strict input validation with whitelisting approaches
6. **Apply least privilege**: Database users should have minimal necessary permissions
7. **Hide error details**: Never expose database errors or stack traces to end users
8. **Regular security testing**: Include SQLi testing in your security assessment process
9. **Code review**: Implement peer review processes focusing on database interaction code
10. **Security training**: Ensure developers understand SQL injection risks and prevention techniques

## References

- [OWASP SQL Injection](https://owasp.org/www-community/attacks/SQL_Injection)
- [CWE-89: SQL Injection](https://cwe.mitre.org/data/definitions/89.html)
- [PortSwigger SQL Injection](https://portswigger.net/web-security/sql-injection)
