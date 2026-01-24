# Security Documentation

This document outlines the security features, configurations, and best practices implemented in the Library Management System.

## Security Features Implemented

### 1. Authentication Security

#### Password Security
- **Strong Password Requirements**: Minimum 8 characters, at least one letter and one number
- **Password Hashing**: Uses Werkzeug's secure password hashing (PBKDF2-SHA256)
- **Token Invalidation**: API tokens are invalidated on password change/reset

#### Rate Limiting
- Login attempts: **5 per minute**
- Registration: **3 per minute**
- Password change/reset: **3 per minute**
- API authentication: **5 per minute**
- General endpoints: **200 per day, 50 per hour**

#### Session Security
- Secure session cookies (HTTPS only in production)
- HTTPOnly cookies (prevents XSS cookie theft)
- SameSite=Lax (CSRF protection)
- Session timeout: 2 hours
- Automatic session regeneration on login

### 2. Input Validation & Sanitization

All user inputs are validated and sanitized:

| Input Type | Validation Rules |
|------------|------------------|
| Username | 3-20 alphanumeric characters or underscores |
| Email | Valid email format |
| Password | Min 8 chars, 1 letter, 1 number |
| ISBN | Valid ISBN-10 or ISBN-13 format |
| Phone | 7-20 chars, digits and common separators |
| Dates | YYYY-MM-DD format |
| Numbers | Positive integers within defined ranges |

### 3. CSRF Protection

- Flask-WTF CSRF protection enabled
- All web forms include CSRF tokens
- API endpoints exempt (use token authentication)
- CSRF tokens valid for 1 hour

### 4. Security Headers

All responses include security headers:

| Header | Value | Purpose |
|--------|-------|---------|
| X-Content-Type-Options | nosniff | Prevent MIME sniffing |
| X-Frame-Options | SAMEORIGIN | Prevent clickjacking |
| X-XSS-Protection | 1; mode=block | XSS filter |
| Referrer-Policy | strict-origin-when-cross-origin | Control referrer info |
| Content-Security-Policy | Restrictive policy | Prevent XSS/injection |
| Cache-Control | no-store | Prevent caching sensitive data |

### 5. CORS Configuration

- Restricted to allowed origins only
- Configurable via `ALLOWED_ORIGINS` environment variable
- Default: `http://localhost:3000,http://localhost:5000`

### 6. SQL Injection Prevention

- All database queries use parameterized statements
- No string interpolation in SQL queries

### 7. Access Control

- Role-based access: Admin and Staff roles
- Admin-only endpoints: Ledger, Chat administration
- All routes require authentication (except login/register)

## Environment Variables

| Variable | Description | Required |
|----------|-------------|----------|
| `SECRET_KEY` | Flask session secret key (32+ bytes) | **Yes** for production |
| `ADMIN_PASSWORD` | Initial admin password | Recommended |
| `ALLOWED_ORIGINS` | Comma-separated allowed CORS origins | No |
| `FLASK_ENV` | production/development | No (default: production) |
| `FLASK_DEBUG` | true/false | No (default: false) |

## Production Deployment Checklist

### Required Steps

1. **Set Secret Key**
   ```bash
   # Generate a secure key
   python -c "import secrets; print(secrets.token_hex(32))"

   # Set in environment
   export SECRET_KEY="your-generated-key-here"
   ```

2. **Set Admin Password**
   ```bash
   export ADMIN_PASSWORD="your-secure-admin-password"
   ```

3. **Configure CORS Origins**
   ```bash
   export ALLOWED_ORIGINS="https://yourdomain.com"
   ```

4. **Enable HTTPS**
   - Use a reverse proxy (nginx, traefik)
   - Configure SSL certificates
   - Set `SESSION_COOKIE_SECURE=True` (automatic in production)

### Docker Production Deployment

```bash
# Create .env file
cat > .env << EOF
SECRET_KEY=$(python -c "import secrets; print(secrets.token_hex(32))")
ADMIN_PASSWORD=your-secure-password
ALLOWED_ORIGINS=https://yourdomain.com
EOF

# Deploy
docker-compose --env-file .env up -d
```

### Docker Security Features

- **Non-root user**: Application runs as `appuser`
- **Read-only filesystem**: Container filesystem is read-only
- **No new privileges**: Prevents privilege escalation
- **Health checks**: Automatic container health monitoring
- **Gunicorn**: Production WSGI server (not Flask dev server)

## Security Monitoring

### Audit Logging

All security-relevant events are logged to `logs/audit.log`:

- `USER_LOGIN` / `USER_LOGOUT`
- `API_LOGIN` / `API_LOGOUT`
- `USER_REGISTERED` / `API_USER_REGISTERED`
- `PASSWORD_CHANGED` / `PASSWORD_RESET`
- All CRUD operations on books, members, transactions
- `CHAT_MESSAGE_SENT`

Each log entry includes:
- Timestamp
- Username/User ID
- Client IP address
- Action performed

### Monitoring Recommendations

1. **Monitor failed login attempts**
   ```bash
   grep "Failed login attempt" logs/app.log
   ```

2. **Check for rate limiting triggers**
   ```bash
   grep "rate limit" logs/app.log
   ```

3. **Review audit trail**
   ```bash
   tail -f logs/audit.log
   ```

## Known Limitations

1. **SQLite**: Single-file database, not suitable for high-concurrency production
2. **In-memory rate limiting**: Rate limits reset on restart
3. **No email verification**: Registration doesn't verify email ownership
4. **No 2FA**: Two-factor authentication not implemented

## Security Vulnerability Reporting

If you discover a security vulnerability, please:

1. Do not publicly disclose the issue
2. Contact the development team directly
3. Provide detailed steps to reproduce
4. Allow reasonable time for a fix before disclosure

## Changelog

### Version 2.0.0 (Security Hardening)

- Added CSRF protection with Flask-WTF
- Implemented rate limiting on all authentication endpoints
- Added comprehensive input validation
- Implemented security headers middleware
- Added secure session configuration
- Updated password requirements (8 chars, letter + number)
- Added API token invalidation on password change
- Docker: Non-root user, read-only filesystem
- Production: Gunicorn WSGI server
- Environment-based configuration for secrets
