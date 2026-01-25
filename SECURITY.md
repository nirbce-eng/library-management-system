# Security Documentation

This document outlines the security features, configurations, and best practices implemented in the Library Management System.

## Security Features Implemented

### 1. Authentication Security

#### Password Security
- **Strong Password Requirements**: Minimum 8 characters, at least one letter and one number
- **Password Hashing**: Uses Werkzeug's secure password hashing (PBKDF2-SHA256)
- **Token Invalidation**: API tokens are invalidated on password change/reset
- **Secure Password Reset**: Token-based reset flow with email verification
  - Cryptographically secure tokens (32 bytes via `secrets.token_urlsafe`)
  - Tokens expire after 30 minutes
  - Single-use tokens (invalidated after use)
  - Prevents user enumeration (same response for valid/invalid emails)

#### API Token Security
- **Token Expiration**: API tokens expire after 24 hours
- **Single Active Token**: Only one token per user (old tokens deleted on new login)
- **Secure Token Generation**: Uses `secrets.token_hex(32)` for cryptographically secure tokens

#### Rate Limiting
| Endpoint | Limit |
|----------|-------|
| Login attempts | 5 per minute |
| Registration | 3 per minute |
| Password change | 3 per minute |
| Password reset request | 3 per minute |
| Password reset (with token) | 5 per minute |
| API authentication | 5 per minute |
| Create/Update operations | 30 per minute |
| Delete operations | 10 per minute |
| Chat messages | 60 per minute |
| General endpoints | 200 per day, 50 per hour |

#### Session Security
- Secure session cookies (HTTPS only in production)
- HTTPOnly cookies (prevents XSS cookie theft)
- SameSite=Lax (CSRF protection)
- Session timeout: 2 hours
- Automatic session regeneration on login

### 2. Input Validation & Sanitization

All user inputs are validated and sanitized using `html.escape()` and length limits:

| Input Type | Validation Rules | Max Length |
|------------|------------------|------------|
| Username | 3-20 alphanumeric characters or underscores | 20 |
| Email | Valid email format | 100 |
| Password | Min 8 chars, 1 letter, 1 number | - |
| ISBN | Valid ISBN-10 or ISBN-13 format | 20 |
| Phone | 7-20 chars, digits and common separators | 20 |
| Dates | YYYY-MM-DD format | - |
| Numbers | Positive integers within defined ranges | - |
| Book Title | Required, non-empty | 200 |
| Author | Required, non-empty | 200 |
| Member Name | Minimum 2 characters | 100 |
| Address | Optional | 500 |
| Chat Message | Non-empty, sanitized | 2000 |
| Search Queries | SQL wildcards escaped | 100 |

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
| Permissions-Policy | geolocation=(), microphone=(), camera=() | Restrict browser features |
| Strict-Transport-Security | max-age=31536000; includeSubDomains | HTTPS enforcement (when enabled) |

### 5. Content Security Policy (CSP)

```
default-src 'self';
script-src 'self' 'unsafe-inline';
style-src 'self' 'unsafe-inline';
img-src 'self' data:;
font-src 'self';
form-action 'self';
frame-ancestors 'self';
base-uri 'self'
```

### 6. CORS Configuration

- Restricted to allowed origins only
- Configurable via `ALLOWED_ORIGINS` environment variable
- Default: `http://localhost:3000,http://localhost:5000`

### 7. SQL Injection Prevention

- All database queries use parameterized statements
- No string interpolation in SQL queries
- Search queries sanitize SQL wildcards (%, _)

### 8. Access Control

- Role-based access: Admin and Staff roles
- Admin-only endpoints: Ledger, user management
- All routes require authentication (except login/register)
- API token and session-based authentication supported

## Environment Variables

| Variable | Description | Required |
|----------|-------------|----------|
| `SECRET_KEY` | Flask session secret key (32+ bytes) | **Yes** (required in production) |
| `ADMIN_PASSWORD` | Initial admin password | Recommended |
| `ALLOWED_ORIGINS` | Comma-separated allowed CORS origins | No |
| `FLASK_ENV` | production/development | No (default: production) |
| `FLASK_DEBUG` | true/false | No (default: false) |
| `ENABLE_HSTS` | Enable Strict-Transport-Security header | No (default: false) |
| `SECRET_COOKIE_SECURE` | Require HTTPS for cookies | No (default: true) |

## Production Deployment Checklist

### Required Steps

1. **Generate and Set Secret Key**
   ```bash
   # Generate a secure key
   python -c "import secrets; print(secrets.token_hex(32))"

   # Create .env file
   echo "SECRET_KEY=your-generated-key-here" > .env
   ```

2. **Set Admin Password**
   ```bash
   echo "ADMIN_PASSWORD=your-secure-admin-password" >> .env
   ```

3. **Configure CORS Origins**
   ```bash
   echo "ALLOWED_ORIGINS=https://yourdomain.com" >> .env
   ```

4. **Enable HTTPS**
   - Use a reverse proxy (nginx, traefik)
   - Configure SSL certificates
   - Set `ENABLE_HSTS=true` for HTTPS enforcement
   - Set `SECRET_COOKIE_SECURE=true` (default)

### Docker Production Deployment

```bash
# Create .env file with required variables
cat > .env << EOF
SECRET_KEY=$(python -c "import secrets; print(secrets.token_hex(32))")
ADMIN_PASSWORD=your-secure-password
ALLOWED_ORIGINS=https://yourdomain.com
ENABLE_HSTS=true
EOF

# Deploy
docker-compose up -d
```

### Docker Security Features

- **Non-root user**: Application runs as `appuser`
- **Read-only filesystem**: Container filesystem is read-only
- **No new privileges**: Prevents privilege escalation
- **Resource limits**: Memory (512MB) and CPU (1.0) limits
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

4. **Monitor for expired tokens**
   ```bash
   grep "Token expired" logs/app.log
   ```

## Penetration Testing Results

### Vulnerabilities Fixed (v2.1.0)

| Issue | Severity | Status |
|-------|----------|--------|
| Missing input sanitization in edit_book() | High | Fixed |
| Missing input sanitization in edit_member() | High | Fixed |
| Missing validation in issue_book() | Medium | Fixed |
| Missing validation in return_book() | Medium | Fixed |
| Chat messages not sanitized (XSS risk) | High | Fixed |
| API endpoints missing input sanitization | High | Fixed |
| API tokens never expire | Medium | Fixed (24h expiration) |
| Hardcoded SECRET_KEY in docker-compose | Critical | Fixed (required env var) |
| Missing rate limiting on API mutations | Medium | Fixed |
| Missing HSTS header | Low | Fixed (configurable) |
| Missing Permissions-Policy header | Low | Fixed |

## Known Limitations

1. **SQLite**: Single-file database, not suitable for high-concurrency production
2. **In-memory rate limiting**: Rate limits reset on restart
3. **No email sending**: Password reset tokens are logged (email integration required for production)
4. **No 2FA**: Two-factor authentication not implemented

## Security Vulnerability Reporting

If you discover a security vulnerability, please:

1. Do not publicly disclose the issue
2. Contact the development team directly
3. Provide detailed steps to reproduce
4. Allow reasonable time for a fix before disclosure

## Changelog

### Version 2.2.0 (Secure Password Reset)

- Implemented token-based password reset flow
- Added `reset_token` and `reset_token_expiry` columns to users table
- Tokens generated using `secrets.token_urlsafe(32)` (cryptographically secure)
- Tokens expire after 30 minutes
- Tokens are single-use (invalidated after successful reset)
- Fixed user enumeration vulnerability (same response for valid/invalid emails)
- Added new `/reset-password/<token>` web route
- Added new `/api/auth/reset-password` API endpoint
- Updated rate limiting for password reset endpoints
- All API tokens invalidated on password reset

### Version 2.1.0 (Security Penetration Testing)

- Added input sanitization to edit_book() and edit_member() routes
- Added validation to issue_book() and return_book() routes
- Added sanitization to all API create/update endpoints
- Implemented API token expiration (24 hours)
- Added rate limiting to API mutation endpoints
- Added Strict-Transport-Security header support (ENABLE_HSTS)
- Added Permissions-Policy header
- Enhanced Content-Security-Policy with form-action and base-uri
- Removed hardcoded SECRET_KEY from docker-compose.yml
- Added resource limits (memory/CPU) to Docker deployment
- Added SQL wildcard escaping in search queries
- Sanitized chat messages to prevent XSS

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
