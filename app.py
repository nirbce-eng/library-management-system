"""
Library Management System
A comprehensive web application for managing library operations
"""

from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, g, session
from flask_cors import CORS
from flask_wtf.csrf import CSRFProtect, CSRFError
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import sqlite3
from datetime import datetime, timedelta
from contextlib import contextmanager
import os
import logging
from logging.handlers import RotatingFileHandler
import time
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
import secrets
import re
import html

app = Flask(__name__)

# Security Configuration - Use environment variables with secure defaults
app.secret_key = os.environ.get('SECRET_KEY') or secrets.token_hex(32)
app.config['SESSION_COOKIE_SECURE'] = os.environ.get('SECRET_COOKIE_SECURE', 'true').lower() == 'true'
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=2)
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max request size
app.config['WTF_CSRF_TIME_LIMIT'] = 3600  # CSRF token valid for 1 hour

# Initialize CSRF protection
csrf = CSRFProtect(app)

# Initialize rate limiter
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://"
)

# Get allowed origins from environment or use default
ALLOWED_ORIGINS = os.environ.get('ALLOWED_ORIGINS', 'http://localhost:3000,http://localhost:5000').split(',')

# Enable CORS for API routes with restricted origins
CORS(app, resources={r"/api/*": {"origins": ALLOWED_ORIGINS}}, supports_credentials=True)

# Exempt API routes from CSRF (they use token authentication)
csrf.exempt('api_login')
csrf.exempt('api_register')

# =============================================================================
# INPUT VALIDATION HELPERS
# =============================================================================

def sanitize_string(value, max_length=500):
    """Sanitize string input by stripping and limiting length"""
    if not value:
        return ''
    return html.escape(str(value).strip()[:max_length])

def validate_email(email):
    """Validate email format"""
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

def validate_isbn(isbn):
    """Validate ISBN format (ISBN-10 or ISBN-13)"""
    # Remove hyphens and spaces
    isbn = re.sub(r'[-\s]', '', isbn)
    if len(isbn) == 10:
        return isbn[:-1].isdigit() and (isbn[-1].isdigit() or isbn[-1].upper() == 'X')
    elif len(isbn) == 13:
        return isbn.isdigit()
    return False

def validate_phone(phone):
    """Validate phone number format"""
    if not phone:
        return True  # Phone is optional
    # Allow digits, spaces, hyphens, parentheses, plus sign
    pattern = r'^[\d\s\-\(\)\+]{7,20}$'
    return re.match(pattern, phone) is not None

def validate_positive_integer(value, max_val=10000):
    """Validate positive integer within range"""
    try:
        num = int(value)
        return 1 <= num <= max_val
    except (ValueError, TypeError):
        return False

def validate_date(date_str):
    """Validate date format YYYY-MM-DD"""
    try:
        datetime.strptime(date_str, '%Y-%m-%d')
        return True
    except ValueError:
        return False

def validate_username(username):
    """Validate username: alphanumeric, underscore, 3-20 chars"""
    pattern = r'^[a-zA-Z0-9_]{3,20}$'
    return re.match(pattern, username) is not None

def validate_password_strength(password):
    """Check password strength: min 8 chars, at least one number, one letter"""
    if len(password) < 8:
        return False, "Password must be at least 8 characters"
    if not re.search(r'[A-Za-z]', password):
        return False, "Password must contain at least one letter"
    if not re.search(r'\d', password):
        return False, "Password must contain at least one number"
    return True, "Password is strong"

def sanitize_search_query(query, max_length=100):
    """Sanitize search query to prevent SQL wildcard abuse"""
    if not query:
        return ''
    # Strip and limit length
    query = str(query).strip()[:max_length]
    # Escape SQL LIKE special characters
    query = query.replace('\\', '\\\\').replace('%', '\\%').replace('_', '\\_')
    return query

# =============================================================================
# SECURITY HEADERS MIDDLEWARE
# =============================================================================

@app.after_request
def add_security_headers(response):
    """Add security headers to all responses"""
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    response.headers['Pragma'] = 'no-cache'

    # HSTS header - only enable when using HTTPS
    if os.environ.get('ENABLE_HSTS', 'false').lower() == 'true':
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'

    # Permissions Policy (formerly Feature Policy)
    response.headers['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=()'

    # Content Security Policy
    if not request.path.startswith('/api/'):
        response.headers['Content-Security-Policy'] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; "
            "font-src 'self'; "
            "form-action 'self'; "
            "frame-ancestors 'self'; "
            "base-uri 'self'"
        )
    return response

# CSRF Error Handler
@app.errorhandler(CSRFError)
def handle_csrf_error(e):
    """Handle CSRF validation errors"""
    if request.path.startswith('/api/'):
        return jsonify({'error': 'CSRF token invalid or missing'}), 403
    flash('Security validation failed. Please try again.', 'error')
    return redirect(request.referrer or url_for('index'))

# Data and log directories
DATA_DIR = 'data'
LOG_DIR = 'logs'
DATABASE = os.path.join(DATA_DIR, 'library.db')

# Ensure data and logs directories exist
os.makedirs(DATA_DIR, exist_ok=True)
os.makedirs(LOG_DIR, exist_ok=True)

# Configure logging
def setup_logging():
    """Configure application logging with multiple handlers"""

    # Create formatters
    detailed_formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    simple_formatter = logging.Formatter(
        '%(asctime)s - %(levelname)s - %(message)s'
    )

    # Application logger
    app_logger = logging.getLogger('library')
    app_logger.setLevel(logging.DEBUG)

    # Console handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(simple_formatter)

    # File handler for general logs
    file_handler = RotatingFileHandler(
        os.path.join(LOG_DIR, 'app.log'),
        maxBytes=10*1024*1024,  # 10MB
        backupCount=5
    )
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(detailed_formatter)

    # File handler for errors only
    error_handler = RotatingFileHandler(
        os.path.join(LOG_DIR, 'error.log'),
        maxBytes=10*1024*1024,  # 10MB
        backupCount=5
    )
    error_handler.setLevel(logging.ERROR)
    error_handler.setFormatter(detailed_formatter)

    # File handler for audit trail
    audit_handler = RotatingFileHandler(
        os.path.join(LOG_DIR, 'audit.log'),
        maxBytes=10*1024*1024,  # 10MB
        backupCount=10
    )
    audit_handler.setLevel(logging.INFO)
    audit_handler.setFormatter(detailed_formatter)

    # Add handlers to app logger
    app_logger.addHandler(console_handler)
    app_logger.addHandler(file_handler)
    app_logger.addHandler(error_handler)

    # Create separate audit logger
    audit_logger = logging.getLogger('library.audit')
    audit_logger.addHandler(audit_handler)
    audit_logger.setLevel(logging.INFO)

    return app_logger, audit_logger

# Initialize loggers
logger, audit_logger = setup_logging()

# Request/Response logging middleware
@app.before_request
def before_request():
    """Log incoming requests and start timing"""
    g.start_time = time.time()
    logger.info(f"Request: {request.method} {request.path} - IP: {request.remote_addr}")
    if request.args:
        logger.debug(f"Query params: {dict(request.args)}")

@app.after_request
def after_request(response):
    """Log response details and timing"""
    duration = time.time() - g.get('start_time', time.time())
    logger.info(
        f"Response: {request.method} {request.path} - "
        f"Status: {response.status_code} - Duration: {duration:.3f}s"
    )
    return response

@app.errorhandler(Exception)
def handle_exception(e):
    """Log unhandled exceptions"""
    logger.exception(f"Unhandled exception: {str(e)}")
    flash('An unexpected error occurred. Please try again.', 'error')
    if 'user_id' in session:
        return redirect(url_for('index'))
    return redirect(url_for('login'))

@contextmanager
def get_db():
    """Context manager for database connections"""
    logger.debug(f"Opening database connection to {DATABASE}")
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
    except sqlite3.Error as e:
        logger.error(f"Database error: {str(e)}")
        raise
    finally:
        conn.close()
        logger.debug("Database connection closed")

def init_db():
    """Initialize the database with required tables"""
    logger.info("Initializing database...")
    with get_db() as conn:
        cursor = conn.cursor()
        
        # Books table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS books (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                author TEXT NOT NULL,
                isbn TEXT UNIQUE NOT NULL,
                publisher TEXT,
                publication_year INTEGER,
                category TEXT,
                total_copies INTEGER DEFAULT 1,
                available_copies INTEGER DEFAULT 1,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Members table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS members (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                email TEXT UNIQUE NOT NULL,
                phone TEXT,
                address TEXT,
                membership_date DATE DEFAULT CURRENT_DATE,
                status TEXT DEFAULT 'active',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Transactions table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS transactions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                book_id INTEGER NOT NULL,
                member_id INTEGER NOT NULL,
                issue_date DATE NOT NULL,
                due_date DATE NOT NULL,
                return_date DATE,
                status TEXT DEFAULT 'issued',
                fine_amount REAL DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (book_id) REFERENCES books (id),
                FOREIGN KEY (member_id) REFERENCES members (id)
            )
        ''')

        # Users table for authentication
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                email TEXT UNIQUE NOT NULL,
                role TEXT DEFAULT 'staff',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        # API tokens table for mobile app authentication
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS api_tokens (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                token TEXT UNIQUE NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')

        # Chat messages table for admin-to-admin communication
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS chat_messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sender_id INTEGER NOT NULL,
                receiver_id INTEGER NOT NULL,
                message TEXT NOT NULL,
                is_read INTEGER DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (sender_id) REFERENCES users (id),
                FOREIGN KEY (receiver_id) REFERENCES users (id)
            )
        ''')

        # Create default admin user if not exists
        cursor.execute('SELECT COUNT(*) FROM users WHERE username = ?', ('admin',))
        if cursor.fetchone()[0] == 0:
            # Use environment variable for admin password or generate a secure random one
            admin_password = os.environ.get('ADMIN_PASSWORD') or secrets.token_urlsafe(16)
            cursor.execute('''
                INSERT INTO users (username, password_hash, email, role)
                VALUES (?, ?, ?, ?)
            ''', ('admin', generate_password_hash(admin_password), 'admin@library.com', 'admin'))
            logger.warning("Default admin user created - CHANGE PASSWORD IMMEDIATELY!")
            if not os.environ.get('ADMIN_PASSWORD'):
                # Only print to console in development, never log the password
                print(f"\n*** IMPORTANT: Default admin password: {admin_password} ***")
                print("*** Set ADMIN_PASSWORD environment variable in production ***\n")

        conn.commit()
        logger.info("Database initialization complete")

# Authentication decorator for web routes
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Check for API token first (for mobile apps)
        auth_header = request.headers.get('Authorization')
        if auth_header and auth_header.startswith('Bearer '):
            token = auth_header.split(' ')[1]
            with get_db() as conn:
                cursor = conn.cursor()
                token_record = cursor.execute('''
                    SELECT t.user_id, t.expires_at, u.username, u.role
                    FROM api_tokens t
                    JOIN users u ON t.user_id = u.id
                    WHERE t.token = ?
                ''', (token,)).fetchone()

                if token_record:
                    # Check if token has expired
                    if token_record['expires_at']:
                        expires_at = datetime.strptime(token_record['expires_at'], '%Y-%m-%d %H:%M:%S')
                        if datetime.now() > expires_at:
                            # Delete expired token
                            cursor.execute('DELETE FROM api_tokens WHERE token = ?', (token,))
                            conn.commit()
                            return jsonify({'error': 'Token expired. Please login again.'}), 401

                    # Set session data for the request
                    session['user_id'] = token_record['user_id']
                    session['username'] = token_record['username']
                    session['role'] = token_record['role']
                    return f(*args, **kwargs)

        # Fall back to session-based auth
        if 'user_id' not in session:
            # For API requests, return JSON error
            if request.path.startswith('/api/'):
                return jsonify({'error': 'Unauthorized'}), 401
            flash('Please log in to access this page.', 'error')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# Admin-only decorator for chat features
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Check for API token first (for mobile apps)
        auth_header = request.headers.get('Authorization')
        if auth_header and auth_header.startswith('Bearer '):
            token = auth_header.split(' ')[1]
            with get_db() as conn:
                cursor = conn.cursor()
                token_record = cursor.execute('''
                    SELECT t.user_id, t.expires_at, u.username, u.role
                    FROM api_tokens t
                    JOIN users u ON t.user_id = u.id
                    WHERE t.token = ?
                ''', (token,)).fetchone()

                if token_record:
                    # Check if token has expired
                    if token_record['expires_at']:
                        expires_at = datetime.strptime(token_record['expires_at'], '%Y-%m-%d %H:%M:%S')
                        if datetime.now() > expires_at:
                            # Delete expired token
                            cursor.execute('DELETE FROM api_tokens WHERE token = ?', (token,))
                            conn.commit()
                            return jsonify({'error': 'Token expired. Please login again.'}), 401

                    if token_record['role'] != 'admin':
                        return jsonify({'error': 'Admin access required'}), 403
                    session['user_id'] = token_record['user_id']
                    session['username'] = token_record['username']
                    session['role'] = token_record['role']
                    return f(*args, **kwargs)

        # Fall back to session-based auth
        if 'user_id' not in session:
            if request.path.startswith('/api/'):
                return jsonify({'error': 'Unauthorized'}), 401
            flash('Please log in to access this page.', 'error')
            return redirect(url_for('login'))
        if session.get('role') != 'admin':
            if request.path.startswith('/api/'):
                return jsonify({'error': 'Admin access required'}), 403
            flash('Admin access required.', 'error')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

# Authentication Routes
@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute", methods=["POST"])
def login():
    """User login"""
    if 'user_id' in session:
        return redirect(url_for('index'))

    if request.method == 'POST':
        username = sanitize_string(request.form.get('username', ''), 20)
        password = request.form.get('password', '')

        # Validate input
        if not username or not password:
            flash('Username and password are required.', 'error')
            return render_template('login.html')

        with get_db() as conn:
            cursor = conn.cursor()
            user = cursor.execute(
                'SELECT * FROM users WHERE username = ?', (username,)
            ).fetchone()

            if user and check_password_hash(user['password_hash'], password):
                session.permanent = True
                session['user_id'] = user['id']
                session['username'] = user['username']
                session['role'] = user['role']
                audit_logger.info(f"USER_LOGIN: username='{username}', ip='{request.remote_addr}'")
                flash('Welcome back!', 'success')
                return redirect(url_for('index'))
            else:
                logger.warning(f"Failed login attempt for username: {username}, ip: {request.remote_addr}")
                flash('Invalid username or password.', 'error')

    return render_template('login.html')

@app.route('/logout')
def logout():
    """User logout"""
    username = session.get('username', 'unknown')
    session.clear()
    audit_logger.info(f"USER_LOGOUT: username='{username}'")
    flash('You have been logged out.', 'success')
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
@limiter.limit("3 per minute", methods=["POST"])
def register():
    """User registration"""
    if 'user_id' in session:
        return redirect(url_for('index'))

    if request.method == 'POST':
        username = sanitize_string(request.form.get('username', ''), 20)
        email = sanitize_string(request.form.get('email', ''), 100).lower()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')

        # Validation
        if not validate_username(username):
            flash('Username must be 3-20 alphanumeric characters or underscores.', 'error')
            return render_template('register.html')

        if not validate_email(email):
            flash('Please enter a valid email address.', 'error')
            return render_template('register.html')

        if password != confirm_password:
            flash('Passwords do not match.', 'error')
            return render_template('register.html')

        is_strong, msg = validate_password_strength(password)
        if not is_strong:
            flash(msg, 'error')
            return render_template('register.html')

        try:
            with get_db() as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT INTO users (username, password_hash, email, role)
                    VALUES (?, ?, ?, ?)
                ''', (username, generate_password_hash(password), email, 'staff'))
                conn.commit()
                audit_logger.info(f"USER_REGISTERED: username='{username}', ip='{request.remote_addr}'")
            flash('Account created successfully! Please sign in.', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError as e:
            if 'username' in str(e).lower():
                flash('Username already exists.', 'error')
            else:
                flash('Email already exists.', 'error')
            logger.warning(f"Registration failed for username={username}: integrity error")

    return render_template('register.html')

@app.route('/change-password', methods=['GET', 'POST'])
@login_required
@limiter.limit("3 per minute", methods=["POST"])
def change_password():
    """Change user password"""
    if request.method == 'POST':
        current_password = request.form.get('current_password', '')
        new_password = request.form.get('new_password', '')
        confirm_password = request.form.get('confirm_password', '')

        if new_password != confirm_password:
            flash('New passwords do not match.', 'error')
            return render_template('change_password.html')

        is_strong, msg = validate_password_strength(new_password)
        if not is_strong:
            flash(msg, 'error')
            return render_template('change_password.html')

        with get_db() as conn:
            cursor = conn.cursor()
            user = cursor.execute(
                'SELECT * FROM users WHERE id = ?', (session['user_id'],)
            ).fetchone()

            if user and check_password_hash(user['password_hash'], current_password):
                cursor.execute(
                    'UPDATE users SET password_hash = ? WHERE id = ?',
                    (generate_password_hash(new_password), session['user_id'])
                )
                # Invalidate all API tokens for this user on password change
                cursor.execute('DELETE FROM api_tokens WHERE user_id = ?', (session['user_id'],))
                conn.commit()
                audit_logger.info(f"PASSWORD_CHANGED: username='{session['username']}', ip='{request.remote_addr}'")
                flash('Password updated successfully!', 'success')
                return redirect(url_for('index'))
            else:
                logger.warning(f"Failed password change attempt for user: {session['username']}, ip: {request.remote_addr}")
                flash('Current password is incorrect.', 'error')

    return render_template('change_password.html')

@app.route('/forgot-password', methods=['GET', 'POST'])
@limiter.limit("3 per minute", methods=["POST"])
def forgot_password():
    """Reset password using username and email verification"""
    if 'user_id' in session:
        return redirect(url_for('index'))

    if request.method == 'POST':
        username = sanitize_string(request.form.get('username', ''), 20)
        email = sanitize_string(request.form.get('email', ''), 100).lower()
        new_password = request.form.get('new_password', '')
        confirm_password = request.form.get('confirm_password', '')

        if new_password != confirm_password:
            flash('Passwords do not match.', 'error')
            return render_template('forgot_password.html')

        is_strong, msg = validate_password_strength(new_password)
        if not is_strong:
            flash(msg, 'error')
            return render_template('forgot_password.html')

        with get_db() as conn:
            cursor = conn.cursor()
            user = cursor.execute(
                'SELECT * FROM users WHERE username = ? AND email = ?',
                (username, email)
            ).fetchone()

            if user:
                cursor.execute(
                    'UPDATE users SET password_hash = ? WHERE id = ?',
                    (generate_password_hash(new_password), user['id'])
                )
                # Invalidate all API tokens for this user on password reset
                cursor.execute('DELETE FROM api_tokens WHERE user_id = ?', (user['id'],))
                conn.commit()
                audit_logger.info(f"PASSWORD_RESET: username='{username}', ip='{request.remote_addr}'")
                flash('Password reset successfully! Please sign in with your new password.', 'success')
                return redirect(url_for('login'))
            else:
                logger.warning(f"Failed password reset attempt, ip: {request.remote_addr}")
                flash('No account found with that username and email combination.', 'error')

    return render_template('forgot_password.html')

# Routes
@app.route('/')
@login_required
def index():
    """Dashboard showing library statistics"""
    with get_db() as conn:
        cursor = conn.cursor()
        
        # Get statistics
        total_books = cursor.execute('SELECT COUNT(*) FROM books').fetchone()[0]
        total_members = cursor.execute('SELECT COUNT(*) FROM members WHERE status="active"').fetchone()[0]
        issued_books = cursor.execute('SELECT COUNT(*) FROM transactions WHERE status="issued"').fetchone()[0]
        overdue_books = cursor.execute('''
            SELECT COUNT(*) FROM transactions 
            WHERE status="issued" AND due_date < date('now')
        ''').fetchone()[0]
        
        # Recent transactions
        recent_transactions = cursor.execute('''
            SELECT t.id, b.title, m.name, t.issue_date, t.due_date, t.status
            FROM transactions t
            JOIN books b ON t.book_id = b.id
            JOIN members m ON t.member_id = m.id
            ORDER BY t.created_at DESC
            LIMIT 5
        ''').fetchall()
        
    return render_template('index.html', 
                         total_books=total_books,
                         total_members=total_members,
                         issued_books=issued_books,
                         overdue_books=overdue_books,
                         recent_transactions=recent_transactions)

# Books Management
@app.route('/books')
@login_required
def books():
    """List all books"""
    search = request.args.get('search', '')
    category = request.args.get('category', '')
    
    with get_db() as conn:
        cursor = conn.cursor()
        
        query = 'SELECT * FROM books WHERE 1=1'
        params = []
        
        if search:
            query += ' AND (title LIKE ? OR author LIKE ? OR isbn LIKE ?)'
            params.extend([f'%{search}%', f'%{search}%', f'%{search}%'])
        
        if category:
            query += ' AND category = ?'
            params.append(category)
        
        query += ' ORDER BY title'
        
        books = cursor.execute(query, params).fetchall()
        categories = cursor.execute('SELECT DISTINCT category FROM books WHERE category IS NOT NULL').fetchall()
        
    return render_template('books.html', books=books, categories=categories, search=search, selected_category=category)

@app.route('/books/add', methods=['GET', 'POST'])
@login_required
def add_book():
    """Add a new book"""
    if request.method == 'POST':
        title = sanitize_string(request.form.get('title', ''), 200)
        author = sanitize_string(request.form.get('author', ''), 200)
        isbn = sanitize_string(request.form.get('isbn', ''), 20)
        publisher = sanitize_string(request.form.get('publisher', ''), 200)
        publication_year = request.form.get('publication_year', None)
        category = sanitize_string(request.form.get('category', ''), 50)
        total_copies = request.form.get('total_copies', 1)

        # Validation
        if not title or len(title) < 1:
            flash('Title is required.', 'error')
            return render_template('add_book.html')

        if not author or len(author) < 1:
            flash('Author is required.', 'error')
            return render_template('add_book.html')

        if not isbn or not validate_isbn(isbn):
            flash('Please enter a valid ISBN (10 or 13 digits).', 'error')
            return render_template('add_book.html')

        if not validate_positive_integer(total_copies, 1000):
            flash('Total copies must be a number between 1 and 1000.', 'error')
            return render_template('add_book.html')

        total_copies = int(total_copies)

        # Validate publication year if provided
        if publication_year:
            try:
                year = int(publication_year)
                if year < 1000 or year > datetime.now().year + 1:
                    flash('Please enter a valid publication year.', 'error')
                    return render_template('add_book.html')
            except ValueError:
                flash('Publication year must be a valid number.', 'error')
                return render_template('add_book.html')

        try:
            with get_db() as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT INTO books (title, author, isbn, publisher, publication_year, category, total_copies, available_copies)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ''', (title, author, isbn, publisher, publication_year, category, total_copies, total_copies))
                conn.commit()
                audit_logger.info(f"BOOK_CREATED: isbn='{isbn}', user='{session['username']}'")
            flash('Book added successfully!', 'success')
            return redirect(url_for('books'))
        except sqlite3.IntegrityError:
            logger.warning(f"Failed to add book - ISBN already exists: {isbn}")
            flash('Book with this ISBN already exists!', 'error')

    return render_template('add_book.html')

@app.route('/books/edit/<int:book_id>', methods=['GET', 'POST'])
@login_required
def edit_book(book_id):
    """Edit a book"""
    with get_db() as conn:
        cursor = conn.cursor()

        if request.method == 'POST':
            # Sanitize all inputs
            title = sanitize_string(request.form.get('title', ''), 200)
            author = sanitize_string(request.form.get('author', ''), 200)
            isbn = sanitize_string(request.form.get('isbn', ''), 20)
            publisher = sanitize_string(request.form.get('publisher', ''), 200)
            publication_year = request.form.get('publication_year', None)
            category = sanitize_string(request.form.get('category', ''), 50)
            total_copies_str = request.form.get('total_copies', '1')

            # Validation
            if not title or len(title) < 1:
                flash('Title is required.', 'error')
                return redirect(url_for('edit_book', book_id=book_id))

            if not author or len(author) < 1:
                flash('Author is required.', 'error')
                return redirect(url_for('edit_book', book_id=book_id))

            if not isbn or not validate_isbn(isbn):
                flash('Please enter a valid ISBN (10 or 13 digits).', 'error')
                return redirect(url_for('edit_book', book_id=book_id))

            if not validate_positive_integer(total_copies_str, 1000):
                flash('Total copies must be a number between 1 and 1000.', 'error')
                return redirect(url_for('edit_book', book_id=book_id))

            total_copies = int(total_copies_str)

            # Validate publication year if provided
            if publication_year:
                try:
                    year = int(publication_year)
                    if year < 1000 or year > datetime.now().year + 1:
                        flash('Please enter a valid publication year.', 'error')
                        return redirect(url_for('edit_book', book_id=book_id))
                except ValueError:
                    flash('Publication year must be a valid number.', 'error')
                    return redirect(url_for('edit_book', book_id=book_id))
            
            try:
                # Get current available copies
                current_book = cursor.execute('SELECT total_copies, available_copies FROM books WHERE id = ?', (book_id,)).fetchone()
                issued_copies = current_book['total_copies'] - current_book['available_copies']
                new_available = total_copies - issued_copies
                
                if new_available < 0:
                    flash('Total copies cannot be less than issued copies!', 'error')
                    return redirect(url_for('edit_book', book_id=book_id))
                
                cursor.execute('''
                    UPDATE books
                    SET title=?, author=?, isbn=?, publisher=?, publication_year=?, category=?, total_copies=?, available_copies=?
                    WHERE id=?
                ''', (title, author, isbn, publisher, publication_year, category, total_copies, new_available, book_id))
                conn.commit()
                audit_logger.info(f"BOOK_UPDATED: id={book_id}, title='{title}', isbn='{isbn}'")
                flash('Book updated successfully!', 'success')
                return redirect(url_for('books'))
            except sqlite3.IntegrityError:
                logger.warning(f"Failed to update book {book_id} - ISBN already exists: {isbn}")
                flash('Book with this ISBN already exists!', 'error')
        
        book = cursor.execute('SELECT * FROM books WHERE id = ?', (book_id,)).fetchone()
    
    return render_template('edit_book.html', book=book)

@app.route('/books/delete/<int:book_id>', methods=['POST'])
@login_required
def delete_book(book_id):
    """Delete a book"""
    with get_db() as conn:
        cursor = conn.cursor()
        
        # Check if book has active transactions
        active_transactions = cursor.execute('''
            SELECT COUNT(*) FROM transactions WHERE book_id = ? AND status = "issued"
        ''', (book_id,)).fetchone()[0]
        
        if active_transactions > 0:
            logger.warning(f"Cannot delete book {book_id} - has active transactions")
            flash('Cannot delete book with active transactions!', 'error')
        else:
            cursor.execute('DELETE FROM books WHERE id = ?', (book_id,))
            conn.commit()
            audit_logger.info(f"BOOK_DELETED: id={book_id}")
            flash('Book deleted successfully!', 'success')

    return redirect(url_for('books'))

# Members Management
@app.route('/members')
@login_required
def members():
    """List all members"""
    search = request.args.get('search', '')
    status = request.args.get('status', '')
    
    with get_db() as conn:
        cursor = conn.cursor()
        
        query = 'SELECT * FROM members WHERE 1=1'
        params = []
        
        if search:
            query += ' AND (name LIKE ? OR email LIKE ? OR phone LIKE ?)'
            params.extend([f'%{search}%', f'%{search}%', f'%{search}%'])
        
        if status:
            query += ' AND status = ?'
            params.append(status)
        
        query += ' ORDER BY name'
        
        members = cursor.execute(query, params).fetchall()
    
    return render_template('members.html', members=members, search=search, selected_status=status)

@app.route('/members/add', methods=['GET', 'POST'])
@login_required
def add_member():
    """Add a new member"""
    if request.method == 'POST':
        name = sanitize_string(request.form.get('name', ''), 100)
        email = sanitize_string(request.form.get('email', ''), 100).lower()
        phone = sanitize_string(request.form.get('phone', ''), 20)
        address = sanitize_string(request.form.get('address', ''), 500)

        # Validation
        if not name or len(name) < 2:
            flash('Name is required (minimum 2 characters).', 'error')
            return render_template('add_member.html')

        if not validate_email(email):
            flash('Please enter a valid email address.', 'error')
            return render_template('add_member.html')

        if phone and not validate_phone(phone):
            flash('Please enter a valid phone number.', 'error')
            return render_template('add_member.html')

        try:
            with get_db() as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT INTO members (name, email, phone, address)
                    VALUES (?, ?, ?, ?)
                ''', (name, email, phone, address))
                conn.commit()
                audit_logger.info(f"MEMBER_CREATED: email='{email}', user='{session['username']}'")
            flash('Member added successfully!', 'success')
            return redirect(url_for('members'))
        except sqlite3.IntegrityError:
            logger.warning(f"Failed to add member - email already exists")
            flash('Member with this email already exists!', 'error')

    return render_template('add_member.html')

@app.route('/members/edit/<int:member_id>', methods=['GET', 'POST'])
@login_required
def edit_member(member_id):
    """Edit a member"""
    with get_db() as conn:
        cursor = conn.cursor()

        if request.method == 'POST':
            # Sanitize all inputs
            name = sanitize_string(request.form.get('name', ''), 100)
            email = sanitize_string(request.form.get('email', ''), 100).lower()
            phone = sanitize_string(request.form.get('phone', ''), 20)
            address = sanitize_string(request.form.get('address', ''), 500)
            status = request.form.get('status', 'active')

            # Validation
            if not name or len(name) < 2:
                flash('Name is required (minimum 2 characters).', 'error')
                return redirect(url_for('edit_member', member_id=member_id))

            if not validate_email(email):
                flash('Please enter a valid email address.', 'error')
                return redirect(url_for('edit_member', member_id=member_id))

            if phone and not validate_phone(phone):
                flash('Please enter a valid phone number.', 'error')
                return redirect(url_for('edit_member', member_id=member_id))

            # Validate status
            if status not in ['active', 'inactive']:
                flash('Invalid status value.', 'error')
                return redirect(url_for('edit_member', member_id=member_id))

            try:
                cursor.execute('''
                    UPDATE members
                    SET name=?, email=?, phone=?, address=?, status=?
                    WHERE id=?
                ''', (name, email, phone, address, status, member_id))
                conn.commit()
                audit_logger.info(f"MEMBER_UPDATED: id={member_id}, name='{name}', email='{email}', status='{status}'")
                flash('Member updated successfully!', 'success')
                return redirect(url_for('members'))
            except sqlite3.IntegrityError:
                logger.warning(f"Failed to update member {member_id} - email already exists: {email}")
                flash('Member with this email already exists!', 'error')
        
        member = cursor.execute('SELECT * FROM members WHERE id = ?', (member_id,)).fetchone()
    
    return render_template('edit_member.html', member=member)

@app.route('/members/delete/<int:member_id>', methods=['POST'])
@login_required
def delete_member(member_id):
    """Delete a member"""
    with get_db() as conn:
        cursor = conn.cursor()
        
        # Check if member has active transactions
        active_transactions = cursor.execute('''
            SELECT COUNT(*) FROM transactions WHERE member_id = ? AND status = "issued"
        ''', (member_id,)).fetchone()[0]
        
        if active_transactions > 0:
            logger.warning(f"Cannot delete member {member_id} - has active transactions")
            flash('Cannot delete member with active transactions!', 'error')
        else:
            cursor.execute('DELETE FROM members WHERE id = ?', (member_id,))
            conn.commit()
            audit_logger.info(f"MEMBER_DELETED: id={member_id}")
            flash('Member deleted successfully!', 'success')

    return redirect(url_for('members'))

# Transactions Management
@app.route('/transactions')
@login_required
def transactions():
    """List all transactions"""
    status = request.args.get('status', '')
    
    with get_db() as conn:
        cursor = conn.cursor()
        
        query = '''
            SELECT t.*, b.title, b.author, m.name as member_name
            FROM transactions t
            JOIN books b ON t.book_id = b.id
            JOIN members m ON t.member_id = m.id
            WHERE 1=1
        '''
        params = []
        
        if status:
            query += ' AND t.status = ?'
            params.append(status)
        
        query += ' ORDER BY t.created_at DESC'
        
        transactions = cursor.execute(query, params).fetchall()
    
    return render_template('transactions.html', transactions=transactions, selected_status=status)

@app.route('/transactions/issue', methods=['GET', 'POST'])
@login_required
def issue_book():
    """Issue a book to a member"""
    if request.method == 'POST':
        # Validate and sanitize inputs
        book_id_str = request.form.get('book_id', '')
        member_id_str = request.form.get('member_id', '')
        issue_date = request.form.get('issue_date', '')
        due_days_str = request.form.get('due_days', '14')

        # Validate book_id
        if not validate_positive_integer(book_id_str, 999999):
            flash('Invalid book selection.', 'error')
            return redirect(url_for('issue_book'))
        book_id = int(book_id_str)

        # Validate member_id
        if not validate_positive_integer(member_id_str, 999999):
            flash('Invalid member selection.', 'error')
            return redirect(url_for('issue_book'))
        member_id = int(member_id_str)

        # Validate issue_date
        if not validate_date(issue_date):
            flash('Invalid issue date format. Use YYYY-MM-DD.', 'error')
            return redirect(url_for('issue_book'))

        # Validate due_days
        if not validate_positive_integer(due_days_str, 365):
            flash('Due days must be between 1 and 365.', 'error')
            return redirect(url_for('issue_book'))
        due_days = int(due_days_str)

        due_date = datetime.strptime(issue_date, '%Y-%m-%d') + timedelta(days=due_days)
        
        with get_db() as conn:
            cursor = conn.cursor()
            
            # Check if book is available
            book = cursor.execute('SELECT available_copies FROM books WHERE id = ?', (book_id,)).fetchone()
            
            if book and book['available_copies'] > 0:
                # Issue the book
                cursor.execute('''
                    INSERT INTO transactions (book_id, member_id, issue_date, due_date, status)
                    VALUES (?, ?, ?, ?, 'issued')
                ''', (book_id, member_id, issue_date, due_date.strftime('%Y-%m-%d')))

                # Update available copies
                cursor.execute('''
                    UPDATE books SET available_copies = available_copies - 1 WHERE id = ?
                ''', (book_id,))

                conn.commit()
                audit_logger.info(f"BOOK_ISSUED: book_id={book_id}, member_id={member_id}, due_date={due_date.strftime('%Y-%m-%d')}")
                flash('Book issued successfully!', 'success')
                return redirect(url_for('transactions'))
            else:
                logger.warning(f"Cannot issue book {book_id} - not available")
                flash('Book is not available!', 'error')
    
    with get_db() as conn:
        cursor = conn.cursor()
        books = cursor.execute('SELECT * FROM books WHERE available_copies > 0 ORDER BY title').fetchall()
        members = cursor.execute('SELECT * FROM members WHERE status = "active" ORDER BY name').fetchall()
    
    return render_template('issue_book.html', books=books, members=members)

@app.route('/transactions/return/<int:transaction_id>', methods=['POST'])
@login_required
def return_book(transaction_id):
    """Return a book"""
    return_date = request.form.get('return_date', '')

    # Validate return_date
    if not validate_date(return_date):
        flash('Invalid return date format. Use YYYY-MM-DD.', 'error')
        return redirect(url_for('transactions'))

    with get_db() as conn:
        cursor = conn.cursor()
        
        # Get transaction details
        transaction = cursor.execute('''
            SELECT * FROM transactions WHERE id = ?
        ''', (transaction_id,)).fetchone()
        
        if transaction:
            # Calculate fine if overdue
            due = datetime.strptime(transaction['due_date'], '%Y-%m-%d')
            returned = datetime.strptime(return_date, '%Y-%m-%d')
            
            fine = 0
            if returned > due:
                overdue_days = (returned - due).days
                fine = overdue_days * 1.0  # $1 per day
            
            # Update transaction
            cursor.execute('''
                UPDATE transactions
                SET return_date = ?, status = 'returned', fine_amount = ?
                WHERE id = ?
            ''', (return_date, fine, transaction_id))

            # Update available copies
            cursor.execute('''
                UPDATE books SET available_copies = available_copies + 1 WHERE id = ?
            ''', (transaction['book_id'],))

            conn.commit()
            audit_logger.info(f"BOOK_RETURNED: transaction_id={transaction_id}, book_id={transaction['book_id']}, fine=${fine:.2f}")

            if fine > 0:
                logger.info(f"Overdue fine calculated: transaction_id={transaction_id}, fine=${fine:.2f}")
                flash(f'Book returned successfully! Fine amount: ${fine:.2f}', 'warning')
            else:
                flash('Book returned successfully!', 'success')
        else:
            logger.error(f"Transaction not found: {transaction_id}")
            flash('Transaction not found!', 'error')
    
    return redirect(url_for('transactions'))

# Chat Web Route
@app.route('/chat')
@login_required
def chat():
    """Chat page for all users"""
    return render_template('chat.html')

# Ledger Web Route
@app.route('/ledger')
@admin_required
def ledger():
    """Admin ledger page showing collected fines"""
    with get_db() as conn:
        cursor = conn.cursor()

        # Get all returned transactions with fines
        fines = cursor.execute('''
            SELECT
                t.id as transaction_id,
                t.fine_amount,
                t.return_date,
                t.issue_date,
                t.due_date,
                b.title as book_title,
                b.isbn,
                m.name as member_name,
                m.email as member_email,
                julianday(t.return_date) - julianday(t.due_date) as days_overdue
            FROM transactions t
            JOIN books b ON t.book_id = b.id
            JOIN members m ON t.member_id = m.id
            WHERE t.status = 'returned' AND t.fine_amount > 0
            ORDER BY t.return_date DESC
        ''').fetchall()

        # Today's fines
        today_fines = cursor.execute('''
            SELECT COALESCE(SUM(fine_amount), 0) FROM transactions
            WHERE status = 'returned' AND fine_amount > 0
            AND date(return_date) = date('now')
        ''').fetchone()[0]

        # This week's fines
        week_fines = cursor.execute('''
            SELECT COALESCE(SUM(fine_amount), 0) FROM transactions
            WHERE status = 'returned' AND fine_amount > 0
            AND return_date >= date('now', '-7 days')
        ''').fetchone()[0]

        # This month's fines
        month_fines = cursor.execute('''
            SELECT COALESCE(SUM(fine_amount), 0) FROM transactions
            WHERE status = 'returned' AND fine_amount > 0
            AND strftime('%Y-%m', return_date) = strftime('%Y-%m', 'now')
        ''').fetchone()[0]

        # Total all-time fines
        total_fines = cursor.execute('''
            SELECT COALESCE(SUM(fine_amount), 0) FROM transactions
            WHERE status = 'returned' AND fine_amount > 0
        ''').fetchone()[0]

        # Currently overdue books (pending fines)
        pending_overdue = cursor.execute('''
            SELECT COUNT(*) FROM transactions
            WHERE status = 'issued' AND due_date < date('now')
        ''').fetchone()[0]

    return render_template('ledger.html',
                           fines=fines,
                           today_fines=today_fines,
                           week_fines=week_fines,
                           month_fines=month_fines,
                           total_fines=total_fines,
                           pending_overdue=pending_overdue)

# API endpoints

# Authentication APIs
@app.route('/api/auth/login', methods=['POST'])
@limiter.limit("5 per minute")
@csrf.exempt
def api_login():
    """API endpoint for user login - returns API token for mobile apps"""
    data = request.get_json()

    if not data or 'username' not in data or 'password' not in data:
        return jsonify({'error': 'Username and password required'}), 400

    username = sanitize_string(data.get('username', ''), 20)
    password = data.get('password', '')

    if not username or not password:
        return jsonify({'error': 'Username and password required'}), 400

    with get_db() as conn:
        cursor = conn.cursor()
        user = cursor.execute(
            'SELECT * FROM users WHERE username = ?', (username,)
        ).fetchone()

        if user and check_password_hash(user['password_hash'], password):
            # Generate API token for mobile app with 24-hour expiration
            api_token = secrets.token_hex(32)
            token_expires_at = datetime.now() + timedelta(hours=24)

            # Delete old tokens for this user (keep only one active token)
            cursor.execute('DELETE FROM api_tokens WHERE user_id = ?', (user['id'],))

            # Store the new token with expiration
            cursor.execute('''
                INSERT INTO api_tokens (user_id, token, expires_at)
                VALUES (?, ?, ?)
            ''', (user['id'], api_token, token_expires_at.strftime('%Y-%m-%d %H:%M:%S')))
            conn.commit()

            # Also set session for web compatibility
            session.permanent = True
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['role'] = user['role']

            audit_logger.info(f"API_LOGIN: username='{username}', ip='{request.remote_addr}'")

            return jsonify({
                'success': True,
                'message': 'Login successful',
                'token': api_token,
                'user': {
                    'id': user['id'],
                    'username': user['username'],
                    'email': user['email'],
                    'role': user['role']
                }
            }), 200
        else:
            logger.warning(f"API failed login attempt, ip: {request.remote_addr}")
            return jsonify({'error': 'Invalid username or password'}), 401

@app.route('/api/auth/logout', methods=['POST'])
@login_required
def api_logout():
    """API endpoint for user logout"""
    username = session.get('username', 'unknown')
    session.clear()
    audit_logger.info(f"API_LOGOUT: username='{username}'")
    return jsonify({'success': True, 'message': 'Logout successful'}), 200

@app.route('/api/auth/register', methods=['POST'])
@limiter.limit("3 per minute")
@csrf.exempt
def api_register():
    """API endpoint for user registration"""
    data = request.get_json()

    if not data:
        return jsonify({'error': 'Request body required'}), 400

    username = sanitize_string(data.get('username', ''), 20)
    email = sanitize_string(data.get('email', ''), 100).lower()
    password = data.get('password', '')

    # Validation
    if not validate_username(username):
        return jsonify({'error': 'Username must be 3-20 alphanumeric characters or underscores'}), 400

    if not validate_email(email):
        return jsonify({'error': 'Please provide a valid email address'}), 400

    is_strong, msg = validate_password_strength(password)
    if not is_strong:
        return jsonify({'error': msg}), 400

    try:
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO users (username, password_hash, email, role)
                VALUES (?, ?, ?, ?)
            ''', (username, generate_password_hash(password), email, 'staff'))
            conn.commit()
            audit_logger.info(f"API_USER_REGISTERED: username='{username}', ip='{request.remote_addr}'")

        return jsonify({
            'success': True,
            'message': 'Account created successfully',
            'user': {
                'username': username,
                'email': email,
                'role': 'staff'
            }
        }), 201
    except sqlite3.IntegrityError as e:
        if 'username' in str(e).lower():
            return jsonify({'error': 'Username already exists'}), 409
        else:
            return jsonify({'error': 'Email already exists'}), 409

@app.route('/api/auth/me', methods=['GET'])
@login_required
def api_get_current_user():
    """API endpoint to get current user info"""
    with get_db() as conn:
        cursor = conn.cursor()
        user = cursor.execute(
            'SELECT id, username, email, role, created_at FROM users WHERE id = ?',
            (session['user_id'],)
        ).fetchone()

        if user:
            return jsonify(dict(user)), 200
        return jsonify({'error': 'User not found'}), 404

# Dashboard API
@app.route('/api/dashboard')
@login_required
def api_dashboard():
    """API endpoint for dashboard statistics"""
    with get_db() as conn:
        cursor = conn.cursor()

        stats = {
            'total_books': cursor.execute('SELECT COUNT(*) FROM books').fetchone()[0],
            'total_members': cursor.execute('SELECT COUNT(*) FROM members WHERE status="active"').fetchone()[0],
            'issued_books': cursor.execute('SELECT COUNT(*) FROM transactions WHERE status="issued"').fetchone()[0],
            'overdue_books': cursor.execute('''
                SELECT COUNT(*) FROM transactions
                WHERE status="issued" AND due_date < date('now')
            ''').fetchone()[0]
        }

        return jsonify(stats)

@app.route('/api/books')
@login_required
def api_list_books():
    """API endpoint to list all books"""
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 10, type=int)
    search = request.args.get('search', '')
    category = request.args.get('category', '')

    offset = (page - 1) * per_page

    with get_db() as conn:
        cursor = conn.cursor()

        query = 'SELECT * FROM books WHERE 1=1'
        params = []

        if search:
            query += ' AND (title LIKE ? OR author LIKE ? OR isbn LIKE ?)'
            params.extend([f'%{search}%', f'%{search}%', f'%{search}%'])

        if category:
            query += ' AND category = ?'
            params.append(category)

        query += ' ORDER BY title LIMIT ? OFFSET ?'
        params.extend([per_page, offset])

        books = cursor.execute(query, params).fetchall()

        # Get total count
        count_query = 'SELECT COUNT(*) FROM books WHERE 1=1'
        count_params = []
        if search:
            count_query += ' AND (title LIKE ? OR author LIKE ? OR isbn LIKE ?)'
            count_params.extend([f'%{search}%', f'%{search}%', f'%{search}%'])
        if category:
            count_query += ' AND category = ?'
            count_params.append(category)

        total = cursor.execute(count_query, count_params).fetchone()[0]

        return jsonify({
            'books': [dict(book) for book in books],
            'page': page,
            'per_page': per_page,
            'total': total,
            'pages': (total + per_page - 1) // per_page
        })

@app.route('/api/books/<int:book_id>')
@login_required
def api_get_book(book_id):
    """API endpoint to get a single book"""
    with get_db() as conn:
        cursor = conn.cursor()
        book = cursor.execute('SELECT * FROM books WHERE id = ?', (book_id,)).fetchone()

        if book:
            return jsonify(dict(book))
        return jsonify({'error': 'Book not found'}), 404

@app.route('/api/books/search')
@login_required
def api_search_books():
    """API endpoint to search books"""
    search = request.args.get('q', '')
    with get_db() as conn:
        cursor = conn.cursor()
        books = cursor.execute('''
            SELECT id, title, author, isbn, available_copies
            FROM books
            WHERE (title LIKE ? OR author LIKE ? OR isbn LIKE ?) AND available_copies > 0
            LIMIT 10
        ''', (f'%{search}%', f'%{search}%', f'%{search}%')).fetchall()

        return jsonify([dict(book) for book in books])

@app.route('/api/books', methods=['POST'])
@login_required
@limiter.limit("30 per minute")
def api_create_book():
    """API endpoint to create a book"""
    data = request.get_json()

    if not data:
        return jsonify({'error': 'Request body required'}), 400

    # Sanitize all inputs
    title = sanitize_string(data.get('title', ''), 200)
    author = sanitize_string(data.get('author', ''), 200)
    isbn = sanitize_string(data.get('isbn', ''), 20)
    publisher = sanitize_string(data.get('publisher', ''), 200)
    publication_year = data.get('publication_year')
    category = sanitize_string(data.get('category', ''), 50)
    total_copies = data.get('total_copies', 1)

    if not title or not author:
        return jsonify({'error': 'Title and author are required'}), 400

    if not isbn or not validate_isbn(isbn):
        return jsonify({'error': 'Please provide a valid ISBN (10 or 13 digits)'}), 400

    # Validate publication year if provided
    if publication_year:
        try:
            year = int(publication_year)
            if year < 1000 or year > datetime.now().year + 1:
                return jsonify({'error': 'Please provide a valid publication year'}), 400
        except (ValueError, TypeError):
            return jsonify({'error': 'Publication year must be a valid number'}), 400

    try:
        total_copies = int(total_copies)
        if total_copies < 1:
            return jsonify({'error': 'Total copies must be at least 1'}), 400
    except ValueError:
        return jsonify({'error': 'Total copies must be a number'}), 400

    try:
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO books (title, author, isbn, publisher, publication_year, category, total_copies, available_copies)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (title, author, isbn, publisher, publication_year, category, total_copies, total_copies))
            conn.commit()
            book_id = cursor.lastrowid
            audit_logger.info(f"API_BOOK_CREATED: id={book_id}, title='{title}', isbn='{isbn}'")

        return jsonify({
            'success': True,
            'message': 'Book created successfully',
            'book': {
                'id': book_id,
                'title': title,
                'author': author,
                'isbn': isbn,
                'publisher': publisher,
                'publication_year': publication_year,
                'category': category,
                'total_copies': total_copies,
                'available_copies': total_copies
            }
        }), 201
    except sqlite3.IntegrityError:
        return jsonify({'error': 'Book with this ISBN already exists'}), 409

@app.route('/api/books/<int:book_id>', methods=['PUT'])
@login_required
@limiter.limit("30 per minute")
def api_update_book(book_id):
    """API endpoint to update a book"""
    data = request.get_json()

    if not data:
        return jsonify({'error': 'Request body required'}), 400

    with get_db() as conn:
        cursor = conn.cursor()

        # Check if book exists
        book = cursor.execute('SELECT * FROM books WHERE id = ?', (book_id,)).fetchone()
        if not book:
            return jsonify({'error': 'Book not found'}), 404

        # Sanitize all inputs
        title = sanitize_string(data.get('title', book['title']), 200)
        author = sanitize_string(data.get('author', book['author']), 200)
        isbn = sanitize_string(data.get('isbn', book['isbn']), 20)
        publisher = sanitize_string(data.get('publisher', book['publisher'] or ''), 200)
        publication_year = data.get('publication_year', book['publication_year'])
        category = sanitize_string(data.get('category', book['category'] or ''), 50)
        total_copies = data.get('total_copies', book['total_copies'])

        # Validate required fields
        if not title or not author:
            return jsonify({'error': 'Title and author are required'}), 400

        if not isbn or not validate_isbn(isbn):
            return jsonify({'error': 'Please provide a valid ISBN (10 or 13 digits)'}), 400

        # Validate publication year if provided
        if publication_year:
            try:
                year = int(publication_year)
                if year < 1000 or year > datetime.now().year + 1:
                    return jsonify({'error': 'Please provide a valid publication year'}), 400
            except (ValueError, TypeError):
                return jsonify({'error': 'Publication year must be a valid number'}), 400

        try:
            total_copies = int(total_copies)
            if total_copies < 1:
                return jsonify({'error': 'Total copies must be at least 1'}), 400

            # Calculate new available copies
            issued_copies = book['total_copies'] - book['available_copies']
            new_available = total_copies - issued_copies

            if new_available < 0:
                return jsonify({'error': 'Total copies cannot be less than issued copies'}), 400

            cursor.execute('''
                UPDATE books
                SET title=?, author=?, isbn=?, publisher=?, publication_year=?, category=?, total_copies=?, available_copies=?
                WHERE id=?
            ''', (title, author, isbn, publisher, publication_year, category, total_copies, new_available, book_id))
            conn.commit()
            audit_logger.info(f"API_BOOK_UPDATED: id={book_id}, title='{title}'")

            return jsonify({
                'success': True,
                'message': 'Book updated successfully',
                'book': {
                    'id': book_id,
                    'title': title,
                    'author': author,
                    'isbn': isbn,
                    'publisher': publisher,
                    'publication_year': publication_year,
                    'category': category,
                    'total_copies': total_copies,
                    'available_copies': new_available
                }
            }), 200
        except sqlite3.IntegrityError:
            return jsonify({'error': 'Book with this ISBN already exists'}), 409
        except ValueError:
            return jsonify({'error': 'Total copies must be a number'}), 400

@app.route('/api/books/<int:book_id>', methods=['DELETE'])
@login_required
@limiter.limit("10 per minute")
def api_delete_book(book_id):
    """API endpoint to delete a book"""
    with get_db() as conn:
        cursor = conn.cursor()

        # Check if book has active transactions
        active_transactions = cursor.execute('''
            SELECT COUNT(*) FROM transactions WHERE book_id = ? AND status = "issued"
        ''', (book_id,)).fetchone()[0]

        if active_transactions > 0:
            return jsonify({'error': 'Cannot delete book with active transactions'}), 409

        # Check if book exists
        book = cursor.execute('SELECT * FROM books WHERE id = ?', (book_id,)).fetchone()
        if not book:
            return jsonify({'error': 'Book not found'}), 404

        cursor.execute('DELETE FROM books WHERE id = ?', (book_id,))
        conn.commit()
        audit_logger.info(f"API_BOOK_DELETED: id={book_id}")

    return jsonify({'success': True, 'message': 'Book deleted successfully'}), 200

@app.route('/api/members')
@login_required
def api_list_members():
    """API endpoint to list all members"""
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 10, type=int)
    search = request.args.get('search', '')
    status = request.args.get('status', '')

    offset = (page - 1) * per_page

    with get_db() as conn:
        cursor = conn.cursor()

        query = 'SELECT * FROM members WHERE 1=1'
        params = []

        if search:
            query += ' AND (name LIKE ? OR email LIKE ? OR phone LIKE ?)'
            params.extend([f'%{search}%', f'%{search}%', f'%{search}%'])

        if status:
            query += ' AND status = ?'
            params.append(status)

        query += ' ORDER BY name LIMIT ? OFFSET ?'
        params.extend([per_page, offset])

        members = cursor.execute(query, params).fetchall()

        # Get total count
        count_query = 'SELECT COUNT(*) FROM members WHERE 1=1'
        count_params = []
        if search:
            count_query += ' AND (name LIKE ? OR email LIKE ? OR phone LIKE ?)'
            count_params.extend([f'%{search}%', f'%{search}%', f'%{search}%'])
        if status:
            count_query += ' AND status = ?'
            count_params.append(status)

        total = cursor.execute(count_query, count_params).fetchone()[0]

        return jsonify({
            'members': [dict(member) for member in members],
            'page': page,
            'per_page': per_page,
            'total': total,
            'pages': (total + per_page - 1) // per_page
        })

@app.route('/api/members/<int:member_id>')
@login_required
def api_get_member(member_id):
    """API endpoint to get a single member"""
    with get_db() as conn:
        cursor = conn.cursor()
        member = cursor.execute('SELECT * FROM members WHERE id = ?', (member_id,)).fetchone()

        if member:
            return jsonify(dict(member))
        return jsonify({'error': 'Member not found'}), 404

@app.route('/api/members/search')
@login_required
def api_search_members():
    """API endpoint to search members"""
    search = request.args.get('q', '')
    with get_db() as conn:
        cursor = conn.cursor()
        members = cursor.execute('''
            SELECT id, name, email
            FROM members
            WHERE (name LIKE ? OR email LIKE ?) AND status = 'active'
            LIMIT 10
        ''', (f'%{search}%', f'%{search}%')).fetchall()

        return jsonify([dict(member) for member in members])

@app.route('/api/members', methods=['POST'])
@login_required
@limiter.limit("30 per minute")
def api_create_member():
    """API endpoint to create a member"""
    data = request.get_json()

    if not data:
        return jsonify({'error': 'Request body required'}), 400

    # Sanitize all inputs
    name = sanitize_string(data.get('name', ''), 100)
    email = sanitize_string(data.get('email', ''), 100).lower()
    phone = sanitize_string(data.get('phone', ''), 20)
    address = sanitize_string(data.get('address', ''), 500)

    # Validation
    if not name or len(name) < 2:
        return jsonify({'error': 'Name is required (minimum 2 characters)'}), 400

    if not validate_email(email):
        return jsonify({'error': 'Please provide a valid email address'}), 400

    if phone and not validate_phone(phone):
        return jsonify({'error': 'Please provide a valid phone number'}), 400

    try:
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO members (name, email, phone, address)
                VALUES (?, ?, ?, ?)
            ''', (name, email, phone, address))
            conn.commit()
            member_id = cursor.lastrowid
            audit_logger.info(f"API_MEMBER_CREATED: id={member_id}, name='{name}', email='{email}'")

        return jsonify({
            'success': True,
            'message': 'Member created successfully',
            'member': {
                'id': member_id,
                'name': name,
                'email': email,
                'phone': phone,
                'address': address,
                'status': 'active'
            }
        }), 201
    except sqlite3.IntegrityError:
        return jsonify({'error': 'Member with this email already exists'}), 409

@app.route('/api/members/<int:member_id>', methods=['PUT'])
@login_required
@limiter.limit("30 per minute")
def api_update_member(member_id):
    """API endpoint to update a member"""
    data = request.get_json()

    if not data:
        return jsonify({'error': 'Request body required'}), 400

    with get_db() as conn:
        cursor = conn.cursor()

        # Check if member exists
        member = cursor.execute('SELECT * FROM members WHERE id = ?', (member_id,)).fetchone()
        if not member:
            return jsonify({'error': 'Member not found'}), 404

        # Sanitize all inputs
        name = sanitize_string(data.get('name', member['name']), 100)
        email = sanitize_string(data.get('email', member['email']), 100).lower()
        phone = sanitize_string(data.get('phone', member['phone'] or ''), 20)
        address = sanitize_string(data.get('address', member['address'] or ''), 500)
        status = data.get('status', member['status'])

        # Validation
        if not name or len(name) < 2:
            return jsonify({'error': 'Name is required (minimum 2 characters)'}), 400

        if not validate_email(email):
            return jsonify({'error': 'Please provide a valid email address'}), 400

        if phone and not validate_phone(phone):
            return jsonify({'error': 'Please provide a valid phone number'}), 400

        if status not in ['active', 'inactive']:
            return jsonify({'error': 'Status must be active or inactive'}), 400

        try:
            cursor.execute('''
                UPDATE members
                SET name=?, email=?, phone=?, address=?, status=?
                WHERE id=?
            ''', (name, email, phone, address, status, member_id))
            conn.commit()
            audit_logger.info(f"API_MEMBER_UPDATED: id={member_id}, name='{name}'")

            return jsonify({
                'success': True,
                'message': 'Member updated successfully',
                'member': {
                    'id': member_id,
                    'name': name,
                    'email': email,
                    'phone': phone,
                    'address': address,
                    'status': status
                }
            }), 200
        except sqlite3.IntegrityError:
            return jsonify({'error': 'Member with this email already exists'}), 409

@app.route('/api/members/<int:member_id>', methods=['DELETE'])
@login_required
@limiter.limit("10 per minute")
def api_delete_member(member_id):
    """API endpoint to delete a member"""
    with get_db() as conn:
        cursor = conn.cursor()

        # Check if member has active transactions
        active_transactions = cursor.execute('''
            SELECT COUNT(*) FROM transactions WHERE member_id = ? AND status = "issued"
        ''', (member_id,)).fetchone()[0]

        if active_transactions > 0:
            return jsonify({'error': 'Cannot delete member with active transactions'}), 409

        # Check if member exists
        member = cursor.execute('SELECT * FROM members WHERE id = ?', (member_id,)).fetchone()
        if not member:
            return jsonify({'error': 'Member not found'}), 404

        cursor.execute('DELETE FROM members WHERE id = ?', (member_id,))
        conn.commit()
        audit_logger.info(f"API_MEMBER_DELETED: id={member_id}")

    return jsonify({'success': True, 'message': 'Member deleted successfully'}), 200

@app.route('/api/transactions')
@login_required
def api_list_transactions():
    """API endpoint to list all transactions"""
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 10, type=int)
    status = request.args.get('status', '')

    offset = (page - 1) * per_page

    with get_db() as conn:
        cursor = conn.cursor()

        query = '''
            SELECT t.*, b.title, b.author, m.name as member_name
            FROM transactions t
            JOIN books b ON t.book_id = b.id
            JOIN members m ON t.member_id = m.id
            WHERE 1=1
        '''
        params = []

        if status:
            query += ' AND t.status = ?'
            params.append(status)

        query += ' ORDER BY t.created_at DESC LIMIT ? OFFSET ?'
        params.extend([per_page, offset])

        transactions = cursor.execute(query, params).fetchall()

        # Get total count
        count_query = 'SELECT COUNT(*) FROM transactions WHERE 1=1'
        count_params = []
        if status:
            count_query += ' AND status = ?'
            count_params.append(status)

        total = cursor.execute(count_query, count_params).fetchone()[0]

        return jsonify({
            'transactions': [dict(t) for t in transactions],
            'page': page,
            'per_page': per_page,
            'total': total,
            'pages': (total + per_page - 1) // per_page
        })

@app.route('/api/transactions/<int:transaction_id>')
@login_required
def api_get_transaction(transaction_id):
    """API endpoint to get a single transaction"""
    with get_db() as conn:
        cursor = conn.cursor()
        transaction = cursor.execute('''
            SELECT t.*, b.title, b.author, m.name as member_name
            FROM transactions t
            JOIN books b ON t.book_id = b.id
            JOIN members m ON t.member_id = m.id
            WHERE t.id = ?
        ''', (transaction_id,)).fetchone()

        if transaction:
            return jsonify(dict(transaction))
        return jsonify({'error': 'Transaction not found'}), 404

@app.route('/api/transactions/issue', methods=['POST'])
@login_required
@limiter.limit("30 per minute")
def api_issue_book():
    """API endpoint to issue a book"""
    data = request.get_json()

    if not data:
        return jsonify({'error': 'Request body required'}), 400

    book_id = data.get('book_id')
    member_id = data.get('member_id')
    issue_date = data.get('issue_date')
    due_days = data.get('due_days', 14)

    if not book_id or not member_id or not issue_date:
        return jsonify({'error': 'book_id, member_id, and issue_date are required'}), 400

    try:
        book_id = int(book_id)
        member_id = int(member_id)
        due_days = int(due_days)

        # Validate and parse date
        issue_date_obj = datetime.strptime(issue_date, '%Y-%m-%d')
        due_date = issue_date_obj + timedelta(days=due_days)

    except ValueError:
        return jsonify({'error': 'Invalid data format'}), 400

    with get_db() as conn:
        cursor = conn.cursor()

        # Check if book exists and is available
        book = cursor.execute('SELECT available_copies FROM books WHERE id = ?', (book_id,)).fetchone()
        if not book:
            return jsonify({'error': 'Book not found'}), 404

        if book['available_copies'] <= 0:
            return jsonify({'error': 'Book is not available'}), 409

        # Check if member exists and is active
        member = cursor.execute('SELECT status FROM members WHERE id = ?', (member_id,)).fetchone()
        if not member:
            return jsonify({'error': 'Member not found'}), 404

        if member['status'] != 'active':
            return jsonify({'error': 'Member is not active'}), 409

        # Issue the book
        cursor.execute('''
            INSERT INTO transactions (book_id, member_id, issue_date, due_date, status)
            VALUES (?, ?, ?, ?, 'issued')
        ''', (book_id, member_id, issue_date, due_date.strftime('%Y-%m-%d')))

        transaction_id = cursor.lastrowid

        # Update available copies
        cursor.execute('''
            UPDATE books SET available_copies = available_copies - 1 WHERE id = ?
        ''', (book_id,))

        conn.commit()
        audit_logger.info(f"API_BOOK_ISSUED: transaction_id={transaction_id}, book_id={book_id}, member_id={member_id}")

    return jsonify({
        'success': True,
        'message': 'Book issued successfully',
        'transaction': {
            'id': transaction_id,
            'book_id': book_id,
            'member_id': member_id,
            'issue_date': issue_date,
            'due_date': due_date.strftime('%Y-%m-%d'),
            'status': 'issued'
        }
    }), 201

@app.route('/api/transactions/<int:transaction_id>/return', methods=['POST'])
@login_required
@limiter.limit("30 per minute")
def api_return_book(transaction_id):
    """API endpoint to return a book"""
    data = request.get_json()

    if not data:
        return jsonify({'error': 'Request body required'}), 400

    return_date = data.get('return_date')

    if not return_date:
        return jsonify({'error': 'return_date is required'}), 400

    try:
        return_date_obj = datetime.strptime(return_date, '%Y-%m-%d')
    except ValueError:
        return jsonify({'error': 'Invalid date format. Use YYYY-MM-DD'}), 400

    with get_db() as conn:
        cursor = conn.cursor()

        # Get transaction details
        transaction = cursor.execute('''
            SELECT * FROM transactions WHERE id = ?
        ''', (transaction_id,)).fetchone()

        if not transaction:
            return jsonify({'error': 'Transaction not found'}), 404

        if transaction['status'] == 'returned':
            return jsonify({'error': 'Book already returned'}), 409

        # Calculate fine if overdue
        due = datetime.strptime(transaction['due_date'], '%Y-%m-%d')
        fine = 0
        if return_date_obj > due:
            overdue_days = (return_date_obj - due).days
            fine = overdue_days * 1.0  # $1 per day

        # Update transaction
        cursor.execute('''
            UPDATE transactions
            SET return_date = ?, status = 'returned', fine_amount = ?
            WHERE id = ?
        ''', (return_date, fine, transaction_id))

        # Update available copies
        cursor.execute('''
            UPDATE books SET available_copies = available_copies + 1 WHERE id = ?
        ''', (transaction['book_id'],))

        conn.commit()
        audit_logger.info(f"API_BOOK_RETURNED: transaction_id={transaction_id}, fine=${fine:.2f}")

    return jsonify({
        'success': True,
        'message': 'Book returned successfully',
        'transaction': {
            'id': transaction_id,
            'book_id': transaction['book_id'],
            'member_id': transaction['member_id'],
            'issue_date': transaction['issue_date'],
            'due_date': transaction['due_date'],
            'return_date': return_date,
            'status': 'returned',
            'fine_amount': fine
        }
    }), 200

# ==================== Chat API (All Users) ====================

@app.route('/api/chat/users')
@login_required
def api_get_chat_users():
    """Get list of all users for chat (excluding current user)"""
    with get_db() as conn:
        cursor = conn.cursor()
        users = cursor.execute('''
            SELECT id, username, email, role
            FROM users
            WHERE id != ?
            ORDER BY username
        ''', (session['user_id'],)).fetchall()

        return jsonify({
            'success': True,
            'users': [dict(user) for user in users]
        })

@app.route('/api/chat/conversations')
@login_required
def api_get_conversations():
    """Get list of conversations for current user with last message preview"""
    current_user_id = session['user_id']

    with get_db() as conn:
        cursor = conn.cursor()

        # Get unique conversation partners with latest message
        conversations = cursor.execute('''
            SELECT
                u.id as user_id,
                u.username,
                u.email,
                u.role,
                m.message as last_message,
                m.created_at as last_message_time,
                m.sender_id as last_sender_id,
                (
                    SELECT COUNT(*)
                    FROM chat_messages
                    WHERE sender_id = u.id
                    AND receiver_id = ?
                    AND is_read = 0
                ) as unread_count
            FROM users u
            INNER JOIN (
                SELECT
                    CASE
                        WHEN sender_id = ? THEN receiver_id
                        ELSE sender_id
                    END as partner_id,
                    message,
                    created_at,
                    sender_id,
                    ROW_NUMBER() OVER (
                        PARTITION BY
                            CASE
                                WHEN sender_id = ? THEN receiver_id
                                ELSE sender_id
                            END
                        ORDER BY created_at DESC
                    ) as rn
                FROM chat_messages
                WHERE sender_id = ? OR receiver_id = ?
            ) m ON u.id = m.partner_id AND m.rn = 1
            ORDER BY m.created_at DESC
        ''', (current_user_id, current_user_id, current_user_id,
              current_user_id, current_user_id)).fetchall()

        return jsonify({
            'success': True,
            'conversations': [dict(conv) for conv in conversations]
        })

@app.route('/api/chat/messages/<int:user_id>')
@login_required
def api_get_messages(user_id):
    """Get all messages between current user and specified user"""
    current_user_id = session['user_id']

    # Optional: get messages after a certain timestamp for polling
    since = request.args.get('since', None)

    with get_db() as conn:
        cursor = conn.cursor()

        # Verify the other user exists
        other_user = cursor.execute(
            'SELECT id, username, role FROM users WHERE id = ?',
            (user_id,)
        ).fetchone()

        if not other_user:
            return jsonify({'error': 'User not found'}), 404

        # Get messages
        if since:
            messages = cursor.execute('''
                SELECT id, sender_id, receiver_id, message, is_read, created_at
                FROM chat_messages
                WHERE ((sender_id = ? AND receiver_id = ?)
                    OR (sender_id = ? AND receiver_id = ?))
                AND created_at > ?
                ORDER BY created_at ASC
            ''', (current_user_id, user_id, user_id, current_user_id, since)).fetchall()
        else:
            messages = cursor.execute('''
                SELECT id, sender_id, receiver_id, message, is_read, created_at
                FROM chat_messages
                WHERE (sender_id = ? AND receiver_id = ?)
                   OR (sender_id = ? AND receiver_id = ?)
                ORDER BY created_at ASC
            ''', (current_user_id, user_id, user_id, current_user_id)).fetchall()

        # Mark received messages as read
        cursor.execute('''
            UPDATE chat_messages
            SET is_read = 1
            WHERE sender_id = ? AND receiver_id = ? AND is_read = 0
        ''', (user_id, current_user_id))
        conn.commit()

        return jsonify({
            'success': True,
            'other_user': dict(other_user),
            'messages': [dict(msg) for msg in messages],
            'current_user_id': current_user_id
        })

@app.route('/api/chat/messages', methods=['POST'])
@login_required
@limiter.limit("60 per minute")
def api_send_message():
    """Send a message to another user"""
    data = request.get_json()

    if not data:
        return jsonify({'error': 'Request body required'}), 400

    receiver_id = data.get('receiver_id')
    message = data.get('message', '').strip()

    if not receiver_id or not message:
        return jsonify({'error': 'receiver_id and message are required'}), 400

    current_user_id = session['user_id']

    with get_db() as conn:
        cursor = conn.cursor()

        # Verify receiver exists
        receiver = cursor.execute(
            'SELECT id FROM users WHERE id = ?',
            (receiver_id,)
        ).fetchone()

        if not receiver:
            return jsonify({'error': 'Receiver not found'}), 404

        # Sanitize message to prevent XSS
        message = sanitize_string(message, 2000)

        if not message:
            return jsonify({'error': 'Message cannot be empty'}), 400

        # Insert message
        cursor.execute('''
            INSERT INTO chat_messages (sender_id, receiver_id, message)
            VALUES (?, ?, ?)
        ''', (current_user_id, receiver_id, message))
        conn.commit()

        message_id = cursor.lastrowid

        # Get the inserted message
        new_message = cursor.execute('''
            SELECT id, sender_id, receiver_id, message, is_read, created_at
            FROM chat_messages WHERE id = ?
        ''', (message_id,)).fetchone()

        audit_logger.info(
            f"CHAT_MESSAGE_SENT: from={current_user_id}, to={receiver_id}"
        )

        return jsonify({
            'success': True,
            'message': dict(new_message)
        }), 201

@app.route('/api/chat/unread-count')
@login_required
def api_get_unread_count():
    """Get total unread message count for current user"""
    current_user_id = session['user_id']

    with get_db() as conn:
        cursor = conn.cursor()
        count = cursor.execute('''
            SELECT COUNT(*) FROM chat_messages
            WHERE receiver_id = ? AND is_read = 0
        ''', (current_user_id,)).fetchone()[0]

        return jsonify({
            'success': True,
            'unread_count': count
        })

# ==================== Ledger API (Admin Only) ====================

@app.route('/api/ledger/fines')
@admin_required
def api_get_fines_ledger():
    """Get ledger of all collected overdue fines (admin only)"""
    with get_db() as conn:
        cursor = conn.cursor()

        # Get all returned transactions with fines
        fines = cursor.execute('''
            SELECT
                t.id as transaction_id,
                t.fine_amount,
                t.return_date,
                t.issue_date,
                t.due_date,
                b.title as book_title,
                b.isbn,
                m.name as member_name,
                m.email as member_email,
                julianday(t.return_date) - julianday(t.due_date) as days_overdue
            FROM transactions t
            JOIN books b ON t.book_id = b.id
            JOIN members m ON t.member_id = m.id
            WHERE t.status = 'returned' AND t.fine_amount > 0
            ORDER BY t.return_date DESC
        ''').fetchall()

        # Calculate totals
        total_fines = cursor.execute('''
            SELECT COALESCE(SUM(fine_amount), 0) FROM transactions
            WHERE status = 'returned' AND fine_amount > 0
        ''').fetchone()[0]

        total_count = len(fines)

        return jsonify({
            'success': True,
            'fines': [dict(fine) for fine in fines],
            'total_fines': total_fines,
            'total_count': total_count
        })

@app.route('/api/ledger/summary')
@admin_required
def api_get_fines_summary():
    """Get summary of fines by period (admin only)"""
    with get_db() as conn:
        cursor = conn.cursor()

        # Today's fines
        today_fines = cursor.execute('''
            SELECT COALESCE(SUM(fine_amount), 0) FROM transactions
            WHERE status = 'returned' AND fine_amount > 0
            AND date(return_date) = date('now')
        ''').fetchone()[0]

        # This week's fines
        week_fines = cursor.execute('''
            SELECT COALESCE(SUM(fine_amount), 0) FROM transactions
            WHERE status = 'returned' AND fine_amount > 0
            AND return_date >= date('now', '-7 days')
        ''').fetchone()[0]

        # This month's fines
        month_fines = cursor.execute('''
            SELECT COALESCE(SUM(fine_amount), 0) FROM transactions
            WHERE status = 'returned' AND fine_amount > 0
            AND strftime('%Y-%m', return_date) = strftime('%Y-%m', 'now')
        ''').fetchone()[0]

        # Total all-time fines
        total_fines = cursor.execute('''
            SELECT COALESCE(SUM(fine_amount), 0) FROM transactions
            WHERE status = 'returned' AND fine_amount > 0
        ''').fetchone()[0]

        # Currently overdue books (pending fines)
        pending_fines = cursor.execute('''
            SELECT COUNT(*) FROM transactions
            WHERE status = 'issued' AND due_date < date('now')
        ''').fetchone()[0]

        return jsonify({
            'success': True,
            'today_fines': today_fines,
            'week_fines': week_fines,
            'month_fines': month_fines,
            'total_fines': total_fines,
            'pending_overdue_count': pending_fines
        })

if __name__ == '__main__':
    logger.info("Starting Library Management System...")
    init_db()

    # Use environment variable for debug mode, default to False for security
    debug_mode = os.environ.get('FLASK_DEBUG', 'false').lower() == 'true'

    if debug_mode:
        logger.warning("Running in DEBUG mode - do not use in production!")
    else:
        logger.info("Running in production mode")

    logger.info("Server starting on http://0.0.0.0:5000")
    app.run(debug=debug_mode, host='0.0.0.0', port=5000)
