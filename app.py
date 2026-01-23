"""
Library Management System
A comprehensive web application for managing library operations
"""

from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, g, session
import sqlite3
from datetime import datetime, timedelta
from contextlib import contextmanager
import os
import logging
from logging.handlers import RotatingFileHandler
import time
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = 'your-secret-key-change-in-production'

DATABASE = 'library.db'
LOG_DIR = 'logs'

# Ensure logs directory exists
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

        # Create default admin user if not exists
        cursor.execute('SELECT COUNT(*) FROM users WHERE username = ?', ('admin',))
        if cursor.fetchone()[0] == 0:
            cursor.execute('''
                INSERT INTO users (username, password_hash, email, role)
                VALUES (?, ?, ?, ?)
            ''', ('admin', generate_password_hash('admin123'), 'admin@library.com', 'admin'))
            logger.info("Default admin user created (username: admin, password: admin123)")

        conn.commit()
        logger.info("Database initialization complete")

# Authentication decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'error')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# Authentication Routes
@app.route('/login', methods=['GET', 'POST'])
def login():
    """User login"""
    if 'user_id' in session:
        return redirect(url_for('index'))

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        with get_db() as conn:
            cursor = conn.cursor()
            user = cursor.execute(
                'SELECT * FROM users WHERE username = ?', (username,)
            ).fetchone()

            if user and check_password_hash(user['password_hash'], password):
                session['user_id'] = user['id']
                session['username'] = user['username']
                session['role'] = user['role']
                audit_logger.info(f"USER_LOGIN: username='{username}'")
                flash('Welcome back!', 'success')
                return redirect(url_for('index'))
            else:
                logger.warning(f"Failed login attempt for username: {username}")
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
def register():
    """User registration"""
    if 'user_id' in session:
        return redirect(url_for('index'))

    if request.method == 'POST':
        username = request.form['username'].strip()
        email = request.form['email'].strip().lower()
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        # Validation
        if len(username) < 3 or len(username) > 20:
            flash('Username must be between 3 and 20 characters.', 'error')
            return render_template('register.html')

        if password != confirm_password:
            flash('Passwords do not match.', 'error')
            return render_template('register.html')

        if len(password) < 6:
            flash('Password must be at least 6 characters.', 'error')
            return render_template('register.html')

        try:
            with get_db() as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT INTO users (username, password_hash, email, role)
                    VALUES (?, ?, ?, ?)
                ''', (username, generate_password_hash(password), email, 'staff'))
                conn.commit()
                audit_logger.info(f"USER_REGISTERED: username='{username}', email='{email}'")
            flash('Account created successfully! Please sign in.', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError as e:
            if 'username' in str(e).lower():
                flash('Username already exists.', 'error')
            else:
                flash('Email already exists.', 'error')
            logger.warning(f"Registration failed for username={username}, email={email}: {str(e)}")

    return render_template('register.html')

@app.route('/change-password', methods=['GET', 'POST'])
@login_required
def change_password():
    """Change user password"""
    if request.method == 'POST':
        current_password = request.form['current_password']
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']

        if new_password != confirm_password:
            flash('New passwords do not match.', 'error')
            return render_template('change_password.html')

        if len(new_password) < 6:
            flash('New password must be at least 6 characters.', 'error')
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
                conn.commit()
                audit_logger.info(f"PASSWORD_CHANGED: username='{session['username']}'")
                flash('Password updated successfully!', 'success')
                return redirect(url_for('index'))
            else:
                logger.warning(f"Failed password change attempt for user: {session['username']}")
                flash('Current password is incorrect.', 'error')

    return render_template('change_password.html')

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    """Reset password using username and email verification"""
    if 'user_id' in session:
        return redirect(url_for('index'))

    if request.method == 'POST':
        username = request.form['username'].strip()
        email = request.form['email'].strip().lower()
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']

        if new_password != confirm_password:
            flash('Passwords do not match.', 'error')
            return render_template('forgot_password.html')

        if len(new_password) < 6:
            flash('Password must be at least 6 characters.', 'error')
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
                conn.commit()
                audit_logger.info(f"PASSWORD_RESET: username='{username}'")
                flash('Password reset successfully! Please sign in with your new password.', 'success')
                return redirect(url_for('login'))
            else:
                logger.warning(f"Failed password reset attempt for username={username}, email={email}")
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
        title = request.form['title']
        author = request.form['author']
        isbn = request.form['isbn']
        publisher = request.form.get('publisher', '')
        publication_year = request.form.get('publication_year', None)
        category = request.form.get('category', '')
        total_copies = int(request.form.get('total_copies', 1))
        
        try:
            with get_db() as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT INTO books (title, author, isbn, publisher, publication_year, category, total_copies, available_copies)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ''', (title, author, isbn, publisher, publication_year, category, total_copies, total_copies))
                conn.commit()
                audit_logger.info(f"BOOK_CREATED: title='{title}', isbn='{isbn}', author='{author}'")
            flash('Book added successfully!', 'success')
            return redirect(url_for('books'))
        except sqlite3.IntegrityError:
            logger.warning(f"Failed to add book - ISBN already exists: {isbn}")
            flash('Book with this ISBN already exists!', 'error')
    
    return render_template('add_book.html')

@app.route('/books/edit/<int:book_id>', methods=['GET', 'POST'])
def edit_book(book_id):
    """Edit a book"""
    with get_db() as conn:
        cursor = conn.cursor()
        
        if request.method == 'POST':
            title = request.form['title']
            author = request.form['author']
            isbn = request.form['isbn']
            publisher = request.form.get('publisher', '')
            publication_year = request.form.get('publication_year', None)
            category = request.form.get('category', '')
            total_copies = int(request.form.get('total_copies', 1))
            
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
def add_member():
    """Add a new member"""
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        phone = request.form.get('phone', '')
        address = request.form.get('address', '')
        
        try:
            with get_db() as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT INTO members (name, email, phone, address)
                    VALUES (?, ?, ?, ?)
                ''', (name, email, phone, address))
                conn.commit()
                audit_logger.info(f"MEMBER_CREATED: name='{name}', email='{email}'")
            flash('Member added successfully!', 'success')
            return redirect(url_for('members'))
        except sqlite3.IntegrityError:
            logger.warning(f"Failed to add member - email already exists: {email}")
            flash('Member with this email already exists!', 'error')
    
    return render_template('add_member.html')

@app.route('/members/edit/<int:member_id>', methods=['GET', 'POST'])
def edit_member(member_id):
    """Edit a member"""
    with get_db() as conn:
        cursor = conn.cursor()
        
        if request.method == 'POST':
            name = request.form['name']
            email = request.form['email']
            phone = request.form.get('phone', '')
            address = request.form.get('address', '')
            status = request.form.get('status', 'active')
            
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
def issue_book():
    """Issue a book to a member"""
    if request.method == 'POST':
        book_id = int(request.form['book_id'])
        member_id = int(request.form['member_id'])
        issue_date = request.form['issue_date']
        due_days = int(request.form.get('due_days', 14))
        
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
def return_book(transaction_id):
    """Return a book"""
    return_date = request.form['return_date']
    
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

# API endpoints
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

if __name__ == '__main__':
    logger.info("Starting Library Management System...")
    init_db()
    logger.info("Server starting on http://0.0.0.0:5000")
    app.run(debug=True, host='0.0.0.0', port=5000)
