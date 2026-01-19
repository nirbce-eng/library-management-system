"""
Library Management System
A comprehensive web application for managing library operations
"""

from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
import sqlite3
from datetime import datetime, timedelta
from contextlib import contextmanager
import os

app = Flask(__name__)
app.secret_key = 'your-secret-key-change-in-production'

DATABASE = 'library.db'

@contextmanager
def get_db():
    """Context manager for database connections"""
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
    finally:
        conn.close()

def init_db():
    """Initialize the database with required tables"""
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
        
        conn.commit()

# Routes
@app.route('/')
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
            flash('Book added successfully!', 'success')
            return redirect(url_for('books'))
        except sqlite3.IntegrityError:
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
                flash('Book updated successfully!', 'success')
                return redirect(url_for('books'))
            except sqlite3.IntegrityError:
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
            flash('Cannot delete book with active transactions!', 'error')
        else:
            cursor.execute('DELETE FROM books WHERE id = ?', (book_id,))
            conn.commit()
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
            flash('Member added successfully!', 'success')
            return redirect(url_for('members'))
        except sqlite3.IntegrityError:
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
                flash('Member updated successfully!', 'success')
                return redirect(url_for('members'))
            except sqlite3.IntegrityError:
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
            flash('Cannot delete member with active transactions!', 'error')
        else:
            cursor.execute('DELETE FROM members WHERE id = ?', (member_id,))
            conn.commit()
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
                flash('Book issued successfully!', 'success')
                return redirect(url_for('transactions'))
            else:
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
            
            if fine > 0:
                flash(f'Book returned successfully! Fine amount: ${fine:.2f}', 'warning')
            else:
                flash('Book returned successfully!', 'success')
        else:
            flash('Transaction not found!', 'error')
    
    return redirect(url_for('transactions'))

# API endpoints
@app.route('/api/books/search')
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

@app.route('/api/members/search')
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

if __name__ == '__main__':
    init_db()
    app.run(debug=True, host='0.0.0.0', port=5000)
