# API Documentation

API endpoints for the Library Management System.

## Base URL

**Local Development:** `http://localhost:5000`
**Docker:** `http://localhost:3000`

## Authentication

All routes except `/login`, `/register`, and `/forgot-password` require authentication via session cookies.

### Login
```http
POST /login
Content-Type: application/x-www-form-urlencoded

username=admin&password=admin123
```

**Response:** Redirects to dashboard on success, returns to login page with error on failure.

### Logout
```http
GET /logout
```

**Response:** Redirects to login page, clears session.

### Register New User
```http
POST /register
Content-Type: application/x-www-form-urlencoded

username=newuser&email=user@example.com&password=password123&confirm_password=password123
```

**Validation:**
- Username: 3-20 characters, alphanumeric and underscore
- Password: minimum 6 characters
- Email: valid email format, unique

### Change Password (Authenticated)
```http
POST /change-password
Content-Type: application/x-www-form-urlencoded

current_password=oldpass&new_password=newpass&confirm_password=newpass
```

### Forgot Password (Request Reset Link)
```http
POST /forgot-password
Content-Type: application/x-www-form-urlencoded

email=admin@library.com
```
A password reset link will be sent to the email if the account exists.

### Reset Password (Use Token)
```http
GET /reset-password/<token>
POST /reset-password/<token>
Content-Type: application/x-www-form-urlencoded

new_password=newpass&confirm_password=newpass
```

---

## JSON API Endpoints

**For complete mobile API documentation with all 24 endpoints, see [MOBILE_API.md](MOBILE_API.md)**

### Quick Reference - All API Endpoints

#### Authentication APIs (7 endpoints)
- POST `/api/auth/login` - Login with JSON
- POST `/api/auth/logout` - Logout with JSON
- POST `/api/auth/register` - Register with JSON
- GET `/api/auth/me` - Get current user
- POST `/api/auth/change-password` - Change password (authenticated)
- POST `/api/auth/forgot-password` - Request password reset token
- POST `/api/auth/reset-password` - Reset password with token

#### User Management APIs (5 endpoints, Admin Only)
- GET `/api/admin/users` - List all users
- GET `/api/admin/users/<id>` - Get single user
- POST `/api/admin/users` - Create user
- PUT `/api/admin/users/<id>` - Update user
- DELETE `/api/admin/users/<id>` - Delete user

#### Dashboard API (1 endpoint)
- GET `/api/dashboard` - Get library statistics

#### Books APIs (7 endpoints)
- GET `/api/books` - List books (with pagination)
- GET `/api/books/<id>` - Get single book
- GET `/api/books/search?q={query}` - Quick search books
- POST `/api/books` - Create book
- PUT `/api/books/<id>` - Update book
- DELETE `/api/books/<id>` - Delete book

#### Members APIs (7 endpoints)
- GET `/api/members` - List members (with pagination)
- GET `/api/members/<id>` - Get single member
- GET `/api/members/search?q={query}` - Quick search members
- POST `/api/members` - Create member
- PUT `/api/members/<id>` - Update member
- DELETE `/api/members/<id>` - Delete member

#### Transactions APIs (5 endpoints)
- GET `/api/transactions` - List transactions (with pagination)
- GET `/api/transactions/<id>` - Get single transaction
- POST `/api/transactions/issue` - Issue book
- POST `/api/transactions/<id>/return` - Return book

---

### Legacy Search Endpoints

#### Search Books
Search for available books by title, author, or ISBN.

```http
GET /api/books/search?q={query}
```

**Parameters:**
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| q | string | Yes | Search query |

**Example Request:**
```bash
curl "http://localhost:5000/api/books/search?q=python"
```

**Example Response:**
```json
[
    {
        "id": 1,
        "title": "Python Programming",
        "author": "John Doe",
        "isbn": "978-0-123456-78-9",
        "available_copies": 3
    }
]
```

**Notes:**
- Returns only books with `available_copies > 0`
- Maximum 10 results
- Case-insensitive search

---

### Search Members
Search for active members by name or email.

```http
GET /api/members/search?q={query}
```

**Parameters:**
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| q | string | Yes | Search query |

**Example Request:**
```bash
curl "http://localhost:5000/api/members/search?q=john"
```

**Example Response:**
```json
[
    {
        "id": 1,
        "name": "John Doe",
        "email": "john.doe@example.com"
    }
]
```

**Notes:**
- Returns only members with `status = 'active'`
- Maximum 10 results
- Case-insensitive search

---

## Web Routes Reference

### Dashboard
| Method | Route | Description |
|--------|-------|-------------|
| GET | `/` | Dashboard with statistics |

### Books Management
| Method | Route | Description |
|--------|-------|-------------|
| GET | `/books` | List all books |
| GET | `/books?search=query` | Search books |
| GET | `/books?category=Fiction` | Filter by category |
| GET | `/books/add` | Add book form |
| POST | `/books/add` | Create book |
| GET | `/books/edit/<id>` | Edit book form |
| POST | `/books/edit/<id>` | Update book |
| POST | `/books/delete/<id>` | Delete book |

**Add/Edit Book Form Fields:**
```
title (required)
author (required)
isbn (required, unique)
publisher (optional)
publication_year (optional)
category (optional)
total_copies (required, default: 1)
```

### Members Management
| Method | Route | Description |
|--------|-------|-------------|
| GET | `/members` | List all members |
| GET | `/members?search=query` | Search members |
| GET | `/members?status=active` | Filter by status |
| GET | `/members/add` | Add member form |
| POST | `/members/add` | Create member |
| GET | `/members/edit/<id>` | Edit member form |
| POST | `/members/edit/<id>` | Update member |
| POST | `/members/delete/<id>` | Delete member |

**Add/Edit Member Form Fields:**
```
name (required)
email (required, unique)
phone (optional)
address (optional)
status (edit only: active/inactive)
```

### Transactions Management
| Method | Route | Description |
|--------|-------|-------------|
| GET | `/transactions` | List all transactions |
| GET | `/transactions?status=issued` | Filter by status |
| GET | `/transactions/issue` | Issue book form |
| POST | `/transactions/issue` | Issue a book |
| POST | `/transactions/return/<id>` | Return a book |

**Issue Book Form Fields:**
```
book_id (required)
member_id (required)
issue_date (required)
due_days (required, default: 14)
```

**Return Book Form Fields:**
```
return_date (required)
```

**Fine Calculation:**
- If `return_date > due_date`: fine = overdue_days * $1.00

### User Management (Admin Only)
| Method | Route | Description |
|--------|-------|-------------|
| GET | `/admin/users` | List all users |
| GET | `/admin/users?search=query` | Search users |
| GET | `/admin/users?role=admin` | Filter by role |
| GET | `/admin/users/add` | Add user form |
| POST | `/admin/users/add` | Create user |
| GET | `/admin/users/edit/<id>` | Edit user form |
| POST | `/admin/users/edit/<id>` | Update user |
| POST | `/admin/users/delete/<id>` | Delete user |

**Add/Edit User Form Fields:**
```
username (required, unique, 3-20 alphanumeric or underscore)
email (required, unique)
password (required for add, optional for edit)
confirm_password (must match password)
role (admin or staff)
```

**Security Notes:**
- Admin cannot delete their own account
- Admin cannot change their own role
- Password change invalidates all API tokens

---

## Database Schema

### Users Table
```sql
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    email TEXT UNIQUE NOT NULL,
    role TEXT DEFAULT 'staff',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
)
```

### Books Table
```sql
CREATE TABLE books (
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
```

### Members Table
```sql
CREATE TABLE members (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email TEXT UNIQUE NOT NULL,
    phone TEXT,
    address TEXT,
    membership_date DATE DEFAULT CURRENT_DATE,
    status TEXT DEFAULT 'active',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
)
```

### Transactions Table
```sql
CREATE TABLE transactions (
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
```

---

## Code Examples

### Python (requests)
```python
import requests

# Create session for authentication
session = requests.Session()

# Login
login_data = {'username': 'admin', 'password': 'admin123'}
session.post('http://localhost:5000/login', data=login_data)

# Search books
response = session.get('http://localhost:5000/api/books/search',
                       params={'q': 'python'})
books = response.json()
print(books)

# Search members
response = session.get('http://localhost:5000/api/members/search',
                       params={'q': 'john'})
members = response.json()
print(members)
```

### JavaScript (fetch)
```javascript
// Search for books (requires authenticated session)
fetch('/api/books/search?q=python')
    .then(response => response.json())
    .then(books => console.log(books))
    .catch(error => console.error('Error:', error));

// Search for members
fetch('/api/members/search?q=john')
    .then(response => response.json())
    .then(members => console.log(members))
    .catch(error => console.error('Error:', error));
```

### cURL
```bash
# Login and save cookies
curl -c cookies.txt -d "username=admin&password=admin123" \
     http://localhost:5000/login

# Search books with session
curl -b cookies.txt "http://localhost:5000/api/books/search?q=python"

# Search members
curl -b cookies.txt "http://localhost:5000/api/members/search?q=john"
```

---

## Error Handling

### Flash Messages
The application uses Flask flash messages for user feedback:

| Category | Description |
|----------|-------------|
| success | Operation completed successfully |
| error | Operation failed |
| warning | Warning (e.g., overdue fine) |

### Common Errors

| Error | Cause | Solution |
|-------|-------|----------|
| Redirect to login | Session expired | Login again |
| "ISBN already exists" | Duplicate ISBN | Use unique ISBN |
| "Email already exists" | Duplicate email | Use unique email |
| "Cannot delete" | Active transactions | Return books first |
| "Book not available" | No copies available | Wait for return |

---

## Extending the API

### Adding a New Endpoint
```python
@app.route('/api/books/<int:book_id>')
@login_required
def get_book(book_id):
    with get_db() as conn:
        cursor = conn.cursor()
        book = cursor.execute(
            'SELECT * FROM books WHERE id = ?',
            (book_id,)
        ).fetchone()

        if book:
            return jsonify(dict(book))
        return jsonify({'error': 'Book not found'}), 404
```

### Adding Pagination
```python
@app.route('/api/books')
@login_required
def list_books():
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 10, type=int)
    offset = (page - 1) * per_page

    with get_db() as conn:
        cursor = conn.cursor()
        books = cursor.execute(
            'SELECT * FROM books LIMIT ? OFFSET ?',
            (per_page, offset)
        ).fetchall()

        total = cursor.execute('SELECT COUNT(*) FROM books').fetchone()[0]

        return jsonify({
            'books': [dict(book) for book in books],
            'page': page,
            'per_page': per_page,
            'total': total,
            'pages': (total + per_page - 1) // per_page
        })
```

---

## Security Notes

For production deployment:

1. **Use HTTPS** - Enable SSL/TLS
2. **Change Secret Key** - Generate secure random key
3. **Rate Limiting** - Implement request throttling
4. **Input Validation** - Sanitize all user inputs
5. **CORS** - Configure allowed origins
6. **Session Security** - Set secure cookie flags

---

**API Version:** 1.2
**Last Updated:** January 25, 2026
