# 📡 API Documentation

API endpoints for the Library Management System.

## Base URL
```
http://localhost:5000
```

## Authentication
Currently, no authentication is required. For production, implement JWT or session-based authentication.

## API Endpoints

### Books API

#### Search Books
Search for available books by title, author, or ISBN.

**Endpoint:** `GET /api/books/search`

**Parameters:**
- `q` (required): Search query string

**Example Request:**
```http
GET /api/books/search?q=python
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
    },
    {
        "id": 2,
        "title": "Learning Python",
        "author": "Jane Smith",
        "isbn": "978-0-987654-32-1",
        "available_copies": 1
    }
]
```

**Status Codes:**
- `200 OK`: Success
- `400 Bad Request`: Missing query parameter

**Notes:**
- Only returns books with `available_copies > 0`
- Maximum 10 results returned
- Case-insensitive search

---

### Members API

#### Search Members
Search for active members by name or email.

**Endpoint:** `GET /api/members/search`

**Parameters:**
- `q` (required): Search query string

**Example Request:**
```http
GET /api/members/search?q=john
```

**Example Response:**
```json
[
    {
        "id": 1,
        "name": "John Doe",
        "email": "john.doe@example.com"
    },
    {
        "id": 5,
        "name": "Johnny Smith",
        "email": "johnny@example.com"
    }
]
```

**Status Codes:**
- `200 OK`: Success
- `400 Bad Request`: Missing query parameter

**Notes:**
- Only returns members with `status = 'active'`
- Maximum 10 results returned
- Case-insensitive search

---

## Web Routes (For Reference)

### Dashboard
```
GET /
```
Returns dashboard with library statistics.

---

### Books Management

#### List Books
```
GET /books?search=<query>&category=<category>
```
**Query Parameters:**
- `search`: Search by title, author, or ISBN
- `category`: Filter by book category

#### Add Book
```
GET  /books/add      # Show form
POST /books/add      # Submit form
```
**Form Fields:**
- `title` (required)
- `author` (required)
- `isbn` (required, unique)
- `publisher` (optional)
- `publication_year` (optional)
- `category` (optional)
- `total_copies` (required, default: 1)

#### Edit Book
```
GET  /books/edit/<int:book_id>
POST /books/edit/<int:book_id>
```

#### Delete Book
```
POST /books/delete/<int:book_id>
```
**Note:** Cannot delete books with active transactions.

---

### Members Management

#### List Members
```
GET /members?search=<query>&status=<status>
```
**Query Parameters:**
- `search`: Search by name, email, or phone
- `status`: Filter by member status (active/inactive)

#### Add Member
```
GET  /members/add
POST /members/add
```
**Form Fields:**
- `name` (required)
- `email` (required, unique)
- `phone` (optional)
- `address` (optional)

#### Edit Member
```
GET  /members/edit/<int:member_id>
POST /members/edit/<int:member_id>
```

#### Delete Member
```
POST /members/delete/<int:member_id>
```
**Note:** Cannot delete members with active transactions.

---

### Transactions Management

#### List Transactions
```
GET /transactions?status=<status>
```
**Query Parameters:**
- `status`: Filter by transaction status (issued/returned)

#### Issue Book
```
GET  /transactions/issue
POST /transactions/issue
```
**Form Fields:**
- `book_id` (required)
- `member_id` (required)
- `issue_date` (required)
- `due_days` (required, default: 14)

**Validation:**
- Book must have available copies
- Member must be active
- Due date calculated automatically

#### Return Book
```
POST /transactions/return/<int:transaction_id>
```
**Form Fields:**
- `return_date` (required)

**Fine Calculation:**
- Overdue days = return_date - due_date
- Fine = overdue_days * $1.00 per day

---

## Error Handling

### Success Response
```json
{
    "success": true,
    "message": "Operation completed successfully",
    "data": {}
}
```

### Error Response
```json
{
    "success": false,
    "error": "Error message",
    "code": "ERROR_CODE"
}
```

### Common Error Codes
- `BOOK_NOT_AVAILABLE`: Book has no available copies
- `DUPLICATE_ISBN`: Book with ISBN already exists
- `DUPLICATE_EMAIL`: Member with email already exists
- `ACTIVE_TRANSACTIONS`: Cannot delete with active transactions
- `NOT_FOUND`: Resource not found
- `VALIDATION_ERROR`: Invalid input data

---

## Database Schema Reference

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

## Usage Examples

### Python (requests)
```python
import requests

# Search for books
response = requests.get('http://localhost:5000/api/books/search', 
                       params={'q': 'python'})
books = response.json()

# Search for members
response = requests.get('http://localhost:5000/api/members/search',
                       params={'q': 'john'})
members = response.json()
```

### JavaScript (fetch)
```javascript
// Search for books
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
# Search for books
curl "http://localhost:5000/api/books/search?q=python"

# Search for members
curl "http://localhost:5000/api/members/search?q=john"
```

---

## Rate Limiting
Currently, no rate limiting is implemented. For production:
- Implement rate limiting (e.g., 100 requests per minute)
- Use Flask-Limiter or similar middleware
- Return `429 Too Many Requests` when limit exceeded

## Security Considerations

### For Production Deployment:

1. **Authentication**
   - Implement JWT tokens
   - Use OAuth 2.0
   - Session-based authentication

2. **Authorization**
   - Role-based access control (Admin, Librarian, Member)
   - Permission checks for sensitive operations

3. **Input Validation**
   - Sanitize all inputs
   - Validate data types
   - Check for SQL injection

4. **HTTPS**
   - Use SSL/TLS certificates
   - Redirect HTTP to HTTPS
   - Secure cookies

5. **CORS**
   - Configure allowed origins
   - Restrict methods
   - Set proper headers

## Extending the API

### Adding New Endpoints

Example: Get book by ID
```python
@app.route('/api/books/<int:book_id>')
def get_book(book_id):
    with get_db() as conn:
        cursor = conn.cursor()
        book = cursor.execute(
            'SELECT * FROM books WHERE id = ?', 
            (book_id,)
        ).fetchone()
        
        if book:
            return jsonify(dict(book))
        else:
            return jsonify({'error': 'Book not found'}), 404
```

### Adding Pagination

```python
@app.route('/api/books')
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

## Testing the API

### Using Postman

1. Import collection
2. Set base URL variable
3. Test each endpoint
4. Validate responses

### Using Python unittest

```python
import unittest
import json
from app import app

class APITestCase(unittest.TestCase):
    def setUp(self):
        self.app = app.test_client()
        
    def test_search_books(self):
        response = self.app.get('/api/books/search?q=python')
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertIsInstance(data, list)
        
if __name__ == '__main__':
    unittest.main()
```

---

## Support & Questions

For API support:
1. Check this documentation
2. Review the source code in `app.py`
3. Test with sample data
4. Submit issues on GitHub

---

**API Version:** 1.0  
**Last Updated:** January 15, 2026
