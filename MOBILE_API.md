# Mobile App API Documentation

Complete REST API endpoints for mobile application integration.

**Base URL:** `http://localhost:3000`

## Authentication

All endpoints except `/api/auth/login` and `/api/auth/register` require authentication.

### Token-Based Authentication (Recommended for Mobile)

After login, include the token in the `Authorization` header for all subsequent requests:

```http
Authorization: Bearer <your_api_token>
```

### Login
```http
POST /api/auth/login
Content-Type: application/json

{
  "username": "admin",
  "password": "admin123"
}
```

**Response (200):**
```json
{
  "success": true,
  "message": "Login successful",
  "token": "a1b2c3d4e5f6...",
  "user": {
    "id": 1,
    "username": "admin",
    "email": "admin@library.com",
    "role": "admin"
  }
}
```

### Logout
```http
POST /api/auth/logout
```

**Response (200):**
```json
{
  "success": true,
  "message": "Logout successful"
}
```

### Register
```http
POST /api/auth/register
Content-Type: application/json

{
  "username": "newuser",
  "email": "user@example.com",
  "password": "password123"
}
```

**Response (201):**
```json
{
  "success": true,
  "message": "Account created successfully",
  "user": {
    "username": "newuser",
    "email": "user@example.com",
    "role": "staff"
  }
}
```

### Get Current User
```http
GET /api/auth/me
```

**Response (200):**
```json
{
  "id": 1,
  "username": "admin",
  "email": "admin@library.com",
  "role": "admin",
  "created_at": "2026-01-21 12:00:00"
}
```

---

## Dashboard

### Get Statistics
```http
GET /api/dashboard
```

**Response (200):**
```json
{
  "total_books": 150,
  "total_members": 45,
  "issued_books": 12,
  "overdue_books": 3
}
```

---

## Books

### List Books
```http
GET /api/books?page=1&per_page=10&search=python&category=Programming
```

**Response (200):**
```json
{
  "books": [
    {
      "id": 1,
      "title": "Python Programming",
      "author": "John Doe",
      "isbn": "978-0-123456-78-9",
      "publisher": "Tech Books",
      "publication_year": 2023,
      "category": "Programming",
      "total_copies": 5,
      "available_copies": 3,
      "created_at": "2026-01-20 10:00:00"
    }
  ],
  "page": 1,
  "per_page": 10,
  "total": 1,
  "pages": 1
}
```

### Get Single Book
```http
GET /api/books/1
```

**Response (200):**
```json
{
  "id": 1,
  "title": "Python Programming",
  "author": "John Doe",
  "isbn": "978-0-123456-78-9",
  "publisher": "Tech Books",
  "publication_year": 2023,
  "category": "Programming",
  "total_copies": 5,
  "available_copies": 3,
  "created_at": "2026-01-20 10:00:00"
}
```

### Search Books
```http
GET /api/books/search?q=python
```

**Response (200):**
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

### Create Book
```http
POST /api/books
Content-Type: application/json

{
  "title": "New Book",
  "author": "Jane Smith",
  "isbn": "978-0-987654-32-1",
  "publisher": "ABC Publishing",
  "publication_year": 2024,
  "category": "Fiction",
  "total_copies": 3
}
```

**Response (201):**
```json
{
  "success": true,
  "message": "Book created successfully",
  "book": {
    "id": 2,
    "title": "New Book",
    "author": "Jane Smith",
    "isbn": "978-0-987654-32-1",
    "publisher": "ABC Publishing",
    "publication_year": 2024,
    "category": "Fiction",
    "total_copies": 3,
    "available_copies": 3
  }
}
```

### Update Book
```http
PUT /api/books/2
Content-Type: application/json

{
  "title": "Updated Book Title",
  "total_copies": 5
}
```

**Response (200):**
```json
{
  "success": true,
  "message": "Book updated successfully",
  "book": {
    "id": 2,
    "title": "Updated Book Title",
    "author": "Jane Smith",
    "isbn": "978-0-987654-32-1",
    "publisher": "ABC Publishing",
    "publication_year": 2024,
    "category": "Fiction",
    "total_copies": 5,
    "available_copies": 5
  }
}
```

### Delete Book
```http
DELETE /api/books/2
```

**Response (200):**
```json
{
  "success": true,
  "message": "Book deleted successfully"
}
```

---

## Members

### List Members
```http
GET /api/members?page=1&per_page=10&search=john&status=active
```

**Response (200):**
```json
{
  "members": [
    {
      "id": 1,
      "name": "John Doe",
      "email": "john@example.com",
      "phone": "123-456-7890",
      "address": "123 Main St",
      "membership_date": "2026-01-15",
      "status": "active",
      "created_at": "2026-01-15 09:00:00"
    }
  ],
  "page": 1,
  "per_page": 10,
  "total": 1,
  "pages": 1
}
```

### Get Single Member
```http
GET /api/members/1
```

**Response (200):**
```json
{
  "id": 1,
  "name": "John Doe",
  "email": "john@example.com",
  "phone": "123-456-7890",
  "address": "123 Main St",
  "membership_date": "2026-01-15",
  "status": "active",
  "created_at": "2026-01-15 09:00:00"
}
```

### Search Members
```http
GET /api/members/search?q=john
```

**Response (200):**
```json
[
  {
    "id": 1,
    "name": "John Doe",
    "email": "john@example.com"
  }
]
```

### Create Member
```http
POST /api/members
Content-Type: application/json

{
  "name": "Jane Doe",
  "email": "jane@example.com",
  "phone": "098-765-4321",
  "address": "456 Oak Ave"
}
```

**Response (201):**
```json
{
  "success": true,
  "message": "Member created successfully",
  "member": {
    "id": 2,
    "name": "Jane Doe",
    "email": "jane@example.com",
    "phone": "098-765-4321",
    "address": "456 Oak Ave",
    "status": "active"
  }
}
```

### Update Member
```http
PUT /api/members/2
Content-Type: application/json

{
  "name": "Jane Smith",
  "status": "inactive"
}
```

**Response (200):**
```json
{
  "success": true,
  "message": "Member updated successfully",
  "member": {
    "id": 2,
    "name": "Jane Smith",
    "email": "jane@example.com",
    "phone": "098-765-4321",
    "address": "456 Oak Ave",
    "status": "inactive"
  }
}
```

### Delete Member
```http
DELETE /api/members/2
```

**Response (200):**
```json
{
  "success": true,
  "message": "Member deleted successfully"
}
```

---

## Transactions

### List Transactions
```http
GET /api/transactions?page=1&per_page=10&status=issued
```

**Response (200):**
```json
{
  "transactions": [
    {
      "id": 1,
      "book_id": 1,
      "member_id": 1,
      "issue_date": "2026-01-20",
      "due_date": "2026-02-03",
      "return_date": null,
      "status": "issued",
      "fine_amount": 0,
      "created_at": "2026-01-20 14:00:00",
      "title": "Python Programming",
      "author": "John Doe",
      "member_name": "John Doe"
    }
  ],
  "page": 1,
  "per_page": 10,
  "total": 1,
  "pages": 1
}
```

### Get Single Transaction
```http
GET /api/transactions/1
```

**Response (200):**
```json
{
  "id": 1,
  "book_id": 1,
  "member_id": 1,
  "issue_date": "2026-01-20",
  "due_date": "2026-02-03",
  "return_date": null,
  "status": "issued",
  "fine_amount": 0,
  "created_at": "2026-01-20 14:00:00",
  "title": "Python Programming",
  "author": "John Doe",
  "member_name": "John Doe"
}
```

### Issue Book
```http
POST /api/transactions/issue
Content-Type: application/json

{
  "book_id": 1,
  "member_id": 1,
  "issue_date": "2026-01-23",
  "due_days": 14
}
```

**Response (201):**
```json
{
  "success": true,
  "message": "Book issued successfully",
  "transaction": {
    "id": 2,
    "book_id": 1,
    "member_id": 1,
    "issue_date": "2026-01-23",
    "due_date": "2026-02-06",
    "status": "issued"
  }
}
```

### Return Book
```http
POST /api/transactions/1/return
Content-Type: application/json

{
  "return_date": "2026-02-10"
}
```

**Response (200):**
```json
{
  "success": true,
  "message": "Book returned successfully",
  "transaction": {
    "id": 1,
    "book_id": 1,
    "member_id": 1,
    "issue_date": "2026-01-20",
    "due_date": "2026-02-03",
    "return_date": "2026-02-10",
    "status": "returned",
    "fine_amount": 7.0
  }
}
```

---

## Admin Chat (Admin Only)

Chat endpoints are restricted to users with `role: "admin"`. Requires Bearer token authentication.

### Get Admin Users
Get list of admin users available for chat (excludes current user).

```http
GET /api/chat/admins
Authorization: Bearer <token>
```

**Response (200):**
```json
{
  "success": true,
  "admins": [
    {
      "id": 2,
      "username": "admin2",
      "email": "admin2@library.com"
    }
  ]
}
```

### Get Conversations
Get list of conversations with last message preview and unread count.

```http
GET /api/chat/conversations
Authorization: Bearer <token>
```

**Response (200):**
```json
{
  "success": true,
  "conversations": [
    {
      "user_id": 2,
      "username": "admin2",
      "email": "admin2@library.com",
      "last_message": "Hello, how are you?",
      "last_message_time": "2026-01-23 10:30:00",
      "last_sender_id": 2,
      "unread_count": 3
    }
  ]
}
```

### Get Messages
Get all messages between current user and specified user. Automatically marks received messages as read.

```http
GET /api/chat/messages/<user_id>
Authorization: Bearer <token>
```

**Optional Query Parameters:**
- `since` - ISO timestamp to get only messages after this time (for polling)

**Example with polling:**
```http
GET /api/chat/messages/2?since=2026-01-23T10:30:00
```

**Response (200):**
```json
{
  "success": true,
  "other_user": {
    "id": 2,
    "username": "admin2",
    "role": "admin"
  },
  "messages": [
    {
      "id": 1,
      "sender_id": 1,
      "receiver_id": 2,
      "message": "Hi there!",
      "is_read": 1,
      "created_at": "2026-01-23 10:00:00"
    },
    {
      "id": 2,
      "sender_id": 2,
      "receiver_id": 1,
      "message": "Hello, how are you?",
      "is_read": 1,
      "created_at": "2026-01-23 10:30:00"
    }
  ],
  "current_user_id": 1
}
```

### Send Message
Send a message to another admin user.

```http
POST /api/chat/messages
Authorization: Bearer <token>
Content-Type: application/json

{
  "receiver_id": 2,
  "message": "Hello from mobile app!"
}
```

**Response (201):**
```json
{
  "success": true,
  "message": {
    "id": 3,
    "sender_id": 1,
    "receiver_id": 2,
    "message": "Hello from mobile app!",
    "is_read": 0,
    "created_at": "2026-01-23 11:00:00"
  }
}
```

### Get Unread Count
Get total unread message count for current user.

```http
GET /api/chat/unread-count
Authorization: Bearer <token>
```

**Response (200):**
```json
{
  "success": true,
  "unread_count": 5
}
```

---

## Error Responses

### 400 Bad Request
```json
{
  "error": "Request body required"
}
```

### 401 Unauthorized
```json
{
  "error": "Invalid username or password"
}
```

### 403 Forbidden (Admin Required)
```json
{
  "error": "Admin access required"
}
```

### 404 Not Found
```json
{
  "error": "Book not found"
}
```

### 409 Conflict
```json
{
  "error": "Book with this ISBN already exists"
}
```

---

## HTTP Status Codes

| Code | Meaning |
|------|---------|
| 200 | OK - Request successful |
| 201 | Created - Resource created |
| 400 | Bad Request - Invalid input |
| 401 | Unauthorized - Authentication required |
| 403 | Forbidden - Admin access required |
| 404 | Not Found - Resource not found |
| 409 | Conflict - Duplicate or constraint violation |

---

## Complete API Summary

### Authentication (4 endpoints)
- ✓ POST `/api/auth/login`
- ✓ POST `/api/auth/logout`
- ✓ POST `/api/auth/register`
- ✓ GET `/api/auth/me`

### Dashboard (1 endpoint)
- ✓ GET `/api/dashboard`

### Books (7 endpoints)
- ✓ GET `/api/books` - List with pagination
- ✓ GET `/api/books/<id>` - Get single
- ✓ GET `/api/books/search` - Quick search
- ✓ POST `/api/books` - Create
- ✓ PUT `/api/books/<id>` - Update
- ✓ DELETE `/api/books/<id>` - Delete

### Members (7 endpoints)
- ✓ GET `/api/members` - List with pagination
- ✓ GET `/api/members/<id>` - Get single
- ✓ GET `/api/members/search` - Quick search
- ✓ POST `/api/members` - Create
- ✓ PUT `/api/members/<id>` - Update
- ✓ DELETE `/api/members/<id>` - Delete

### Transactions (5 endpoints)
- ✓ GET `/api/transactions` - List with pagination
- ✓ GET `/api/transactions/<id>` - Get single
- ✓ POST `/api/transactions/issue` - Issue book
- ✓ POST `/api/transactions/<id>/return` - Return book

### Admin Chat (5 endpoints) - Admin Only
- ✓ GET `/api/chat/admins` - List admin users
- ✓ GET `/api/chat/conversations` - Get conversations
- ✓ GET `/api/chat/messages/<user_id>` - Get messages with user
- ✓ POST `/api/chat/messages` - Send message
- ✓ GET `/api/chat/unread-count` - Get unread count

**Total: 29 API endpoints**

---

**Version:** 2.1
**Last Updated:** January 23, 2026
