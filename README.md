# Library Management System

A comprehensive web-based library management system built with Flask, SQLite, and modern web technologies. Features user authentication, comprehensive logging, and a modern responsive UI.

## Features

### Core Functionality
- **Books Management**: Add, edit, delete, and search books
- **Members Management**: Register and manage library members
- **Transaction Tracking**: Issue and return books with due date tracking
- **Automated Fine Calculation**: Calculate fines for overdue books ($1/day)
- **Real-time Dashboard**: View library statistics at a glance
- **Advanced Search**: Search books by title, author, or ISBN
- **Category Filtering**: Filter books by category

### Authentication System
- **User Login/Logout**: Secure session-based authentication
- **User Registration**: Create new staff accounts
- **Change Password**: Update password while logged in
- **Forgot Password**: Reset password using username + email verification
- **Role-based Access**: Admin and staff roles

### Logging & Audit Trail
- **Request Logging**: All HTTP requests logged with timing
- **Audit Trail**: Track all CRUD operations (books, members, transactions)
- **Error Logging**: Separate error log for debugging
- **Rotating Log Files**: Automatic log rotation (10MB max, 5 backups)

### Technical Features
- Responsive modern UI with dark theme
- RESTful API endpoints
- SQLite database with proper relationships
- Docker support with persistent volumes
- Input validation and error handling
- Flash messages for user feedback

## Quick Start

### Default Login Credentials
- **Username**: `admin`
- **Password**: `admin123`

### Option 1: Docker (Recommended)

```bash
# Start the application
docker compose up -d

# Access at http://localhost:3000

# View logs
docker compose logs -f

# Stop
docker compose down
```

### Option 2: Local Development

```bash
# Create virtual environment
python -m venv venv

# Activate (Windows)
venv\Scripts\activate

# Activate (macOS/Linux)
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Run application
python app.py

# Access at http://localhost:5000
```

## Project Structure

```
library-management-system/
├── app.py                      # Main Flask application
├── requirements.txt            # Python dependencies
├── Dockerfile                  # Docker configuration
├── docker-compose.yml          # Docker Compose configuration
├── library.db                  # SQLite database
│
├── logs/                       # Log files (auto-created)
│   ├── app.log                # General application logs
│   ├── error.log              # Error logs only
│   └── audit.log              # Audit trail logs
│
├── static/
│   ├── css/style.css          # Main stylesheet
│   └── js/main.js             # JavaScript functionality
│
└── templates/
    ├── base.html              # Base template with navigation
    ├── index.html             # Dashboard
    ├── login.html             # Login page
    ├── register.html          # User registration
    ├── change_password.html   # Change password form
    ├── forgot_password.html   # Password reset
    ├── books.html             # Books listing
    ├── add_book.html          # Add book form
    ├── edit_book.html         # Edit book form
    ├── members.html           # Members listing
    ├── add_member.html        # Add member form
    ├── edit_member.html       # Edit member form
    ├── transactions.html      # Transactions listing
    └── issue_book.html        # Issue book form
```

## Database Schema

### Users Table
| Column | Type | Description |
|--------|------|-------------|
| id | INTEGER | Primary key |
| username | TEXT | Unique username |
| password_hash | TEXT | Hashed password |
| email | TEXT | Unique email |
| role | TEXT | admin/staff |
| created_at | TIMESTAMP | Creation time |

### Books Table
| Column | Type | Description |
|--------|------|-------------|
| id | INTEGER | Primary key |
| title | TEXT | Book title |
| author | TEXT | Author name |
| isbn | TEXT | ISBN (unique) |
| publisher | TEXT | Publisher name |
| publication_year | INTEGER | Year published |
| category | TEXT | Book category |
| total_copies | INTEGER | Total copies |
| available_copies | INTEGER | Available copies |
| created_at | TIMESTAMP | Creation time |

### Members Table
| Column | Type | Description |
|--------|------|-------------|
| id | INTEGER | Primary key |
| name | TEXT | Member name |
| email | TEXT | Email (unique) |
| phone | TEXT | Phone number |
| address | TEXT | Address |
| membership_date | DATE | Join date |
| status | TEXT | active/inactive |
| created_at | TIMESTAMP | Creation time |

### Transactions Table
| Column | Type | Description |
|--------|------|-------------|
| id | INTEGER | Primary key |
| book_id | INTEGER | FK to books |
| member_id | INTEGER | FK to members |
| issue_date | DATE | Issue date |
| due_date | DATE | Due date |
| return_date | DATE | Return date |
| status | TEXT | issued/returned |
| fine_amount | REAL | Fine amount |
| created_at | TIMESTAMP | Creation time |

## API Endpoints

### Complete REST API (24 endpoints)

**Documentation:** See [MOBILE_API.md](MOBILE_API.md) for complete mobile API documentation.

#### Authentication APIs (4)
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/auth/login` | Login (JSON response) |
| POST | `/api/auth/logout` | Logout (JSON response) |
| POST | `/api/auth/register` | Register user (JSON response) |
| GET | `/api/auth/me` | Get current user info |

#### Dashboard API (1)
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/dashboard` | Get library statistics |

#### Books APIs (7)
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/books` | List books (with pagination) |
| GET | `/api/books/<id>` | Get single book |
| GET | `/api/books/search?q={query}` | Quick search books |
| POST | `/api/books` | Create book |
| PUT | `/api/books/<id>` | Update book |
| DELETE | `/api/books/<id>` | Delete book |

#### Members APIs (7)
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/members` | List members (with pagination) |
| GET | `/api/members/<id>` | Get single member |
| GET | `/api/members/search?q={query}` | Quick search members |
| POST | `/api/members` | Create member |
| PUT | `/api/members/<id>` | Update member |
| DELETE | `/api/members/<id>` | Delete member |

#### Transactions APIs (5)
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/transactions` | List transactions (with pagination) |
| GET | `/api/transactions/<id>` | Get single transaction |
| POST | `/api/transactions/issue` | Issue book |
| POST | `/api/transactions/<id>/return` | Return book |

### Web Routes (for browser access)
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET/POST | `/login` | User login page |
| GET | `/logout` | User logout |
| GET/POST | `/register` | User registration page |
| GET/POST | `/change-password` | Change password page |
| GET/POST | `/forgot-password` | Reset password page |

## Logging

### Log Files
- **app.log**: All application activity (DEBUG level)
- **error.log**: Errors only (ERROR level)
- **audit.log**: Audit trail for security-sensitive operations

### Audit Events Logged
- `USER_LOGIN` / `USER_LOGOUT`
- `USER_REGISTERED`
- `PASSWORD_CHANGED` / `PASSWORD_RESET`
- `BOOK_CREATED` / `BOOK_UPDATED` / `BOOK_DELETED`
- `MEMBER_CREATED` / `MEMBER_UPDATED` / `MEMBER_DELETED`
- `BOOK_ISSUED` / `BOOK_RETURNED`

### Log Format
```
2026-01-21 12:00:00,000 - library.audit - INFO - BOOK_CREATED: title='Python Guide', isbn='123456'
```

## Configuration

### Environment Variables
| Variable | Default | Description |
|----------|---------|-------------|
| FLASK_APP | app.py | Flask application |
| FLASK_ENV | production | Environment mode |

### Customization

**Change Secret Key** (app.py):
```python
app.secret_key = 'your-secure-secret-key'
```

**Adjust Fine Rate** (app.py, line ~614):
```python
fine = overdue_days * 1.0  # $1 per day
```

**Change Default Loan Period** (templates/issue_book.html):
```html
<input type="number" name="due_days" value="14" min="1" max="90">
```

## Docker Configuration

### Volumes
- `library-data`: Database persistence
- `library-logs`: Log file persistence

### Ports
- Container port: 5000
- Host port: 3000 (configurable in docker-compose.yml)

### Commands
```bash
# Build and start
docker compose up --build -d

# View logs
docker compose logs -f library-app

# Access container shell
docker exec -it library-management-system /bin/bash

# Restart
docker compose restart

# Stop and remove
docker compose down

# Stop and remove with volumes
docker compose down -v
```

## Troubleshooting

### Login Issues
- Clear browser cookies for localhost
- Check if default admin user exists in database
- Verify password hash in users table

### Database Errors
- Delete `library.db` to recreate fresh database
- Check file permissions on database file

### Docker Issues
- Ensure Docker Desktop is running
- Check logs: `docker compose logs`
- Rebuild: `docker compose up --build`

### Port Already in Use
```bash
# Find process using port
netstat -ano | findstr :5000

# Kill process (Windows)
taskkill /PID <pid> /F
```

## Security Considerations

For production deployment:
1. Change the Flask secret key
2. Use environment variables for sensitive config
3. Enable HTTPS with SSL certificate
4. Set `debug=False` in production
5. Use a production WSGI server (gunicorn, uWSGI)
6. Regular database backups
7. Monitor audit logs for suspicious activity

## Tech Stack

- **Backend**: Python 3.11, Flask 3.0
- **Database**: SQLite
- **Frontend**: HTML5, CSS3, JavaScript
- **Authentication**: Werkzeug password hashing
- **Containerization**: Docker, Docker Compose
- **Logging**: Python logging with RotatingFileHandler

## License

This project is open source and available for educational purposes.

---

**Happy Library Managing!**
