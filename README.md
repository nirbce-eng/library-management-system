# Library Management System

A comprehensive web-based library management system built with Flask, SQLite, and modern web technologies. Features user authentication, staff chat, fines ledger, comprehensive logging, and a modern responsive UI.

## Features

### Core Functionality
- **Books Management**: Add, edit, delete, and search books
- **Members Management**: Register and manage library members
- **Transaction Tracking**: Issue and return books with due date tracking
- **Automated Fine Calculation**: Calculate fines for overdue books ($1/day)
- **Real-time Dashboard**: View library statistics at a glance
- **Advanced Search**: Search books by title, author, or ISBN
- **Category Filtering**: Filter books by category

### Admin Features
- **Fines Ledger**: Track all collected overdue fines with summary statistics
- **Staff Chat**: Real-time messaging between staff members
- **User Management**: Role-based access control (admin/staff)

### Authentication System
- **User Login/Logout**: Secure session-based authentication
- **User Registration**: Create new staff accounts
- **Change Password**: Update password while logged in
- **Forgot Password**: Reset password using username + email verification
- **API Token Auth**: Token-based authentication for mobile apps
- **Role-based Access**: Admin and staff roles

### Mobile API
- Complete REST API for mobile app integration
- Token-based authentication
- Full CRUD operations for all entities
- Chat and ledger endpoints

### Logging & Audit Trail
- **Request Logging**: All HTTP requests logged with timing
- **Audit Trail**: Track all CRUD operations (books, members, transactions)
- **Error Logging**: Separate error log for debugging
- **Rotating Log Files**: Automatic log rotation (10MB max, 5 backups)

## Quick Start

### Default Login Credentials
- **Username**: `admin`
- **Password**: `admin123`

### Option 1: Docker (Recommended)

```bash
# Start the application
docker-compose up -d

# Access at http://localhost:3000

# View logs
docker-compose logs -f

# Stop
docker-compose down
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
│
├── data/                       # Data directory (auto-created)
│   └── library.db             # SQLite database (persistent)
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
    ├── issue_book.html        # Issue book form
    ├── chat.html              # Staff chat (admin)
    └── ledger.html            # Fines ledger (admin)
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

### Chat Messages Table
| Column | Type | Description |
|--------|------|-------------|
| id | INTEGER | Primary key |
| sender_id | INTEGER | FK to users |
| receiver_id | INTEGER | FK to users |
| message | TEXT | Message content |
| is_read | INTEGER | Read status (0/1) |
| created_at | TIMESTAMP | Creation time |

### API Tokens Table
| Column | Type | Description |
|--------|------|-------------|
| id | INTEGER | Primary key |
| user_id | INTEGER | FK to users |
| token | TEXT | Unique API token |
| created_at | TIMESTAMP | Creation time |

## API Endpoints

### Authentication APIs
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/auth/login` | Login, returns API token |
| POST | `/api/auth/logout` | Logout |
| POST | `/api/auth/register` | Register user |
| GET | `/api/auth/me` | Get current user info |

### Dashboard API
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/dashboard` | Get library statistics |

### Books APIs
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/books` | List books (paginated) |
| GET | `/api/books/<id>` | Get single book |
| GET | `/api/books/search?q={query}` | Search books |
| POST | `/api/books` | Create book |
| PUT | `/api/books/<id>` | Update book |
| DELETE | `/api/books/<id>` | Delete book |

### Members APIs
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/members` | List members (paginated) |
| GET | `/api/members/<id>` | Get single member |
| GET | `/api/members/search?q={query}` | Search members |
| POST | `/api/members` | Create member |
| PUT | `/api/members/<id>` | Update member |
| DELETE | `/api/members/<id>` | Delete member |

### Transactions APIs
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/transactions` | List transactions (paginated) |
| GET | `/api/transactions/<id>` | Get single transaction |
| POST | `/api/transactions/issue` | Issue book |
| POST | `/api/transactions/<id>/return` | Return book |

### Chat APIs
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/chat/users` | List available chat users |
| GET | `/api/chat/conversations` | Get conversation list |
| GET | `/api/chat/messages/<user_id>` | Get messages with user |
| POST | `/api/chat/messages` | Send message |
| GET | `/api/chat/unread-count` | Get unread message count |

### Ledger APIs (Admin Only)
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/ledger/fines` | Get all collected fines |
| GET | `/api/ledger/summary` | Get fines summary by period |

## Docker Deployment

### Docker Compose (Recommended)

```bash
# Build and start
docker-compose up -d

# View logs
docker-compose logs -f library-app

# Stop
docker-compose down

# Rebuild after code changes
docker-compose up -d --build

# Stop and remove volumes (reset database)
docker-compose down -v
```

### Docker Commands

```bash
# Build image
docker build -t library-management-system .

# Run container
docker run -d \
  --name library-app \
  -p 3000:5000 \
  -v library-data:/app/data \
  -v library-logs:/app/logs \
  library-management-system

# View logs
docker logs -f library-app

# Access shell
docker exec -it library-app /bin/bash

# Stop
docker stop library-app
```

### Data Persistence

Docker volumes are used for persistent storage:
- `library-data` - SQLite database
- `library-logs` - Application logs

**Backup database:**
```bash
docker cp library-management-system:/app/data/library.db ./backup/
```

**Restore database:**
```bash
docker cp ./backup/library.db library-management-system:/app/data/
```

## Logging

### Log Files
- **app.log**: All application activity (DEBUG level)
- **error.log**: Errors only (ERROR level)
- **audit.log**: Audit trail for security-sensitive operations

### Audit Events Logged
- `USER_LOGIN` / `USER_LOGOUT` / `API_LOGIN` / `API_LOGOUT`
- `USER_REGISTERED` / `API_USER_REGISTERED`
- `PASSWORD_CHANGED` / `PASSWORD_RESET`
- `BOOK_CREATED` / `BOOK_UPDATED` / `BOOK_DELETED`
- `MEMBER_CREATED` / `MEMBER_UPDATED` / `MEMBER_DELETED`
- `BOOK_ISSUED` / `BOOK_RETURNED`
- `CHAT_MESSAGE_SENT`

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

**Adjust Fine Rate** (app.py):
```python
fine = overdue_days * 1.0  # $1 per day
```

**Change Default Loan Period** (templates/issue_book.html):
```html
<input type="number" name="due_days" value="14" min="1" max="90">
```

## Troubleshooting

### Login Issues
- Clear browser cookies for localhost
- Check if default admin user exists in database
- Verify password hash in users table

### Database Errors
- Delete `data/library.db` to recreate fresh database
- Check file permissions on database file

### Docker Issues
- Ensure Docker Desktop is running
- Check logs: `docker-compose logs`
- Rebuild: `docker-compose up --build`

### Port Already in Use
```bash
# Change port in docker-compose.yml
ports:
  - "3001:5000"  # Use port 3001 instead
```

### CORS Issues (Mobile App)
- CORS is enabled for `/api/*` endpoints
- Ensure mobile app uses correct API URL

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

- **Backend**: Python 3.11, Flask 3.0, Flask-CORS
- **Database**: SQLite
- **Frontend**: HTML5, CSS3, JavaScript
- **Authentication**: Werkzeug password hashing, API tokens
- **Containerization**: Docker, Docker Compose
- **Logging**: Python logging with RotatingFileHandler

## License

This project is open source and available for educational purposes.

---

**Happy Library Managing!**
