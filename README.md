# 📚 Library Management System

A comprehensive web-based library management system built with Flask, SQLite, and modern web technologies.

## 🌟 Features

### Core Functionality
- **Books Management**: Add, edit, delete, and search books
- **Members Management**: Register and manage library members
- **Transaction Tracking**: Issue and return books with due date tracking
- **Automated Fine Calculation**: Calculate fines for overdue books
- **Real-time Dashboard**: View library statistics at a glance
- **Advanced Search**: Search books by title, author, or ISBN
- **Category Filtering**: Filter books by category

### Technical Features
- Responsive modern UI design
- RESTful API endpoints
- SQLite database with proper relationships
- Input validation and error handling
- Flash messages for user feedback
- Modal dialogs for quick actions

## 📋 Prerequisites

- Python 3.8 or higher
- Docker Desktop (for containerized deployment)
- VS Code (recommended for development)

## 🚀 Installation & Setup

### Option 1: Local Development Setup

1. **Clone or download the project**
   ```bash
   cd library-management-system
   ```

2. **Create a virtual environment** (recommended)
   ```bash
   python -m venv venv
   
   # On Windows
   venv\Scripts\activate
   
   # On macOS/Linux
   source venv/bin/activate
   ```

3. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Run the application**
   ```bash
   python app.py
   ```

5. **Access the application**
   - Open your browser and navigate to: `http://localhost:5000`

### Option 2: Docker Deployment

#### Using Docker Desktop:

1. **Make sure Docker Desktop is running**

2. **Build and run using Docker Compose**
   ```bash
   docker-compose up -d
   ```

3. **Access the application**
   - Open your browser and navigate to: `http://localhost:5000`

4. **View logs**
   ```bash
   docker-compose logs -f
   ```

5. **Stop the application**
   ```bash
   docker-compose down
   ```

#### Using Docker Commands Directly:

1. **Build the Docker image**
   ```bash
   docker build -t library-management-system .
   ```

2. **Run the container**
   ```bash
   docker run -d -p 5000:5000 --name library-app library-management-system
   ```

3. **Stop the container**
   ```bash
   docker stop library-app
   docker rm library-app
   ```

## 📁 Project Structure

```
library-management-system/
│
├── app.py                      # Main Flask application
├── requirements.txt            # Python dependencies
├── Dockerfile                  # Docker configuration
├── docker-compose.yml          # Docker Compose configuration
├── .dockerignore              # Docker ignore file
│
├── static/                    # Static files
│   ├── css/
│   │   └── style.css         # Main stylesheet
│   └── js/
│       └── main.js           # JavaScript functionality
│
├── templates/                 # HTML templates
│   ├── base.html             # Base template
│   ├── index.html            # Dashboard
│   ├── books.html            # Books listing
│   ├── add_book.html         # Add book form
│   ├── edit_book.html        # Edit book form
│   ├── members.html          # Members listing
│   ├── add_member.html       # Add member form
│   ├── edit_member.html      # Edit member form
│   ├── transactions.html     # Transactions listing
│   └── issue_book.html       # Issue book form
│
└── library.db                # SQLite database (created automatically)
```

## 🗄️ Database Schema

### Books Table
- `id`: Primary key
- `title`: Book title
- `author`: Author name
- `isbn`: ISBN number (unique)
- `publisher`: Publisher name
- `publication_year`: Year of publication
- `category`: Book category
- `total_copies`: Total number of copies
- `available_copies`: Number of available copies
- `created_at`: Timestamp

### Members Table
- `id`: Primary key
- `name`: Member name
- `email`: Email address (unique)
- `phone`: Phone number
- `address`: Physical address
- `membership_date`: Date of membership
- `status`: Active/Inactive
- `created_at`: Timestamp

### Transactions Table
- `id`: Primary key
- `book_id`: Foreign key to books
- `member_id`: Foreign key to members
- `issue_date`: Date book was issued
- `due_date`: Date book is due
- `return_date`: Date book was returned
- `status`: Issued/Returned
- `fine_amount`: Fine amount for overdue
- `created_at`: Timestamp

## 🎯 Usage Guide

### Dashboard
- View total books, active members, issued books, and overdue books
- Quick access to recent transactions
- Quick action buttons for common tasks

### Managing Books
1. Click "Books" in the navigation
2. Use search to find books by title, author, or ISBN
3. Filter by category
4. Add new books using the "+ Add New Book" button
5. Edit or delete existing books using the action buttons

### Managing Members
1. Click "Members" in the navigation
2. Search members by name, email, or phone
3. Filter by status (Active/Inactive)
4. Register new members using the "+ Register Member" button
5. Edit or deactivate members as needed

### Issuing Books
1. Click "Transactions" → "+ Issue Book"
2. Select the book from available inventory
3. Select an active member
4. Set issue date and loan period
5. System automatically calculates due date

### Returning Books
1. Go to "Transactions"
2. Find the issued book
3. Click the return button (📥)
4. Enter return date
5. System automatically calculates any fines ($1/day for overdue)

## ⚙️ Configuration

### Changing the Secret Key
In `app.py`, update the secret key for production:
```python
app.secret_key = 'your-secret-key-change-in-production'
```

### Adjusting Fine Rates
In `app.py`, find the return_book function and modify:
```python
fine = overdue_days * 1.0  # Change 1.0 to your desired rate
```

### Changing Default Loan Period
In `templates/issue_book.html`, modify:
```html
<input type="number" id="due_days" name="due_days" value="14" min="1" max="90">
```

## 🔧 Development with VS Code

### Recommended Extensions
- Python
- Pylance
- Docker
- SQLite Viewer

### Debug Configuration
Create `.vscode/launch.json`:
```json
{
    "version": "0.2.0",
    "configurations": [
        {
            "name": "Python: Flask",
            "type": "python",
            "request": "launch",
            "module": "flask",
            "env": {
                "FLASK_APP": "app.py",
                "FLASK_ENV": "development"
            },
            "args": [
                "run",
                "--no-debugger",
                "--no-reload"
            ],
            "jinja": true
        }
    ]
}
```

## 🐛 Troubleshooting

### Application won't start
- Ensure Python 3.8+ is installed
- Check if port 5000 is already in use
- Verify all dependencies are installed

### Database errors
- Delete `library.db` and restart the application
- The database will be recreated automatically

### Docker issues
- Ensure Docker Desktop is running
- Check Docker logs: `docker-compose logs`
- Try rebuilding: `docker-compose up --build`

### Can't delete books/members
- Books with active transactions cannot be deleted
- Members with active transactions cannot be deleted
- Return all books first, then delete

## 🔒 Security Considerations

For production deployment:
1. Change the Flask secret key
2. Use environment variables for configuration
3. Enable HTTPS
4. Implement user authentication
5. Add rate limiting
6. Regular database backups

## 📈 Future Enhancements

Potential features to add:
- User authentication and authorization
- Email notifications for due dates
- Report generation (PDF/Excel)
- Barcode scanning support
- Book reservation system
- Multi-language support
- Advanced analytics dashboard
- Mobile app integration

## 📝 API Endpoints

### Books API
- `GET /api/books/search?q={query}` - Search available books

### Members API
- `GET /api/members/search?q={query}` - Search active members

## 🤝 Contributing

To contribute to this project:
1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## 📄 License

This project is open source and available for educational purposes.

## 👨‍💻 Support

For issues, questions, or suggestions:
- Check the troubleshooting section
- Review the code comments
- Open an issue on the repository

## 🎉 Credits

Built with:
- **Flask**: Web framework
- **SQLite**: Database
- **HTML/CSS/JavaScript**: Frontend
- **Docker**: Containerization

---

**Happy Library Managing! 📚**
