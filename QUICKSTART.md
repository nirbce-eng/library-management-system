# 🚀 Quick Start Guide

Get your Library Management System up and running in 5 minutes!

## Choose Your Setup Method

### ⚡ Quick Setup (Recommended for Beginners)

**Step 1:** Open VS Code
- Launch Visual Studio Code
- Click File → Open Folder
- Select the `library-management-system` folder

**Step 2:** Open Terminal in VS Code
- Press `Ctrl+~` (Windows/Linux) or `Cmd+~` (Mac)

**Step 3:** Install Dependencies
```bash
pip install -r requirements.txt
```

**Step 4:** Run the Application
```bash
python app.py
```

**Step 5:** Open Your Browser
- Go to: `http://localhost:5000`
- Start using your library management system!

---

### 🐳 Docker Setup (Recommended for Production)

**Step 1:** Make Sure Docker Desktop is Running
- Open Docker Desktop application
- Wait for it to fully start

**Step 2:** Open Terminal/Command Prompt
- Navigate to project folder:
```bash
cd library-management-system
```

**Step 3:** Build and Run
```bash
docker-compose up -d
```

**Step 4:** Access Application
- Open browser: `http://localhost:5000`

**To Stop:**
```bash
docker-compose down
```

---

## First Time Usage

### 1. Dashboard Overview
When you first open the application, you'll see:
- Total Books: 0
- Active Members: 0
- Issued Books: 0
- Overdue Books: 0

### 2. Add Your First Book
1. Click **"Books"** in navigation
2. Click **"+ Add New Book"**
3. Fill in the form:
   - Title: "The Great Gatsby"
   - Author: "F. Scott Fitzgerald"
   - ISBN: "978-0-7432-7356-5"
   - Publisher: "Scribner"
   - Year: "1925"
   - Category: "Fiction"
   - Copies: "3"
4. Click **"Add Book"**

### 3. Register Your First Member
1. Click **"Members"** in navigation
2. Click **"+ Register Member"**
3. Fill in the form:
   - Name: "John Doe"
   - Email: "john.doe@example.com"
   - Phone: "+1234567890"
   - Address: "123 Main St"
4. Click **"Register Member"**

### 4. Issue Your First Book
1. Click **"Transactions"** → **"+ Issue Book"**
2. Select book from dropdown
3. Select member from dropdown
4. Set issue date (defaults to today)
5. Set loan period (default: 14 days)
6. Click **"Issue Book"**

### 5. Return a Book
1. Go to **"Transactions"**
2. Find the issued book
3. Click the return icon (📥)
4. Enter return date
5. Click **"Process Return"**
   - If late, fine will be calculated automatically

---

## Common Tasks

### Search for Books
1. Go to "Books" page
2. Type in search box (searches title, author, ISBN)
3. Press Enter or click search icon

### Filter by Category
1. Go to "Books" page
2. Select category from dropdown
3. Results update automatically

### View Member History
1. Go to "Transactions"
2. Use search to find all transactions for a member

### Check Overdue Books
1. Go to "Transactions"
2. Filter by "Currently Issued"
3. Look for books where due date < today

---

## Keyboard Shortcuts

### In VS Code:
- `F5`: Run with debugger
- `Ctrl+C`: Stop application (in terminal)
- `Ctrl+~`: Toggle terminal

### In Browser:
- `Ctrl+R` or `F5`: Refresh page
- `Ctrl+Shift+I`: Open developer tools

---

## Troubleshooting Quick Fixes

### Port Already in Use
```bash
# Find and kill process on port 5000 (Windows)
netstat -ano | findstr :5000
taskkill /PID <PID> /F

# On Mac/Linux
lsof -ti:5000 | xargs kill
```

### Database Locked
- Stop the application
- Delete `library.db` file
- Restart application (creates new database)

### Module Not Found
```bash
pip install -r requirements.txt
```

### Docker Won't Start
- Ensure Docker Desktop is running
- Check if port 5000 is free
- Try: `docker-compose down` then `docker-compose up -d`

---

## Sample Data

Want to test with sample data? Add these:

### Sample Books:
1. **Python Crash Course** by Eric Matthes (978-1-59327-928-8)
2. **Clean Code** by Robert Martin (978-0-13-235088-4)
3. **To Kill a Mockingbird** by Harper Lee (978-0-06-112008-4)

### Sample Members:
1. **Alice Johnson** (alice@example.com)
2. **Bob Smith** (bob@example.com)
3. **Carol White** (carol@example.com)

---

## Next Steps

Once you're comfortable with the basics:

1. **Read the Full Documentation**
   - `README.md` - Complete feature list
   - `DOCKER_GUIDE.md` - Detailed Docker setup
   - `VSCODE_GUIDE.md` - VS Code development tips
   - `API_DOCS.md` - API reference

2. **Customize the System**
   - Change fine rates in `app.py`
   - Modify default loan period
   - Update color scheme in `style.css`

3. **Deploy to Production**
   - Follow Docker guide for deployment
   - Set up backups
   - Configure security settings

---

## Quick Reference Card

```
Application URL: http://localhost:5000

Pages:
  / ................. Dashboard
  /books ............ Books Management
  /members .......... Members Management
  /transactions ..... Transactions

Docker Commands:
  docker-compose up -d ........ Start
  docker-compose down ......... Stop
  docker-compose logs -f ...... View Logs

Python Commands:
  python app.py ............... Run App
  pip install -r requirements.txt .. Install

Fine Calculation:
  $1.00 per day overdue

Default Loan Period:
  14 days
```

---

## Need Help?

1. Check the troubleshooting section above
2. Review the detailed guides in the documentation folder
3. Check error messages in terminal/console
4. Look at the browser console (F12) for frontend errors

---

**Happy Library Managing! 📚**

*Estimated setup time: 5-10 minutes*
