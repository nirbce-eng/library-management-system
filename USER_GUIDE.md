# User Guide

Complete guide for using the Library Management System.

## Getting Started

### Access the Application

- **Local Development**: http://localhost:5000
- **Docker**: http://localhost:3000

### Default Login

| Field | Value |
|-------|-------|
| Username | admin |
| Password | admin123 |

## Authentication

### Login

1. Navigate to the login page
2. Enter your username and password
3. Click "Sign In"

### Register New Account

1. Click "Create one" on the login page
2. Fill in the registration form:
   - Username (3-20 characters)
   - Email address
   - Password (minimum 6 characters)
   - Confirm password
3. Click "Create Account"
4. Sign in with your new credentials

### Change Password

1. Click on your username in the top-right corner
2. Select "Change Password"
3. Enter your current password
4. Enter and confirm your new password
5. Click "Update Password"

### Forgot Password

1. Click "Forgot password?" on the login page
2. Enter your username and registered email
3. Enter and confirm your new password
4. Click "Reset Password"

### Logout

1. Click on your username in the top-right corner
2. Click "Logout"

---

## Dashboard

The dashboard provides an overview of library statistics:

| Metric | Description |
|--------|-------------|
| Total Books | Number of books in the library |
| Active Members | Members with active status |
| Issued Books | Currently issued books |
| Overdue Books | Books past their due date |

### Recent Transactions

Shows the 5 most recent book transactions with:
- Book title
- Member name
- Issue date
- Due date
- Status

---

## Books Management

### View All Books

1. Click "Books" in the navigation menu
2. View the list of all books with:
   - Title and author
   - ISBN
   - Category
   - Total/Available copies

### Search Books

1. Enter search term in the search box
2. Search matches title, author, or ISBN
3. Results update automatically

### Filter by Category

1. Click the category dropdown
2. Select a category
3. Only books in that category are shown

### Add New Book

1. Click "+ Add New Book"
2. Fill in the form:

| Field | Required | Description |
|-------|----------|-------------|
| Title | Yes | Book title |
| Author | Yes | Author name |
| ISBN | Yes | Unique ISBN number |
| Publisher | No | Publisher name |
| Publication Year | No | Year published |
| Category | No | Book category (e.g., Fiction, Science) |
| Total Copies | Yes | Number of copies (default: 1) |

3. Click "Add Book"

### Edit Book

1. Find the book in the list
2. Click the edit icon (pencil)
3. Modify the details
4. Click "Update Book"

### Delete Book

1. Find the book in the list
2. Click the delete icon (trash)
3. Confirm deletion

**Note**: Books with active transactions cannot be deleted. Return all copies first.

---

## Members Management

### View All Members

1. Click "Members" in the navigation menu
2. View the list of all members with:
   - Name and email
   - Phone number
   - Membership date
   - Status (Active/Inactive)

### Search Members

1. Enter search term in the search box
2. Search matches name, email, or phone
3. Results update automatically

### Filter by Status

1. Click the status dropdown
2. Select "Active" or "Inactive"
3. Only members with that status are shown

### Register New Member

1. Click "+ Register Member"
2. Fill in the form:

| Field | Required | Description |
|-------|----------|-------------|
| Name | Yes | Member's full name |
| Email | Yes | Unique email address |
| Phone | No | Contact number |
| Address | No | Physical address |

3. Click "Register Member"

### Edit Member

1. Find the member in the list
2. Click the edit icon (pencil)
3. Modify the details
4. Change status if needed (Active/Inactive)
5. Click "Update Member"

### Delete Member

1. Find the member in the list
2. Click the delete icon (trash)
3. Confirm deletion

**Note**: Members with active transactions cannot be deleted. Return all books first.

---

## Transactions Management

### View All Transactions

1. Click "Transactions" in the navigation menu
2. View all transactions with:
   - Book title and author
   - Member name
   - Issue date
   - Due date
   - Return date (if returned)
   - Status
   - Fine amount (if any)

### Filter by Status

1. Click the status dropdown
2. Select "Issued" or "Returned"
3. Only transactions with that status are shown

### Issue a Book

1. Click "+ Issue Book"
2. Fill in the form:

| Field | Required | Description |
|-------|----------|-------------|
| Book | Yes | Select from available books |
| Member | Yes | Select from active members |
| Issue Date | Yes | Date of issue |
| Loan Period | Yes | Number of days (default: 14) |

3. Click "Issue Book"

**Notes**:
- Only books with available copies are shown
- Only active members are shown
- Due date is calculated automatically

### Return a Book

1. Find the issued transaction
2. Click the return icon
3. Enter the return date
4. Click "Return Book"

**Fine Calculation**:
- If returned after due date: $1.00 per day overdue
- Fine is calculated automatically
- Fine amount is displayed after return

---

## Fine Policy

| Condition | Fine |
|-----------|------|
| Returned on or before due date | $0.00 |
| Returned after due date | $1.00 per day |

**Example**:
- Due date: January 15
- Return date: January 20
- Overdue: 5 days
- Fine: $5.00

---

## Tips and Best Practices

### Books
- Use consistent category names (e.g., "Fiction" not "fiction")
- Keep ISBN numbers accurate for tracking
- Update available copies when receiving new stock

### Members
- Verify email addresses for communication
- Set inactive status for members who have left
- Keep contact information up to date

### Transactions
- Issue books promptly to track due dates accurately
- Process returns on the actual return date
- Monitor overdue books regularly

---

## Keyboard Shortcuts

| Key | Action |
|-----|--------|
| Tab | Move to next field |
| Enter | Submit form |
| Esc | Close modal/dialog |

---

## Troubleshooting

### Can't Login
- Check username spelling
- Verify password (case-sensitive)
- Clear browser cookies
- Try "Forgot Password" to reset

### Book Not Showing in Issue Form
- Check if book has available copies
- Verify book status in Books section

### Member Not Showing in Issue Form
- Check if member is active
- Verify member status in Members section

### Can't Delete Book/Member
- Check for active transactions
- Return all books first
- Try again after returns processed

### Fine Not Calculated
- Verify return date is after due date
- Check date format is correct

---

## Data Export

Currently, data can be exported by:

1. Accessing the database directly (admin only)
2. Using the API endpoints
3. Taking screenshots of reports

---

## Security Notes

### Password Requirements
- Minimum 6 characters
- Can include letters, numbers, symbols

### Session Security
- Sessions expire after inactivity
- Always logout on shared computers
- Don't share your credentials

### Audit Trail
All actions are logged including:
- Login/logout events
- Book operations
- Member operations
- Transaction operations

---

## Support

For assistance:
1. Check this user guide
2. Review the FAQ below
3. Contact your system administrator

---

## FAQ

**Q: Can I have multiple users with the same email?**
A: No, email addresses must be unique.

**Q: What happens if I try to delete a book with issued copies?**
A: The system will prevent deletion and show an error message.

**Q: Can I change a member's email after registration?**
A: Yes, edit the member and update the email (must be unique).

**Q: How do I view overdue books?**
A: Check the dashboard for overdue count, or filter transactions by "Issued" status and check due dates.

**Q: Can I issue the same book to the same member multiple times?**
A: Yes, as long as copies are available.

**Q: What if I enter the wrong return date?**
A: Contact your administrator to correct the transaction.

---

**Version**: 1.1
**Last Updated**: January 21, 2026
