# 💻 VS Code Development Guide

Complete guide for developing the Library Management System in Visual Studio Code.

## Prerequisites

1. **Install VS Code**
   - Download from: https://code.visualstudio.com/

2. **Install Python**
   - Python 3.8 or higher
   - Add Python to PATH during installation

3. **Install Git** (optional but recommended)
   - Download from: https://git-scm.com/

## Initial Setup

### Step 1: Open Project in VS Code

1. Launch VS Code
2. File → Open Folder
3. Select `library-management-system` folder
4. Click "Select Folder"

### Step 2: Install Recommended Extensions

Open Command Palette (Ctrl+Shift+P / Cmd+Shift+P) and run:
```
Extensions: Show Recommended Extensions
```

**Essential Extensions:**

1. **Python** (Microsoft)
   - Python language support
   - IntelliSense, debugging, code navigation

2. **Pylance** (Microsoft)
   - Enhanced Python language support
   - Type checking and auto-completion

3. **Python Debugger** (Microsoft)
   - Python debugging support

**Helpful Extensions:**

4. **SQLite Viewer** (alexcvzz)
   - View and edit SQLite databases

5. **Docker** (Microsoft)
   - Docker file support and management

6. **Jinja** (wholroyd)
   - Syntax highlighting for Jinja templates

7. **HTML CSS Support** (ecmel)
   - Better HTML/CSS IntelliSense

8. **Auto Rename Tag** (Jun Han)
   - Auto rename paired HTML tags

9. **Prettier** (Prettier)
   - Code formatter

10. **GitLens** (GitKraken) - Optional
    - Enhanced Git capabilities

### Install Extensions via Command Line:
```bash
code --install-extension ms-python.python
code --install-extension ms-python.vscode-pylance
code --install-extension ms-python.debugpy
code --install-extension alexcvzz.vscode-sqlite
code --install-extension ms-azuretools.vscode-docker
code --install-extension wholroyd.jinja
```

## Project Configuration

### Create VS Code Settings

Create `.vscode/settings.json`:

```json
{
    "python.defaultInterpreterPath": "${workspaceFolder}/venv/bin/python",
    "python.linting.enabled": true,
    "python.linting.pylintEnabled": true,
    "python.formatting.provider": "autopep8",
    "python.testing.pytestEnabled": false,
    "python.testing.unittestEnabled": false,
    "editor.formatOnSave": true,
    "editor.rulers": [80, 120],
    "files.exclude": {
        "**/__pycache__": true,
        "**/*.pyc": true,
        "**/.pytest_cache": true,
        "**/.vscode": false
    },
    "files.watcherExclude": {
        "**/__pycache__/**": true
    },
    "emmet.includeLanguages": {
        "jinja-html": "html"
    },
    "[python]": {
        "editor.tabSize": 4,
        "editor.insertSpaces": true
    },
    "[html]": {
        "editor.tabSize": 2,
        "editor.insertSpaces": true
    },
    "[css]": {
        "editor.tabSize": 2,
        "editor.insertSpaces": true
    },
    "[javascript]": {
        "editor.tabSize": 2,
        "editor.insertSpaces": true
    }
}
```

### Create Launch Configuration

Create `.vscode/launch.json`:

```json
{
    "version": "0.2.0",
    "configurations": [
        {
            "name": "Python: Flask",
            "type": "debugpy",
            "request": "launch",
            "module": "flask",
            "env": {
                "FLASK_APP": "app.py",
                "FLASK_ENV": "development",
                "FLASK_DEBUG": "1"
            },
            "args": [
                "run",
                "--host=0.0.0.0",
                "--port=5000"
            ],
            "jinja": true,
            "justMyCode": true,
            "console": "integratedTerminal"
        },
        {
            "name": "Python: Current File",
            "type": "debugpy",
            "request": "launch",
            "program": "${file}",
            "console": "integratedTerminal",
            "justMyCode": true
        }
    ]
}
```

### Create Tasks

Create `.vscode/tasks.json`:

```json
{
    "version": "2.0.0",
    "tasks": [
        {
            "label": "Run Flask App",
            "type": "shell",
            "command": "${command:python.interpreterPath}",
            "args": ["app.py"],
            "problemMatcher": [],
            "group": {
                "kind": "build",
                "isDefault": true
            }
        },
        {
            "label": "Install Dependencies",
            "type": "shell",
            "command": "${command:python.interpreterPath}",
            "args": ["-m", "pip", "install", "-r", "requirements.txt"],
            "problemMatcher": []
        },
        {
            "label": "Docker Build",
            "type": "shell",
            "command": "docker",
            "args": ["build", "-t", "library-management-system", "."],
            "problemMatcher": []
        },
        {
            "label": "Docker Run",
            "type": "shell",
            "command": "docker-compose",
            "args": ["up", "-d"],
            "problemMatcher": []
        }
    ]
}
```

## Development Workflow

### 1. Set Up Virtual Environment

**Using VS Code Terminal:**

```bash
# Open integrated terminal (Ctrl+` or Cmd+`)

# Create virtual environment
python -m venv venv

# Activate virtual environment
# Windows
venv\Scripts\activate

# macOS/Linux
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### 2. Select Python Interpreter

1. Press `Ctrl+Shift+P` (Windows/Linux) or `Cmd+Shift+P` (Mac)
2. Type: "Python: Select Interpreter"
3. Select the interpreter from `venv` folder

### 3. Run the Application

**Method 1: Using Debug**
1. Press `F5` or click Run → Start Debugging
2. Select "Python: Flask" configuration
3. Application starts at http://localhost:5000

**Method 2: Using Terminal**
```bash
python app.py
```

**Method 3: Using Task**
1. Press `Ctrl+Shift+B` (build task)
2. Or Terminal → Run Task → Run Flask App

### 4. Debug the Application

**Setting Breakpoints:**
1. Click in the gutter (left of line numbers)
2. Red dot appears = breakpoint set

**Debug Controls:**
- F5: Continue
- F10: Step Over
- F11: Step Into
- Shift+F11: Step Out
- Ctrl+Shift+F5: Restart
- Shift+F5: Stop

**Debug Panel:**
- Variables: View current variables
- Watch: Add expressions to watch
- Call Stack: View function call hierarchy
- Breakpoints: Manage all breakpoints

### 5. Edit Files

**Quick Navigation:**
- `Ctrl+P`: Quick file open
- `Ctrl+Shift+O`: Go to symbol in file
- `Ctrl+T`: Go to symbol in workspace
- `F12`: Go to definition
- `Alt+F12`: Peek definition
- `Shift+F12`: Find all references

**Editing:**
- `Ctrl+Space`: Trigger IntelliSense
- `Ctrl+.`: Quick fix
- `Alt+Up/Down`: Move line up/down
- `Ctrl+/`: Toggle line comment
- `Shift+Alt+F`: Format document

## Working with SQLite Database

### Using SQLite Viewer Extension

1. **Open Database:**
   - Right-click `library.db`
   - Select "Open Database"

2. **View Tables:**
   - Expand database in SQLite Explorer panel
   - Click on table to view data

3. **Run Queries:**
   - Right-click on database
   - Select "New Query"
   - Write SQL and execute

### Using Integrated Terminal

```bash
# Open database
sqlite3 library.db

# Common commands
.tables              # List all tables
.schema books        # View table schema
SELECT * FROM books; # Query data
.exit                # Exit SQLite
```

## Code Snippets

Add to User Snippets (File → Preferences → User Snippets → python.json):

```json
{
    "Flask Route": {
        "prefix": "froute",
        "body": [
            "@app.route('/${1:path}', methods=['${2:GET}'])",
            "def ${3:function_name}():",
            "    ${4:pass}",
            "    return render_template('${5:template}.html')"
        ],
        "description": "Flask route template"
    },
    "Flask Route with DB": {
        "prefix": "froutedb",
        "body": [
            "@app.route('/${1:path}')",
            "def ${2:function_name}():",
            "    with get_db() as conn:",
            "        cursor = conn.cursor()",
            "        ${3:# Query here}",
            "    return render_template('${4:template}.html')"
        ],
        "description": "Flask route with database"
    }
}
```

## Git Integration

### Initialize Git Repository

```bash
# Initialize repo
git init

# Add files
git add .

# Commit
git commit -m "Initial commit"
```

### VS Code Git Features

**Source Control Panel** (Ctrl+Shift+G):
- View changes
- Stage/unstage files
- Commit changes
- View history
- Create branches
- Push/pull

**Common Git Operations:**
1. **Stage Changes:** Click + icon next to file
2. **Commit:** Enter message and click ✓
3. **Create Branch:** Click branch name in status bar
4. **Merge:** Right-click branch and select "Merge"

## Testing

### Manual Testing

1. **Test Books Management:**
   - Add book → Verify in database
   - Edit book → Verify changes
   - Delete book → Verify removal
   - Search books → Verify results

2. **Test Members:**
   - Similar testing as books

3. **Test Transactions:**
   - Issue book → Verify count decreased
   - Return book → Verify fine calculation
   - Check overdue → Verify status

### Using VS Code REST Client

Install REST Client extension:
```bash
code --install-extension humao.rest-client
```

Create `tests/api.http`:
```http
### Search Books
GET http://localhost:5000/api/books/search?q=python

### Search Members
GET http://localhost:5000/api/members/search?q=john
```

## Docker Integration

### Using Docker Extension

1. **View Docker Resources:**
   - Open Docker view in sidebar
   - View images, containers, registries

2. **Build Image:**
   - Right-click Dockerfile
   - Select "Build Image"

3. **Run Container:**
   - Right-click image
   - Select "Run"
   - Configure ports and volumes

### Docker Commands in Terminal

```bash
# Build
docker build -t library-management-system .

# Run
docker-compose up -d

# View logs
docker-compose logs -f

# Stop
docker-compose down
```

## Productivity Tips

### Keyboard Shortcuts

**Essential:**
- `Ctrl+P`: Quick open
- `Ctrl+Shift+P`: Command palette
- `Ctrl+B`: Toggle sidebar
- `Ctrl+J`: Toggle panel
- `Ctrl+~`: Toggle terminal
- `Ctrl+K Ctrl+S`: Keyboard shortcuts reference

**Multi-cursor:**
- `Alt+Click`: Add cursor
- `Ctrl+Alt+Up/Down`: Add cursor above/below
- `Ctrl+D`: Select next occurrence
- `Ctrl+Shift+L`: Select all occurrences

**Code Folding:**
- `Ctrl+Shift+[`: Fold region
- `Ctrl+Shift+]`: Unfold region
- `Ctrl+K Ctrl+0`: Fold all
- `Ctrl+K Ctrl+J`: Unfold all

### Workspace Settings

**Zen Mode:**
- `Ctrl+K Z`: Enter Zen mode (distraction-free)

**Split Editor:**
- `Ctrl+\`: Split editor
- `Ctrl+1/2/3`: Focus editor group

**Terminal:**
- `Ctrl+Shift+~`: Create new terminal
- `Ctrl+PageUp/Down`: Switch terminals

## Troubleshooting

### Python Not Found

1. Verify Python installation:
   ```bash
   python --version
   ```

2. Set interpreter path in settings:
   ```json
   "python.defaultInterpreterPath": "C:/Python311/python.exe"
   ```

### Import Errors

1. Ensure virtual environment is activated
2. Reinstall dependencies:
   ```bash
   pip install -r requirements.txt
   ```

### Flask Not Running

1. Check if port 5000 is available
2. Verify FLASK_APP environment variable
3. Check terminal for error messages

### Debug Not Working

1. Verify launch configuration
2. Check Python debugger extension is installed
3. Ensure breakpoints are in executable code

## Best Practices

1. **Use Virtual Environment:** Always work in venv
2. **Format Code:** Use autopep8 or black
3. **Write Comments:** Document complex logic
4. **Use Type Hints:** Add type annotations
5. **Test Changes:** Test before committing
6. **Commit Often:** Small, focused commits
7. **Use .gitignore:** Exclude unnecessary files

## Additional Resources

- VS Code Docs: https://code.visualstudio.com/docs
- Python in VS Code: https://code.visualstudio.com/docs/python/python-tutorial
- Flask Documentation: https://flask.palletsprojects.com/
- SQLite Documentation: https://www.sqlite.org/docs.html

---

**Happy Coding! 🚀**
