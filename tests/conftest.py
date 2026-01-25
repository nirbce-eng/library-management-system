"""
Test fixtures for Library Management System
"""
import pytest
import os
import sys
import tempfile
import sqlite3

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import app as flask_app, init_db, get_db, limiter
from werkzeug.security import generate_password_hash


@pytest.fixture
def app():
    """Create and configure a test application instance."""
    # Create a temporary database file
    db_fd, db_path = tempfile.mkstemp(suffix='.db')

    # Disable rate limiting for tests
    limiter.enabled = False

    flask_app.config.update({
        'TESTING': True,
        'WTF_CSRF_ENABLED': False,
        'SECRET_KEY': 'test-secret-key',
    })

    # Override the DATABASE path
    import app as app_module
    original_db = app_module.DATABASE
    app_module.DATABASE = db_path

    # Initialize the database
    with flask_app.app_context():
        init_db()
        # Create test users
        with get_db() as conn:
            cursor = conn.cursor()
            # Create test admin user
            cursor.execute('''
                INSERT OR REPLACE INTO users (id, username, password_hash, email, role)
                VALUES (?, ?, ?, ?, ?)
            ''', (100, 'testadmin', generate_password_hash('Admin123!'), 'testadmin@test.com', 'admin'))
            # Create test staff user
            cursor.execute('''
                INSERT OR REPLACE INTO users (id, username, password_hash, email, role)
                VALUES (?, ?, ?, ?, ?)
            ''', (101, 'teststaff', generate_password_hash('Staff123!'), 'teststaff@test.com', 'staff'))
            conn.commit()

    yield flask_app

    # Cleanup
    app_module.DATABASE = original_db
    os.close(db_fd)
    os.unlink(db_path)


@pytest.fixture
def client(app):
    """Create a test client."""
    return app.test_client()


@pytest.fixture
def admin_token(client):
    """Get an admin auth token."""
    response = client.post('/api/auth/login', json={
        'username': 'testadmin',
        'password': 'Admin123!'
    })
    data = response.get_json()
    return data.get('token')


@pytest.fixture
def staff_token(client):
    """Get a staff auth token."""
    response = client.post('/api/auth/login', json={
        'username': 'teststaff',
        'password': 'Staff123!'
    })
    data = response.get_json()
    return data.get('token')


@pytest.fixture
def admin_headers(admin_token):
    """Get headers with admin auth token."""
    return {'Authorization': f'Bearer {admin_token}'}


@pytest.fixture
def staff_headers(staff_token):
    """Get headers with staff auth token."""
    return {'Authorization': f'Bearer {staff_token}'}


@pytest.fixture
def sample_book(client, admin_headers):
    """Create a sample book for testing."""
    response = client.post('/api/books', json={
        'title': 'Test Book',
        'author': 'Test Author',
        'isbn': '9781234567890',
        'publisher': 'Test Publisher',
        'publication_year': 2024,
        'category': 'Fiction',
        'total_copies': 5
    }, headers=admin_headers)
    data = response.get_json()
    return data.get('book', {})


@pytest.fixture
def sample_member(client, admin_headers):
    """Create a sample member for testing."""
    response = client.post('/api/members', json={
        'name': 'Test Member',
        'email': 'testmember@test.com',
        'phone': '1234567890',
        'address': '123 Test Street'
    }, headers=admin_headers)
    data = response.get_json()
    return data.get('member', {})


@pytest.fixture
def logged_in_admin_client(client):
    """Return a client that is logged in as admin."""
    client.post('/login', data={
        'username': 'testadmin',
        'password': 'Admin123!'
    })
    return client


@pytest.fixture
def logged_in_staff_client(client):
    """Return a client that is logged in as staff."""
    client.post('/login', data={
        'username': 'teststaff',
        'password': 'Staff123!'
    })
    return client
