"""
Tests for authentication API endpoints
"""
import pytest


class TestAPILogin:
    """Tests for POST /api/auth/login"""

    def test_login_success(self, client):
        """Test successful login with valid credentials."""
        response = client.post('/api/auth/login', json={
            'username': 'testadmin',
            'password': 'Admin123!'
        })
        assert response.status_code == 200
        data = response.get_json()
        assert data['success'] is True
        assert 'token' in data
        assert data['user']['username'] == 'testadmin'
        assert data['user']['role'] == 'admin'

    def test_login_invalid_password(self, client):
        """Test login with wrong password."""
        response = client.post('/api/auth/login', json={
            'username': 'testadmin',
            'password': 'wrongpassword'
        })
        assert response.status_code == 401
        data = response.get_json()
        assert 'error' in data

    def test_login_invalid_username(self, client):
        """Test login with non-existent user."""
        response = client.post('/api/auth/login', json={
            'username': 'nonexistent',
            'password': 'password123'
        })
        assert response.status_code == 401

    def test_login_missing_credentials(self, client):
        """Test login without credentials."""
        response = client.post('/api/auth/login', json={})
        assert response.status_code == 400


class TestAPIRegister:
    """Tests for POST /api/auth/register"""

    def test_register_success(self, client):
        """Test successful user registration."""
        response = client.post('/api/auth/register', json={
            'username': 'newuser',
            'email': 'newuser@test.com',
            'password': 'NewPass123!'
        })
        assert response.status_code == 201
        data = response.get_json()
        assert data['success'] is True
        assert data['user']['username'] == 'newuser'
        assert data['user']['role'] == 'staff'

    def test_register_duplicate_username(self, client):
        """Test registration with existing username."""
        response = client.post('/api/auth/register', json={
            'username': 'testadmin',
            'email': 'different@test.com',
            'password': 'Password123!'
        })
        assert response.status_code == 409

    def test_register_invalid_email(self, client):
        """Test registration with invalid email."""
        response = client.post('/api/auth/register', json={
            'username': 'validuser',
            'email': 'invalid-email',
            'password': 'Password123!'
        })
        assert response.status_code == 400

    def test_register_weak_password(self, client):
        """Test registration with weak password."""
        response = client.post('/api/auth/register', json={
            'username': 'validuser',
            'email': 'valid@test.com',
            'password': '123'
        })
        assert response.status_code == 400

    def test_register_short_username(self, client):
        """Test registration with too short username."""
        response = client.post('/api/auth/register', json={
            'username': 'ab',
            'email': 'valid@test.com',
            'password': 'Password123!'
        })
        assert response.status_code == 400


class TestAPILogout:
    """Tests for POST /api/auth/logout"""

    def test_logout_success(self, client, admin_headers):
        """Test successful logout."""
        response = client.post('/api/auth/logout', headers=admin_headers)
        assert response.status_code == 200
        data = response.get_json()
        assert data['success'] is True

    def test_logout_unauthenticated(self, client):
        """Test logout without authentication."""
        response = client.post('/api/auth/logout')
        assert response.status_code == 401


class TestAPIGetCurrentUser:
    """Tests for GET /api/auth/me"""

    def test_get_current_user_admin(self, client, admin_headers):
        """Test getting current admin user info."""
        response = client.get('/api/auth/me', headers=admin_headers)
        assert response.status_code == 200
        data = response.get_json()
        assert data['username'] == 'testadmin'
        assert data['role'] == 'admin'

    def test_get_current_user_staff(self, client, staff_headers):
        """Test getting current staff user info."""
        response = client.get('/api/auth/me', headers=staff_headers)
        assert response.status_code == 200
        data = response.get_json()
        assert data['username'] == 'teststaff'
        assert data['role'] == 'staff'

    def test_get_current_user_unauthenticated(self, client):
        """Test getting current user without authentication."""
        response = client.get('/api/auth/me')
        assert response.status_code == 401


class TestAPIChangePassword:
    """Tests for POST /api/auth/change-password"""

    def test_change_password_success(self, client, admin_headers):
        """Test successful password change."""
        response = client.post('/api/auth/change-password', json={
            'current_password': 'Admin123!',
            'new_password': 'NewAdmin123!'
        }, headers=admin_headers)
        assert response.status_code == 200
        data = response.get_json()
        assert data['success'] is True

    def test_change_password_wrong_current(self, client, admin_headers):
        """Test password change with wrong current password."""
        response = client.post('/api/auth/change-password', json={
            'current_password': 'WrongPassword!',
            'new_password': 'NewAdmin123!'
        }, headers=admin_headers)
        assert response.status_code == 401

    def test_change_password_weak_new(self, client, admin_headers):
        """Test password change with weak new password."""
        response = client.post('/api/auth/change-password', json={
            'current_password': 'Admin123!',
            'new_password': '123'
        }, headers=admin_headers)
        assert response.status_code == 400

    def test_change_password_unauthenticated(self, client):
        """Test password change without authentication."""
        response = client.post('/api/auth/change-password', json={
            'current_password': 'old',
            'new_password': 'new'
        })
        assert response.status_code == 401


class TestAPIForgotPassword:
    """Tests for POST /api/auth/forgot-password"""

    def test_forgot_password_success(self, client):
        """Test successful password reset."""
        response = client.post('/api/auth/forgot-password', json={
            'username': 'teststaff',
            'email': 'teststaff@test.com',
            'new_password': 'ResetPass123!'
        })
        assert response.status_code == 200
        data = response.get_json()
        assert data['success'] is True

    def test_forgot_password_wrong_email(self, client):
        """Test password reset with wrong email."""
        response = client.post('/api/auth/forgot-password', json={
            'username': 'teststaff',
            'email': 'wrong@test.com',
            'new_password': 'ResetPass123!'
        })
        assert response.status_code == 404

    def test_forgot_password_wrong_username(self, client):
        """Test password reset with wrong username."""
        response = client.post('/api/auth/forgot-password', json={
            'username': 'wronguser',
            'email': 'teststaff@test.com',
            'new_password': 'ResetPass123!'
        })
        assert response.status_code == 404

    def test_forgot_password_weak_password(self, client):
        """Test password reset with weak password."""
        response = client.post('/api/auth/forgot-password', json={
            'username': 'teststaff',
            'email': 'teststaff@test.com',
            'new_password': '123'
        })
        assert response.status_code == 400
