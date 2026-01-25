"""
Tests for user management API endpoints (admin only)
"""
import pytest


class TestAPIListUsers:
    """Tests for GET /api/admin/users"""

    def test_list_users_admin(self, client, admin_headers):
        """Test admin can list users."""
        response = client.get('/api/admin/users', headers=admin_headers)
        assert response.status_code == 200
        data = response.get_json()
        assert data['success'] is True
        assert 'users' in data

    def test_list_users_staff_forbidden(self, client, staff_headers):
        """Test staff cannot list users."""
        response = client.get('/api/admin/users', headers=staff_headers)
        assert response.status_code == 403

    def test_list_users_unauthenticated(self, client):
        """Test unauthenticated cannot list users."""
        response = client.get('/api/admin/users')
        assert response.status_code == 401


class TestAPICreateUser:
    """Tests for POST /api/admin/users"""

    def test_create_user_admin(self, client, admin_headers):
        """Test admin can create user."""
        response = client.post('/api/admin/users', json={
            'username': 'createduser',
            'email': 'created@test.com',
            'password': 'Created123!',
            'role': 'staff'
        }, headers=admin_headers)
        assert response.status_code == 201
        data = response.get_json()
        assert data['success'] is True
        assert data['user']['username'] == 'createduser'

    def test_create_admin_user(self, client, admin_headers):
        """Test admin can create another admin."""
        response = client.post('/api/admin/users', json={
            'username': 'newadmin',
            'email': 'newadmin@test.com',
            'password': 'Admin123!',
            'role': 'admin'
        }, headers=admin_headers)
        assert response.status_code == 201
        data = response.get_json()
        assert data['user']['role'] == 'admin'

    def test_create_user_staff_forbidden(self, client, staff_headers):
        """Test staff cannot create user."""
        response = client.post('/api/admin/users', json={
            'username': 'shouldfail',
            'email': 'fail@test.com',
            'password': 'Password123!',
            'role': 'staff'
        }, headers=staff_headers)
        assert response.status_code == 403

    def test_create_user_duplicate_username(self, client, admin_headers):
        """Test creating user with duplicate username."""
        response = client.post('/api/admin/users', json={
            'username': 'testadmin',  # Existing user
            'email': 'different@test.com',
            'password': 'Password123!',
            'role': 'staff'
        }, headers=admin_headers)
        assert response.status_code == 409

    def test_create_user_invalid_role(self, client, admin_headers):
        """Test creating user with invalid role."""
        response = client.post('/api/admin/users', json={
            'username': 'newuser',
            'email': 'new@test.com',
            'password': 'Password123!',
            'role': 'superadmin'  # Invalid role
        }, headers=admin_headers)
        assert response.status_code == 400


class TestAPIGetUser:
    """Tests for GET /api/admin/users/<id>"""

    def test_get_user_admin(self, client, admin_headers):
        """Test admin can get user details."""
        response = client.get('/api/admin/users/100', headers=admin_headers)
        assert response.status_code == 200
        data = response.get_json()
        assert data['user']['username'] == 'testadmin'

    def test_get_user_not_found(self, client, admin_headers):
        """Test getting non-existent user."""
        response = client.get('/api/admin/users/99999', headers=admin_headers)
        assert response.status_code == 404

    def test_get_user_staff_forbidden(self, client, staff_headers):
        """Test staff cannot get user details."""
        response = client.get('/api/admin/users/100', headers=staff_headers)
        assert response.status_code == 403


class TestAPIUpdateUser:
    """Tests for PUT /api/admin/users/<id>"""

    def test_update_user_admin(self, client, admin_headers):
        """Test admin can update user."""
        response = client.put('/api/admin/users/101', json={
            'username': 'updatedstaff',
            'email': 'updated@test.com'
        }, headers=admin_headers)
        assert response.status_code == 200
        data = response.get_json()
        assert data['success'] is True

    def test_update_user_change_role(self, client, admin_headers):
        """Test admin can change user role."""
        # First create a user to update
        create_response = client.post('/api/admin/users', json={
            'username': 'rolechange',
            'email': 'rolechange@test.com',
            'password': 'Password123!',
            'role': 'staff'
        }, headers=admin_headers)
        user_id = create_response.get_json()['user']['id']

        # Update role
        response = client.put(f'/api/admin/users/{user_id}', json={
            'role': 'admin'
        }, headers=admin_headers)
        assert response.status_code == 200
        data = response.get_json()
        assert data['user']['role'] == 'admin'

    def test_update_user_staff_forbidden(self, client, staff_headers):
        """Test staff cannot update user."""
        response = client.put('/api/admin/users/101', json={
            'username': 'shouldfail'
        }, headers=staff_headers)
        assert response.status_code == 403

    def test_update_user_not_found(self, client, admin_headers):
        """Test updating non-existent user."""
        response = client.put('/api/admin/users/99999', json={
            'username': 'test'
        }, headers=admin_headers)
        assert response.status_code == 404

    def test_admin_cannot_change_own_role(self, client, admin_headers):
        """Test admin cannot change their own role."""
        response = client.put('/api/admin/users/100', json={
            'role': 'staff'
        }, headers=admin_headers)
        assert response.status_code == 403


class TestAPIDeleteUser:
    """Tests for DELETE /api/admin/users/<id>"""

    def test_delete_user_admin(self, client, admin_headers):
        """Test admin can delete user."""
        # First create a user to delete
        create_response = client.post('/api/admin/users', json={
            'username': 'todelete',
            'email': 'todelete@test.com',
            'password': 'Password123!',
            'role': 'staff'
        }, headers=admin_headers)
        user_id = create_response.get_json()['user']['id']

        # Delete user
        response = client.delete(f'/api/admin/users/{user_id}', headers=admin_headers)
        assert response.status_code == 200

    def test_delete_user_staff_forbidden(self, client, staff_headers):
        """Test staff cannot delete user."""
        response = client.delete('/api/admin/users/101', headers=staff_headers)
        assert response.status_code == 403

    def test_admin_cannot_delete_self(self, client, admin_headers):
        """Test admin cannot delete themselves."""
        response = client.delete('/api/admin/users/100', headers=admin_headers)
        assert response.status_code == 403

    def test_delete_user_not_found(self, client, admin_headers):
        """Test deleting non-existent user."""
        response = client.delete('/api/admin/users/99999', headers=admin_headers)
        assert response.status_code == 404


class TestWebUserManagement:
    """Tests for web-based user management routes"""

    def test_admin_users_page(self, logged_in_admin_client):
        """Test admin can access users page."""
        response = logged_in_admin_client.get('/admin/users')
        assert response.status_code == 200
        assert b'User Management' in response.data

    def test_staff_users_page_forbidden(self, logged_in_staff_client):
        """Test staff cannot access users page."""
        response = logged_in_staff_client.get('/admin/users')
        assert response.status_code == 302  # Redirect

    def test_add_user_page(self, logged_in_admin_client):
        """Test admin can access add user page."""
        response = logged_in_admin_client.get('/admin/users/add')
        assert response.status_code == 200
        assert b'Add New User' in response.data

    def test_edit_user_page(self, logged_in_admin_client):
        """Test admin can access edit user page."""
        response = logged_in_admin_client.get('/admin/users/edit/100')
        assert response.status_code == 200
        assert b'Edit User' in response.data
