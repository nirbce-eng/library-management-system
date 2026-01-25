"""
Tests for members API endpoints
"""
import pytest


class TestAPIListMembers:
    """Tests for GET /api/members"""

    def test_list_members_empty(self, client, admin_headers):
        """Test listing members when none exist."""
        response = client.get('/api/members', headers=admin_headers)
        assert response.status_code == 200
        data = response.get_json()
        assert 'members' in data

    def test_list_members_with_data(self, client, admin_headers, sample_member):
        """Test listing members with existing data."""
        response = client.get('/api/members', headers=admin_headers)
        assert response.status_code == 200
        data = response.get_json()
        assert len(data['members']) >= 1

    def test_list_members_unauthenticated(self, client):
        """Test listing members without authentication."""
        response = client.get('/api/members')
        assert response.status_code == 401


class TestAPICreateMember:
    """Tests for POST /api/members"""

    def test_create_member_success(self, client, admin_headers):
        """Test successful member creation."""
        response = client.post('/api/members', json={
            'name': 'John Doe',
            'email': 'john@test.com',
            'phone': '9876543210',
            'address': '456 Main St'
        }, headers=admin_headers)
        assert response.status_code == 201
        data = response.get_json()
        assert data['success'] is True
        assert data['member']['name'] == 'John Doe'

    def test_create_member_missing_name(self, client, admin_headers):
        """Test member creation without name."""
        response = client.post('/api/members', json={
            'email': 'test@test.com'
        }, headers=admin_headers)
        assert response.status_code == 400

    def test_create_member_invalid_email(self, client, admin_headers):
        """Test member creation with invalid email."""
        response = client.post('/api/members', json={
            'name': 'Test Name',
            'email': 'invalid-email'
        }, headers=admin_headers)
        assert response.status_code == 400

    def test_create_member_duplicate_email(self, client, admin_headers, sample_member):
        """Test member creation with duplicate email."""
        response = client.post('/api/members', json={
            'name': 'Another Person',
            'email': 'testmember@test.com'  # Same as sample_member
        }, headers=admin_headers)
        assert response.status_code == 409


class TestAPIGetMember:
    """Tests for GET /api/members/<id>"""

    def test_get_member_success(self, client, admin_headers, sample_member):
        """Test getting a single member."""
        member_id = sample_member.get('id')
        response = client.get(f'/api/members/{member_id}', headers=admin_headers)
        assert response.status_code == 200
        data = response.get_json()
        assert data['name'] == 'Test Member'

    def test_get_member_not_found(self, client, admin_headers):
        """Test getting a non-existent member."""
        response = client.get('/api/members/99999', headers=admin_headers)
        assert response.status_code == 404


class TestAPIUpdateMember:
    """Tests for PUT /api/members/<id>"""

    def test_update_member_success(self, client, admin_headers, sample_member):
        """Test successful member update."""
        member_id = sample_member.get('id')
        response = client.put(f'/api/members/{member_id}', json={
            'name': 'Updated Name',
            'email': 'updated@test.com'
        }, headers=admin_headers)
        assert response.status_code == 200
        data = response.get_json()
        assert data['member']['name'] == 'Updated Name'

    def test_update_member_not_found(self, client, admin_headers):
        """Test updating a non-existent member."""
        response = client.put('/api/members/99999', json={
            'name': 'Updated'
        }, headers=admin_headers)
        assert response.status_code == 404


class TestAPIDeleteMember:
    """Tests for DELETE /api/members/<id>"""

    def test_delete_member_success(self, client, admin_headers, sample_member):
        """Test successful member deletion."""
        member_id = sample_member.get('id')
        response = client.delete(f'/api/members/{member_id}', headers=admin_headers)
        assert response.status_code == 200

    def test_delete_member_not_found(self, client, admin_headers):
        """Test deleting a non-existent member."""
        response = client.delete('/api/members/99999', headers=admin_headers)
        assert response.status_code == 404


class TestAPISearchMembers:
    """Tests for GET /api/members/search"""

    def test_search_members(self, client, admin_headers, sample_member):
        """Test searching for members."""
        response = client.get('/api/members/search?q=Test', headers=admin_headers)
        assert response.status_code == 200
        data = response.get_json()
        assert isinstance(data, list)

    def test_search_members_no_results(self, client, admin_headers):
        """Test search with no results."""
        response = client.get('/api/members/search?q=NonExistent', headers=admin_headers)
        assert response.status_code == 200
        data = response.get_json()
        assert data == []
