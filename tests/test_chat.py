"""
Tests for chat API endpoints
"""
import pytest


class TestAPIChatUsers:
    """Tests for GET /api/chat/users"""

    def test_get_chat_users_admin(self, client, admin_headers):
        """Test admin can get chat users."""
        response = client.get('/api/chat/users', headers=admin_headers)
        assert response.status_code == 200
        data = response.get_json()
        assert 'users' in data

    def test_get_chat_users_staff(self, client, staff_headers):
        """Test staff can get chat users."""
        response = client.get('/api/chat/users', headers=staff_headers)
        assert response.status_code == 200

    def test_get_chat_users_unauthenticated(self, client):
        """Test unauthenticated cannot get chat users."""
        response = client.get('/api/chat/users')
        assert response.status_code == 401


class TestAPIChatConversations:
    """Tests for GET /api/chat/conversations"""

    def test_get_conversations_admin(self, client, admin_headers):
        """Test admin can get conversations."""
        response = client.get('/api/chat/conversations', headers=admin_headers)
        assert response.status_code == 200
        data = response.get_json()
        assert 'conversations' in data

    def test_get_conversations_staff(self, client, staff_headers):
        """Test staff can get conversations."""
        response = client.get('/api/chat/conversations', headers=staff_headers)
        assert response.status_code == 200


class TestAPISendMessage:
    """Tests for POST /api/chat/messages"""

    def test_send_message_success(self, client, admin_headers):
        """Test sending a message."""
        response = client.post('/api/chat/messages', json={
            'receiver_id': 101,  # teststaff
            'message': 'Hello from test!'
        }, headers=admin_headers)
        assert response.status_code == 201
        data = response.get_json()
        assert data['success'] is True

    def test_send_message_to_self(self, client, admin_headers):
        """Test sending message to self (allowed by API)."""
        response = client.post('/api/chat/messages', json={
            'receiver_id': 100,  # testadmin (self)
            'message': 'Hello to myself'
        }, headers=admin_headers)
        # API allows sending to self
        assert response.status_code == 201

    def test_send_message_missing_receiver(self, client, admin_headers):
        """Test sending message without receiver."""
        response = client.post('/api/chat/messages', json={
            'message': 'Hello!'
        }, headers=admin_headers)
        assert response.status_code == 400

    def test_send_message_empty(self, client, admin_headers):
        """Test sending empty message."""
        response = client.post('/api/chat/messages', json={
            'receiver_id': 101,
            'message': ''
        }, headers=admin_headers)
        assert response.status_code == 400


class TestAPIGetMessages:
    """Tests for GET /api/chat/messages/<user_id>"""

    def test_get_messages_success(self, client, admin_headers):
        """Test getting messages with a user."""
        # First send a message
        client.post('/api/chat/messages', json={
            'receiver_id': 101,
            'message': 'Test message'
        }, headers=admin_headers)

        # Get messages
        response = client.get('/api/chat/messages/101', headers=admin_headers)
        assert response.status_code == 200
        data = response.get_json()
        assert 'messages' in data

    def test_get_messages_with_nonexistent_user(self, client, admin_headers):
        """Test getting messages with non-existent user."""
        response = client.get('/api/chat/messages/99999', headers=admin_headers)
        assert response.status_code == 404  # User not found


class TestAPIUnreadCount:
    """Tests for GET /api/chat/unread-count"""

    def test_get_unread_count(self, client, admin_headers):
        """Test getting unread message count."""
        response = client.get('/api/chat/unread-count', headers=admin_headers)
        assert response.status_code == 200
        data = response.get_json()
        assert 'unread_count' in data
