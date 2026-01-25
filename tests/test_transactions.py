"""
Tests for transactions API endpoints
"""
import pytest
from datetime import datetime, timedelta


class TestAPIListTransactions:
    """Tests for GET /api/transactions"""

    def test_list_transactions_empty(self, client, admin_headers):
        """Test listing transactions when none exist."""
        response = client.get('/api/transactions', headers=admin_headers)
        assert response.status_code == 200
        data = response.get_json()
        assert 'transactions' in data

    def test_list_transactions_unauthenticated(self, client):
        """Test listing transactions without authentication."""
        response = client.get('/api/transactions')
        assert response.status_code == 401


class TestAPIIssueBook:
    """Tests for POST /api/transactions/issue"""

    def test_issue_book_success(self, client, admin_headers, sample_book, sample_member):
        """Test successful book issuance."""
        book_id = sample_book.get('id')
        member_id = sample_member.get('id')
        issue_date = datetime.now().strftime('%Y-%m-%d')

        response = client.post('/api/transactions/issue', json={
            'book_id': book_id,
            'member_id': member_id,
            'issue_date': issue_date,
            'due_days': 14
        }, headers=admin_headers)
        assert response.status_code == 201
        data = response.get_json()
        assert data['success'] is True

    def test_issue_book_invalid_book(self, client, admin_headers, sample_member):
        """Test issuing a non-existent book."""
        member_id = sample_member.get('id')
        issue_date = datetime.now().strftime('%Y-%m-%d')

        response = client.post('/api/transactions/issue', json={
            'book_id': 99999,
            'member_id': member_id,
            'issue_date': issue_date
        }, headers=admin_headers)
        assert response.status_code == 404

    def test_issue_book_invalid_member(self, client, admin_headers, sample_book):
        """Test issuing to a non-existent member."""
        book_id = sample_book.get('id')
        issue_date = datetime.now().strftime('%Y-%m-%d')

        response = client.post('/api/transactions/issue', json={
            'book_id': book_id,
            'member_id': 99999,
            'issue_date': issue_date
        }, headers=admin_headers)
        assert response.status_code == 404

    def test_issue_book_missing_fields(self, client, admin_headers):
        """Test issuing without required fields."""
        response = client.post('/api/transactions/issue', json={
            'book_id': 1
        }, headers=admin_headers)
        assert response.status_code == 400


class TestAPIReturnBook:
    """Tests for POST /api/transactions/<id>/return"""

    def test_return_book_success(self, client, admin_headers, sample_book, sample_member):
        """Test successful book return."""
        # First issue a book
        book_id = sample_book.get('id')
        member_id = sample_member.get('id')
        issue_date = datetime.now().strftime('%Y-%m-%d')

        issue_response = client.post('/api/transactions/issue', json={
            'book_id': book_id,
            'member_id': member_id,
            'issue_date': issue_date
        }, headers=admin_headers)
        transaction_id = issue_response.get_json().get('transaction', {}).get('id')

        # Return the book
        return_date = datetime.now().strftime('%Y-%m-%d')
        response = client.post(f'/api/transactions/{transaction_id}/return',
                               json={'return_date': return_date},
                               headers=admin_headers)
        assert response.status_code == 200
        data = response.get_json()
        assert data['success'] is True

    def test_return_book_not_found(self, client, admin_headers):
        """Test returning a non-existent transaction."""
        return_date = datetime.now().strftime('%Y-%m-%d')
        response = client.post('/api/transactions/99999/return',
                               json={'return_date': return_date},
                               headers=admin_headers)
        assert response.status_code == 404


class TestAPIGetTransaction:
    """Tests for GET /api/transactions/<id>"""

    def test_get_transaction_success(self, client, admin_headers, sample_book, sample_member):
        """Test getting a single transaction."""
        # First issue a book
        book_id = sample_book.get('id')
        member_id = sample_member.get('id')
        issue_date = datetime.now().strftime('%Y-%m-%d')

        issue_response = client.post('/api/transactions/issue', json={
            'book_id': book_id,
            'member_id': member_id,
            'issue_date': issue_date
        }, headers=admin_headers)
        transaction_id = issue_response.get_json().get('transaction', {}).get('id')

        # Get the transaction
        response = client.get(f'/api/transactions/{transaction_id}', headers=admin_headers)
        assert response.status_code == 200

    def test_get_transaction_not_found(self, client, admin_headers):
        """Test getting a non-existent transaction."""
        response = client.get('/api/transactions/99999', headers=admin_headers)
        assert response.status_code == 404
