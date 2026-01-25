"""
Tests for books API endpoints
"""
import pytest


class TestAPIListBooks:
    """Tests for GET /api/books"""

    def test_list_books_empty(self, client, admin_headers):
        """Test listing books when none exist."""
        response = client.get('/api/books', headers=admin_headers)
        assert response.status_code == 200
        data = response.get_json()
        assert 'books' in data

    def test_list_books_with_data(self, client, admin_headers, sample_book):
        """Test listing books with existing data."""
        response = client.get('/api/books', headers=admin_headers)
        assert response.status_code == 200
        data = response.get_json()
        assert len(data['books']) >= 1

    def test_list_books_pagination(self, client, admin_headers, sample_book):
        """Test book listing pagination."""
        response = client.get('/api/books?page=1&per_page=5', headers=admin_headers)
        assert response.status_code == 200
        data = response.get_json()
        assert 'page' in data
        assert 'per_page' in data

    def test_list_books_unauthenticated(self, client):
        """Test listing books without authentication."""
        response = client.get('/api/books')
        assert response.status_code == 401


class TestAPICreateBook:
    """Tests for POST /api/books"""

    def test_create_book_success(self, client, admin_headers):
        """Test successful book creation."""
        response = client.post('/api/books', json={
            'title': 'New Book',
            'author': 'New Author',
            'isbn': '9780123456789',
            'publisher': 'New Publisher',
            'publication_year': 2024,
            'category': 'Science',
            'total_copies': 3
        }, headers=admin_headers)
        assert response.status_code == 201
        data = response.get_json()
        assert data['success'] is True
        assert data['book']['title'] == 'New Book'

    def test_create_book_missing_title(self, client, admin_headers):
        """Test book creation without title."""
        response = client.post('/api/books', json={
            'author': 'Author',
            'isbn': '9780123456780'
        }, headers=admin_headers)
        assert response.status_code == 400

    def test_create_book_invalid_isbn(self, client, admin_headers):
        """Test book creation with invalid ISBN."""
        response = client.post('/api/books', json={
            'title': 'Book',
            'author': 'Author',
            'isbn': 'invalid'
        }, headers=admin_headers)
        assert response.status_code == 400

    def test_create_book_duplicate_isbn(self, client, admin_headers, sample_book):
        """Test book creation with duplicate ISBN."""
        response = client.post('/api/books', json={
            'title': 'Another Book',
            'author': 'Another Author',
            'isbn': '9781234567890'  # Same as sample_book
        }, headers=admin_headers)
        assert response.status_code == 409

    def test_create_book_staff_allowed(self, client, staff_headers):
        """Test that staff can create books."""
        response = client.post('/api/books', json={
            'title': 'Staff Book',
            'author': 'Staff Author',
            'isbn': '9780111222333',
            'total_copies': 1
        }, headers=staff_headers)
        assert response.status_code == 201


class TestAPIGetBook:
    """Tests for GET /api/books/<id>"""

    def test_get_book_success(self, client, admin_headers, sample_book):
        """Test getting a single book."""
        book_id = sample_book.get('id')
        response = client.get(f'/api/books/{book_id}', headers=admin_headers)
        assert response.status_code == 200
        data = response.get_json()
        assert data['title'] == 'Test Book'

    def test_get_book_not_found(self, client, admin_headers):
        """Test getting a non-existent book."""
        response = client.get('/api/books/99999', headers=admin_headers)
        assert response.status_code == 404


class TestAPIUpdateBook:
    """Tests for PUT /api/books/<id>"""

    def test_update_book_success(self, client, admin_headers, sample_book):
        """Test successful book update."""
        book_id = sample_book.get('id')
        response = client.put(f'/api/books/{book_id}', json={
            'title': 'Updated Title',
            'author': 'Updated Author',
            'isbn': '9781234567890'
        }, headers=admin_headers)
        assert response.status_code == 200
        data = response.get_json()
        assert data['book']['title'] == 'Updated Title'

    def test_update_book_not_found(self, client, admin_headers):
        """Test updating a non-existent book."""
        response = client.put('/api/books/99999', json={
            'title': 'Updated'
        }, headers=admin_headers)
        assert response.status_code == 404


class TestAPIDeleteBook:
    """Tests for DELETE /api/books/<id>"""

    def test_delete_book_success(self, client, admin_headers, sample_book):
        """Test successful book deletion."""
        book_id = sample_book.get('id')
        response = client.delete(f'/api/books/{book_id}', headers=admin_headers)
        assert response.status_code == 200

    def test_delete_book_not_found(self, client, admin_headers):
        """Test deleting a non-existent book."""
        response = client.delete('/api/books/99999', headers=admin_headers)
        assert response.status_code == 404


class TestAPISearchBooks:
    """Tests for GET /api/books/search"""

    def test_search_books(self, client, admin_headers, sample_book):
        """Test searching for books."""
        response = client.get('/api/books/search?q=Test', headers=admin_headers)
        assert response.status_code == 200
        data = response.get_json()
        assert isinstance(data, list)

    def test_search_books_no_results(self, client, admin_headers):
        """Test search with no results."""
        response = client.get('/api/books/search?q=NonExistent', headers=admin_headers)
        assert response.status_code == 200
        data = response.get_json()
        assert data == []
