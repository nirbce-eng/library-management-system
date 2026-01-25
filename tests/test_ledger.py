"""
Tests for ledger API endpoints (admin only)
"""
import pytest


class TestAPIGetFines:
    """Tests for GET /api/ledger/fines"""

    def test_get_fines_admin(self, client, admin_headers):
        """Test admin can get fines."""
        response = client.get('/api/ledger/fines', headers=admin_headers)
        assert response.status_code == 200
        data = response.get_json()
        assert data['success'] is True
        assert 'fines' in data
        assert 'total_fines' in data

    def test_get_fines_staff_forbidden(self, client, staff_headers):
        """Test staff cannot get fines."""
        response = client.get('/api/ledger/fines', headers=staff_headers)
        assert response.status_code == 403

    def test_get_fines_unauthenticated(self, client):
        """Test unauthenticated cannot get fines."""
        response = client.get('/api/ledger/fines')
        assert response.status_code == 401


class TestAPIGetFinesSummary:
    """Tests for GET /api/ledger/summary"""

    def test_get_fines_summary_admin(self, client, admin_headers):
        """Test admin can get fines summary."""
        response = client.get('/api/ledger/summary', headers=admin_headers)
        assert response.status_code == 200
        data = response.get_json()
        assert data['success'] is True
        assert 'today_fines' in data
        assert 'week_fines' in data
        assert 'month_fines' in data
        assert 'total_fines' in data

    def test_get_fines_summary_staff_forbidden(self, client, staff_headers):
        """Test staff cannot get fines summary."""
        response = client.get('/api/ledger/summary', headers=staff_headers)
        assert response.status_code == 403


class TestWebLedger:
    """Tests for web-based ledger routes"""

    def test_ledger_page_admin(self, logged_in_admin_client):
        """Test admin can access ledger page."""
        response = logged_in_admin_client.get('/ledger')
        assert response.status_code == 200
        assert b'Fines Ledger' in response.data

    def test_ledger_page_staff_forbidden(self, logged_in_staff_client):
        """Test staff cannot access ledger page."""
        response = logged_in_staff_client.get('/ledger')
        assert response.status_code == 302  # Redirect
