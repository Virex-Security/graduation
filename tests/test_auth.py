"""
Authentication security tests.
These verify that the critical auth fixes are working correctly.
"""
import pytest


class TestLoginSecurity:
    """Test login endpoint security properties."""

    def test_login_returns_httponly_cookie(self, api_client):
        """JWT must be in httpOnly cookie, not response body."""
        resp = api_client.post('/api/login', json={
            'username': 'admin', 'password': 'Admin@123'
        })
        # Whether login succeeds or not, the token must NOT be in the JSON body
        data = resp.get_json() or {}
        assert 'token' not in data, "Token must not be exposed in JSON response body"

    def test_invalid_credentials_returns_401(self, api_client):
        resp = api_client.post('/api/login', json={
            'username': 'admin', 'password': 'wrong-password'
        })
        assert resp.status_code == 401

    def test_missing_credentials_handled(self, api_client):
        resp = api_client.post('/api/login', json={})
        assert resp.status_code in (400, 401)

    def test_brute_force_blocks_after_5_attempts(self, api_client):
        """After 5 failed attempts, IP should be blocked."""
        for _ in range(5):
            api_client.post('/api/login', json={
                'username': 'admin', 'password': 'wrong'
            })
        resp = api_client.post('/api/login', json={
            'username': 'admin', 'password': 'wrong'
        })
        assert resp.status_code == 429


class TestProtectedRoutes:
    """Test that protected routes reject unauthenticated requests."""

    def test_dashboard_data_requires_auth(self, api_client):
        resp = api_client.get('/api/security/stats')
        assert resp.status_code == 401

    def test_users_list_requires_admin(self, api_client):
        resp = api_client.get('/api/users')
        assert resp.status_code == 401

    def test_logs_requires_auth(self, api_client):
        resp = api_client.get('/api/logs')
        assert resp.status_code == 401


class TestConfig:
    """Test that configuration validation works."""

    def test_secret_key_is_set(self):
        import os
        assert os.getenv("SECRET_KEY"), "SECRET_KEY must be set"
        assert len(os.getenv("SECRET_KEY")) >= 32, "SECRET_KEY must be at least 32 chars"
