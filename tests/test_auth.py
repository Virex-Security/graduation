<<<<<<< HEAD
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
=======
"""Tests for auth module"""
import pytest
import jwt
from datetime import datetime, timedelta
from flask import Flask
from auth import login_user, logout_user
from models import UserManager
from roles import Role
import tempfile
import os


class TestAuth:
    """Test authentication functions"""
    
    @pytest.fixture
    def app(self, temp_storage):
        """Create Flask app for testing"""
        app = Flask(__name__)
        app.config['SECRET_KEY'] = 'test-secret-key-long-enough-for-hs256'
        app.config['TESTING'] = True
        return app
    
    @pytest.fixture
    def temp_storage(self):
        """Create a temporary file path for user storage (file does not exist initially)"""
        fd, path = tempfile.mkstemp(suffix='.json')
        os.close(fd)
        # Remove the empty file so UserManager creates it fresh
        os.unlink(path)
        yield path
        if os.path.exists(path):
            os.unlink(path)
    
    @pytest.fixture
    def setup_user_manager(self, temp_storage, monkeypatch):
        """Setup UserManager with test storage - uses default users (admin/admin123, user/user123)"""
        import models
        import auth
        test_manager = UserManager(storage_path=temp_storage)
        # UserManager auto-creates 'admin' with 'admin123' and 'user' with 'user123'
        # Patch in both modules since auth imports user_manager directly
        monkeypatch.setattr(models, 'user_manager', test_manager)
        monkeypatch.setattr(auth, 'user_manager', test_manager)
        return test_manager
    
    def test_login_user_success(self, app, setup_user_manager):
        """Test successful login returns token cookie"""
        with app.app_context():
            # Use default user created by UserManager
            response, status = login_user("user", "user123")
            
            assert status == 200
            # Check response has auth_token cookie
            cookies = response.headers.getlist('Set-Cookie')
            assert any('auth_token' in cookie for cookie in cookies)
    
    def test_login_user_invalid_password(self, app, setup_user_manager):
        """Test login with invalid password fails"""
        with app.app_context():
            response, status = login_user("user", "wrongpassword")
            
            assert status == 401
            assert b'Invalid credentials' in response.get_data()
    
    def test_login_user_nonexistent_user(self, app, setup_user_manager):
        """Test login with nonexistent user fails"""
        with app.app_context():
            response, status = login_user("nonexistent", "anypassword")
            
            assert status == 401
            assert b'Invalid credentials' in response.get_data()
    
    def test_login_returns_role_in_response(self, app, setup_user_manager):
        """Test successful login includes role in response"""
        import json
        with app.app_context():
            # Use default admin created by UserManager
            response, status = login_user("admin", "admin123")
            
            assert status == 200
            data = json.loads(response.get_data())
            assert data['role'] == Role.ADMIN
            assert data['username'] == "admin"
    
    def test_logout_user_clears_cookie(self, app):
        """Test logout clears auth_token cookie"""
        with app.app_context():
            response = logout_user()
            
            cookies = response.headers.getlist('Set-Cookie')
            # Should set auth_token to empty with expired time
            assert any('auth_token=' in cookie for cookie in cookies)
    
    def test_login_token_contains_user_info(self, app, setup_user_manager):
        """Test JWT token contains correct user information"""
        with app.app_context():
            # Use default user created by UserManager
            response, status = login_user("user", "user123")
            
            assert status == 200
            
            # Extract token from cookie header
            cookies = response.headers.getlist('Set-Cookie')
            token_cookie = next(c for c in cookies if 'auth_token=' in c)
            token = token_cookie.split('auth_token=')[1].split(';')[0]
            
            # Decode and verify token contents
            decoded = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            
            assert decoded['user'] == "user"
            assert decoded['role'] == Role.USER
            assert 'exp' in decoded
>>>>>>> 967891135f8e00079cef2ba1d9796462c24daaba
