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
