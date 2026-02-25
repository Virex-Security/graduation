"""Tests for decorators module"""
import pytest
import jwt
from datetime import datetime, timedelta
from flask import Flask, jsonify
from decorators import token_required, require_role, admin_required
from models import UserManager
from roles import Role
import tempfile
import os


class TestDecorators:
    """Test authentication and authorization decorators"""
    
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
    def app(self, temp_storage, monkeypatch):
        """Create Flask app for testing with routes"""
        app = Flask(__name__)
        app.config['SECRET_KEY'] = 'test-secret-key-long-enough-for-hs256'
        app.config['TESTING'] = True
        
        # Setup UserManager - patch in both models and decorators modules
        import models
        import decorators
        test_manager = UserManager(storage_path=temp_storage)
        test_manager.add_user("testadmin", "adminpass123", Role.ADMIN)
        test_manager.add_user("testuser", "userpass123", Role.USER)
        monkeypatch.setattr(models, 'user_manager', test_manager)
        monkeypatch.setattr(decorators, 'user_manager', test_manager)
        
        # Define test routes
        @app.route('/api/protected')
        @token_required
        def protected_api(current_user):
            return jsonify({'user': current_user['username']})
        
        @app.route('/page/protected')
        @token_required
        def protected_page(current_user):
            return f"Welcome {current_user['username']}"
        
        @app.route('/api/admin-only')
        @admin_required
        def admin_only_api(current_user):
            return jsonify({'admin': current_user['username']})
        
        @app.route('/api/user-role')
        @require_role(Role.USER)
        def user_role_api(current_user):
            return jsonify({'user': current_user['username']})
        
        @app.route('/login')
        def login_page():
            return "Login Page"
        
        return app
    
    @pytest.fixture
    def client(self, app):
        """Create test client"""
        return app.test_client()
    
    def create_token(self, app, username, role, expired=False):
        """Helper to create JWT tokens for testing"""
        if expired:
            exp = datetime.utcnow() - timedelta(hours=1)
        else:
            exp = datetime.utcnow() + timedelta(hours=24)
        
        return jwt.encode({
            'user': username,
            'role': role,
            'exp': exp
        }, app.config['SECRET_KEY'], algorithm="HS256")
    
    # token_required tests
    def test_token_required_no_token_api(self, client):
        """Test API route without token returns 401"""
        response = client.get('/api/protected')
        
        assert response.status_code == 401
        assert b'Token is missing' in response.data
    
    def test_token_required_no_token_page_redirects(self, client):
        """Test page route without token redirects to login"""
        response = client.get('/page/protected')
        
        assert response.status_code == 302
        assert '/login' in response.headers['Location']
    
    def test_token_required_valid_token(self, app, client):
        """Test route with valid token succeeds"""
        token = self.create_token(app, 'testuser', Role.USER)
        client.set_cookie('auth_token', token)
        
        response = client.get('/api/protected')
        
        assert response.status_code == 200
        assert b'testuser' in response.data
    
    def test_token_required_expired_token_api(self, app, client):
        """Test API route with expired token returns 401"""
        token = self.create_token(app, 'testuser', Role.USER, expired=True)
        client.set_cookie('auth_token', token)
        
        response = client.get('/api/protected')
        
        assert response.status_code == 401
        assert b'Token is invalid' in response.data
    
    def test_token_required_invalid_token(self, client):
        """Test route with invalid token returns 401"""
        client.set_cookie('auth_token', 'invalid-token-string')
        
        response = client.get('/api/protected')
        
        assert response.status_code == 401
    
    def test_token_required_nonexistent_user(self, app, client):
        """Test token for non-existent user returns 401"""
        token = self.create_token(app, 'deleted_user', Role.USER)
        client.set_cookie('auth_token', token)
        
        response = client.get('/api/protected')
        
        assert response.status_code == 401
        assert b'User not found' in response.data
    
    # admin_required tests
    def test_admin_required_with_admin(self, app, client):
        """Test admin route with admin user succeeds"""
        token = self.create_token(app, 'testadmin', Role.ADMIN)
        client.set_cookie('auth_token', token)
        
        response = client.get('/api/admin-only')
        
        assert response.status_code == 200
        assert b'testadmin' in response.data
    
    def test_admin_required_with_user(self, app, client):
        """Test admin route with regular user returns 403"""
        token = self.create_token(app, 'testuser', Role.USER)
        client.set_cookie('auth_token', token)
        
        response = client.get('/api/admin-only')
        
        assert response.status_code == 403
    
    # require_role tests
    def test_require_role_matching_role(self, app, client):
        """Test route with matching role succeeds"""
        token = self.create_token(app, 'testuser', Role.USER)
        client.set_cookie('auth_token', token)
        
        response = client.get('/api/user-role')
        
        assert response.status_code == 200
    
    def test_require_role_admin_can_access_any(self, app, client):
        """Test admin can access any role-required route"""
        token = self.create_token(app, 'testadmin', Role.ADMIN)
        client.set_cookie('auth_token', token)
        
        response = client.get('/api/user-role')
        
        assert response.status_code == 200
