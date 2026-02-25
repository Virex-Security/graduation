"""Tests for models module - UserManager"""
import pytest
import os
import json
import tempfile
from models import UserManager
from roles import Role


class TestUserManager:
    """Test the UserManager class"""
    
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
    def user_manager(self, temp_storage):
        """Create a UserManager with temporary storage"""
        return UserManager(storage_path=temp_storage)
    
    def test_initialization_creates_default_users(self, temp_storage):
        """Test that UserManager creates default users on init"""
        # Ensure file doesn't exist
        if os.path.exists(temp_storage):
            os.unlink(temp_storage)
        
        manager = UserManager(storage_path=temp_storage)
        
        # Check default admin user exists
        admin = manager.get_user("admin")
        assert admin is not None
        assert admin['role'] == Role.ADMIN
        
        # Check default user exists  
        user = manager.get_user("user")
        assert user is not None
        assert user['role'] == Role.USER
    
    def test_add_user_success(self, user_manager):
        """Test adding a new user successfully"""
        success, message = user_manager.add_user("testuser", "testpass123", Role.USER)
        
        assert success is True
        assert message == "User added successfully"
    
    def test_add_user_duplicate(self, user_manager):
        """Test adding a duplicate user fails"""
        user_manager.add_user("testuser", "testpass123", Role.USER)
        success, message = user_manager.add_user("testuser", "another_pass", Role.USER)
        
        assert success is False
        assert message == "User already exists"
    
    def test_get_user_exists(self, user_manager):
        """Test getting an existing user"""
        user_manager.add_user("testuser", "testpass123", Role.USER)
        
        user = user_manager.get_user("testuser")
        
        assert user is not None
        assert user['username'] == "testuser"
        assert user['role'] == Role.USER
    
    def test_get_user_not_exists(self, user_manager):
        """Test getting a non-existent user returns None"""
        user = user_manager.get_user("nonexistent")
        
        assert user is None
    
    def test_verify_password_correct(self, user_manager):
        """Test verifying correct password"""
        user_manager.add_user("testuser", "testpass123", Role.USER)
        
        user = user_manager.verify_password("testuser", "testpass123")
        
        assert user is not None
        assert user['username'] == "testuser"
    
    def test_verify_password_incorrect(self, user_manager):
        """Test verifying incorrect password returns None"""
        user_manager.add_user("testuser", "testpass123", Role.USER)
        
        user = user_manager.verify_password("testuser", "wrongpassword")
        
        assert user is None
    
    def test_verify_password_nonexistent_user(self, user_manager):
        """Test verifying password for non-existent user returns None"""
        user = user_manager.verify_password("nonexistent", "anypassword")
        
        assert user is None
    
    def test_password_is_hashed(self, user_manager):
        """Test that passwords are stored hashed, not plain text"""
        user_manager.add_user("testuser", "testpass123", Role.USER)
        
        user = user_manager.get_user("testuser")
        
        assert user['password_hash'] != "testpass123"
        assert "pbkdf2:sha256" in user['password_hash'] or "scrypt" in user['password_hash']
    
    def test_persistence(self, temp_storage):
        """Test that users persist across manager instances"""
        # Create first manager and add user
        manager1 = UserManager(storage_path=temp_storage)
        manager1.add_user("persistuser", "persistpass", Role.USER)
        
        # Create second manager with same storage
        manager2 = UserManager(storage_path=temp_storage)
        
        # User should exist in second manager
        user = manager2.get_user("persistuser")
        assert user is not None
        assert user['username'] == "persistuser"
    
    def test_user_has_id(self, user_manager):
        """Test that created users have an ID"""
        user_manager.add_user("testuser", "testpass123", Role.USER)
        
        user = user_manager.get_user("testuser")
        
        assert 'id' in user
        assert isinstance(user['id'], int)
