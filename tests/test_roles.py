"""Tests for roles module"""
import pytest
from roles import Role


class TestRole:
    """Test the Role class"""
    
    def test_admin_constant(self):
        """Test ADMIN role constant is defined correctly"""
        assert Role.ADMIN == "admin"
    
    def test_user_constant(self):
        """Test USER role constant is defined correctly"""
        assert Role.USER == "user"
    
    def test_all_roles_returns_list(self):
        """Test all_roles returns a list"""
        result = Role.all_roles()
        assert isinstance(result, list)
    
    def test_all_roles_contains_admin(self):
        """Test all_roles contains ADMIN role"""
        result = Role.all_roles()
        assert Role.ADMIN in result
    
    def test_all_roles_contains_user(self):
        """Test all_roles contains USER role"""
        result = Role.all_roles()
        assert Role.USER in result
    
    def test_all_roles_count(self):
        """Test all_roles returns expected number of roles"""
        result = Role.all_roles()
        assert len(result) == 2
