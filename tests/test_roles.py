"""Unit tests for roles.py module."""
import pytest


class TestRole:
    """Tests for the Role class."""

    def test_admin_constant(self):
        """Role.ADMIN should be 'admin'."""
        from roles import Role
        
        assert Role.ADMIN == "admin"

    def test_user_constant(self):
        """Role.USER should be 'user'."""
        from roles import Role
        
        assert Role.USER == "user"

    def test_all_roles_returns_list(self):
        """Role.all_roles() should return a list."""
        from roles import Role
        
        result = Role.all_roles()
        assert isinstance(result, list)

    def test_all_roles_contains_admin(self):
        """Role.all_roles() should contain the admin role."""
        from roles import Role
        
        result = Role.all_roles()
        assert Role.ADMIN in result

    def test_all_roles_contains_user(self):
        """Role.all_roles() should contain the user role."""
        from roles import Role
        
        result = Role.all_roles()
        assert Role.USER in result

    def test_all_roles_length(self):
        """Role.all_roles() should return exactly 2 roles."""
        from roles import Role
        
        result = Role.all_roles()
        assert len(result) == 2

    def test_all_roles_order(self):
        """Role.all_roles() should return roles in expected order."""
        from roles import Role
        
        result = Role.all_roles()
        assert result == [Role.ADMIN, Role.USER]

    def test_role_constants_are_strings(self):
        """Role constants should be strings."""
        from roles import Role
        
        assert isinstance(Role.ADMIN, str)
        assert isinstance(Role.USER, str)

    def test_role_constants_are_unique(self):
        """Role constants should be unique values."""
        from roles import Role
        
        assert Role.ADMIN != Role.USER
