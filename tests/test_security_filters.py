"""Unit tests for security/filters.py module."""
import pytest
from unittest.mock import MagicMock


class TestIsTrivial:
    """Tests for the is_trivial() function."""

    def test_health_endpoints_are_trivial(self):
        """Health check endpoints should be trivial."""
        from security.filters import is_trivial
        
        for path in ['/health', '/api/health', '/status', '/ping']:
            req = MagicMock()
            req.path = path
            assert is_trivial(req) is True, f"{path} should be trivial"

    def test_dashboard_internal_apis_are_trivial(self):
        """Dashboard internal API calls should be trivial."""
        from security.filters import is_trivial
        
        paths = [
            '/api/dashboard/stats',
            '/api/dashboard/widgets',
            '/api/dashboard/config',
        ]
        for path in paths:
            req = MagicMock()
            req.path = path
            assert is_trivial(req) is True, f"{path} should be trivial"

    def test_static_files_are_trivial(self):
        """Static file requests should be trivial."""
        from security.filters import is_trivial
        
        static_files = [
            '/static/app.js',
            '/styles/main.css',
            '/images/logo.png',
            '/images/photo.jpg',
            '/favicon.ico',
            '/icons/icon.svg',
            '/fonts/font.woff',
            '/fonts/font.ttf',
        ]
        for path in static_files:
            req = MagicMock()
            req.path = path
            assert is_trivial(req) is True, f"{path} should be trivial"

    def test_security_stats_endpoint_is_trivial(self):
        """Security stats endpoint (monitoring) should be trivial."""
        from security.filters import is_trivial
        
        req = MagicMock()
        req.path = '/api/security/stats'
        assert is_trivial(req) is True

    def test_api_endpoints_are_not_trivial(self):
        """Regular API endpoints should not be trivial."""
        from security.filters import is_trivial
        
        non_trivial_paths = [
            '/api/login',
            '/api/users',
            '/api/data',
            '/api/transactions',
            '/api/admin',
        ]
        for path in non_trivial_paths:
            req = MagicMock()
            req.path = path
            assert is_trivial(req) is False, f"{path} should NOT be trivial"

    def test_page_requests_are_not_trivial(self):
        """HTML page requests should not be trivial."""
        from security.filters import is_trivial
        
        req = MagicMock()
        req.path = '/login'
        assert is_trivial(req) is False

        req.path = '/admin'
        assert is_trivial(req) is False


class TestIsBusinessRelevant:
    """Tests for the is_business_relevant() function."""

    def test_post_requests_are_business_relevant(self):
        """All POST requests should be business relevant."""
        from security.filters import is_business_relevant
        
        req = MagicMock()
        req.method = 'POST'
        req.path = '/any/path'
        assert is_business_relevant(req) is True

    def test_put_requests_are_business_relevant(self):
        """All PUT requests should be business relevant."""
        from security.filters import is_business_relevant
        
        req = MagicMock()
        req.method = 'PUT'
        req.path = '/any/path'
        assert is_business_relevant(req) is True

    def test_patch_requests_are_business_relevant(self):
        """All PATCH requests should be business relevant."""
        from security.filters import is_business_relevant
        
        req = MagicMock()
        req.method = 'PATCH'
        req.path = '/any/path'
        assert is_business_relevant(req) is True

    def test_delete_requests_are_business_relevant(self):
        """All DELETE requests should be business relevant."""
        from security.filters import is_business_relevant
        
        req = MagicMock()
        req.method = 'DELETE'
        req.path = '/any/path'
        assert is_business_relevant(req) is True

    def test_api_endpoints_are_business_relevant(self):
        """API endpoints (except health/dashboard) should be business relevant."""
        from security.filters import is_business_relevant
        
        api_paths = [
            '/api/users',
            '/api/data',
            '/api/transactions',
            '/api/some/resource',
        ]
        for path in api_paths:
            req = MagicMock()
            req.method = 'GET'
            req.path = path
            assert is_business_relevant(req) is True, f"GET {path} should be business relevant"

    def test_dashboard_api_not_business_relevant(self):
        """Dashboard API endpoints should not be business relevant (GET)."""
        from security.filters import is_business_relevant
        
        req = MagicMock()
        req.method = 'GET'
        req.path = '/api/dashboard/stats'
        assert is_business_relevant(req) is False

    def test_health_api_not_business_relevant(self):
        """Health API endpoint should not be business relevant (GET)."""
        from security.filters import is_business_relevant
        
        req = MagicMock()
        req.method = 'GET'
        req.path = '/api/health'
        assert is_business_relevant(req) is False

    def test_security_stats_not_business_relevant(self):
        """Security stats endpoint should not be business relevant (GET)."""
        from security.filters import is_business_relevant
        
        req = MagicMock()
        req.method = 'GET'
        req.path = '/api/security/stats'
        assert is_business_relevant(req) is False

    def test_sensitive_endpoints_are_business_relevant(self):
        """Sensitive endpoints should be business relevant even for GET."""
        from security.filters import is_business_relevant
        
        sensitive_paths = [
            '/login',
            '/api/login',
            '/admin',
            '/api/admin',
            '/api/data',
            '/user/profile',
            '/api/user/settings',
            '/transaction/123',
            '/api/transaction/456',
        ]
        for path in sensitive_paths:
            req = MagicMock()
            req.method = 'GET'
            req.path = path
            assert is_business_relevant(req) is True, f"GET {path} should be business relevant"

    def test_static_files_not_business_relevant(self):
        """Static file GET requests should not be business relevant."""
        from security.filters import is_business_relevant
        
        req = MagicMock()
        req.method = 'GET'
        req.path = '/static/app.js'
        assert is_business_relevant(req) is False

    def test_homepage_get_not_business_relevant(self):
        """GET to non-sensitive page should not be business relevant."""
        from security.filters import is_business_relevant
        
        req = MagicMock()
        req.method = 'GET'
        req.path = '/about'
        assert is_business_relevant(req) is False
