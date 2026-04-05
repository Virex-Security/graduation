"""
Pytest fixtures for Virex Security System tests.
"""
import os
import pytest
from dotenv import load_dotenv

# Load test environment before any app imports
os.environ.setdefault("SECRET_KEY", "test-secret-key-for-ci-minimum-32-chars!!")
os.environ.setdefault("INTERNAL_API_SECRET", "test-internal-secret-for-ci-only-32chars")
os.environ.setdefault("SMTP_EMAIL", "test@example.com")
os.environ.setdefault("SMTP_PASSWORD", "test-password")
os.environ.setdefault("FLASK_DEBUG", "false")
os.environ.setdefault("COOKIE_SECURE", "false")


@pytest.fixture(scope="session")
def api_app():
    """Create API Flask app for testing."""
    from app.api import create_api_app
    app = create_api_app()
    app.config["TESTING"] = True
    app.config["WTF_CSRF_ENABLED"] = False
    return app


@pytest.fixture(scope="session")
def dashboard_app():
    """Create Dashboard Flask app for testing."""
    from app.dashboard import create_dashboard_app
    app = create_dashboard_app()
    app.config["TESTING"] = True
    return app


@pytest.fixture
def api_client(api_app):
    return api_app.test_client()


@pytest.fixture
def dashboard_client(dashboard_app):
    return dashboard_app.test_client()
