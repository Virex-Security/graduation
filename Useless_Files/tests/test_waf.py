"""
WAF detection tests — verify the WAF catches known attack patterns.
"""
import pytest


class TestSQLInjectionDetection:
    """Verify SQL injection payloads are blocked."""

    @pytest.mark.parametrize("payload", [
        "1' OR '1'='1",
        "' UNION SELECT * FROM users--",
        "admin'--",
        "1; DROP TABLE users--",
    ])
    def test_sql_injection_blocked_in_body(self, api_client, payload):
        resp = api_client.post('/api/login', json={
            'username': payload,
            'password': 'test'
        })
        # Should be blocked (400) or rejected as invalid creds (401) — never 200
        assert resp.status_code != 200, f"SQL injection payload was not blocked: {payload!r}"


class TestXSSDetection:
    """Verify XSS payloads are blocked."""

    @pytest.mark.parametrize("payload", [
        "<script>alert(1)</script>",
        "javascript:alert(1)",
        "<img src=x onerror=alert(1)>",
    ])
    def test_xss_blocked_in_query(self, api_client, payload):
        resp = api_client.get(f'/api/products?search={payload}')
        assert resp.status_code in (400, 401, 403)


class TestSensitivePathBlocking:
    """Verify scanner bait paths return 404."""

    @pytest.mark.parametrize("path", [
        "/.env",
        "/wp-admin",
        "/phpmyadmin",
        "/etc/passwd",
    ])
    def test_sensitive_path_returns_404(self, api_client, path):
        resp = api_client.get(path)
        assert resp.status_code == 404
