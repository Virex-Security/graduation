"""Unit tests for security/events.py module."""
import pytest
import re
import time
from unittest.mock import patch


class TestNewRequestId:
    """Tests for the new_request_id() function."""

    def test_returns_string(self):
        """new_request_id should return a string."""
        from security.events import new_request_id
        
        result = new_request_id()
        assert isinstance(result, str)

    def test_returns_valid_uuid_format(self):
        """new_request_id should return a valid UUID4 format."""
        from security.events import new_request_id
        
        result = new_request_id()
        uuid_pattern = re.compile(
            r'^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$',
            re.IGNORECASE
        )
        assert uuid_pattern.match(result), f"'{result}' is not a valid UUID4"

    def test_returns_unique_ids(self):
        """new_request_id should return unique IDs on each call."""
        from security.events import new_request_id
        
        ids = [new_request_id() for _ in range(100)]
        assert len(ids) == len(set(ids)), "Request IDs should be unique"


class TestNowTs:
    """Tests for the now_ts() function."""

    def test_returns_string(self):
        """now_ts should return a string."""
        from security.events import now_ts
        
        result = now_ts()
        assert isinstance(result, str)

    def test_returns_correct_format(self):
        """now_ts should return timestamp in YYYY-MM-DD HH:MM:SS format."""
        from security.events import now_ts
        
        result = now_ts()
        pattern = re.compile(r'^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$')
        assert pattern.match(result), f"'{result}' is not in expected format"

    def test_timestamp_is_current(self):
        """now_ts should return current time."""
        from security.events import now_ts
        
        expected = time.strftime("%Y-%m-%d %H:%M:%S")
        result = now_ts()
        # Allow 1 second difference due to execution time
        assert result[:16] == expected[:16], f"Timestamp {result} differs from expected {expected}"


class TestBuildEvent:
    """Tests for the build_event() function."""

    def test_builds_event_with_required_fields(self):
        """build_event should return dict with all required fields."""
        from security.events import build_event
        
        event = build_event(
            request_id="req-123",
            ip="192.168.1.1",
            endpoint="/api/test",
            method="GET",
            attack_type="SQL Injection"
        )
        
        assert isinstance(event, dict)
        assert "event_id" in event
        assert "timestamp" in event
        assert event["request_id"] == "req-123"
        assert event["ip"] == "192.168.1.1"
        assert event["endpoint"] == "/api/test"
        assert event["method"] == "GET"
        assert event["attack_type"] == "SQL Injection"

    def test_default_values(self):
        """build_event should use correct default values."""
        from security.events import build_event
        
        event = build_event(
            request_id="req-123",
            ip="192.168.1.1",
            endpoint="/api/test",
            method="GET",
            attack_type="XSS"
        )
        
        assert event["severity"] == "Medium"
        assert event["detection_type"] == "Other"
        assert event["blocked"] is False
        assert event["reason"] == ""
        assert event["snippet"] == ""

    def test_custom_severity(self):
        """build_event should accept custom severity."""
        from security.events import build_event
        
        event = build_event(
            request_id="req-123",
            ip="192.168.1.1",
            endpoint="/api/test",
            method="POST",
            attack_type="SQL Injection",
            severity="High"
        )
        
        assert event["severity"] == "High"

    def test_blocked_is_boolean(self):
        """build_event should convert blocked to boolean."""
        from security.events import build_event
        
        # Test truthy value
        event = build_event(
            request_id="req-123",
            ip="192.168.1.1",
            endpoint="/api/test",
            method="POST",
            attack_type="XSS",
            blocked=1
        )
        assert event["blocked"] is True
        
        # Test falsy value
        event = build_event(
            request_id="req-123",
            ip="192.168.1.1",
            endpoint="/api/test",
            method="POST",
            attack_type="XSS",
            blocked=0
        )
        assert event["blocked"] is False

    def test_snippet_truncation(self):
        """build_event should truncate snippet to 200 characters."""
        from security.events import build_event
        
        long_snippet = "x" * 300
        event = build_event(
            request_id="req-123",
            ip="192.168.1.1",
            endpoint="/api/test",
            method="POST",
            attack_type="SQL Injection",
            snippet=long_snippet
        )
        
        assert len(event["snippet"]) == 200
        assert event["snippet"] == "x" * 200

    def test_short_snippet_not_truncated(self):
        """build_event should not truncate short snippets."""
        from security.events import build_event
        
        short_snippet = "SELECT * FROM users"
        event = build_event(
            request_id="req-123",
            ip="192.168.1.1",
            endpoint="/api/test",
            method="POST",
            attack_type="SQL Injection",
            snippet=short_snippet
        )
        
        assert event["snippet"] == short_snippet

    def test_empty_snippet_handling(self):
        """build_event should handle empty snippet."""
        from security.events import build_event
        
        event = build_event(
            request_id="req-123",
            ip="192.168.1.1",
            endpoint="/api/test",
            method="POST",
            attack_type="XSS",
            snippet=""
        )
        
        assert event["snippet"] == ""

    def test_event_id_is_unique(self):
        """build_event should generate unique event IDs."""
        from security.events import build_event
        
        events = [
            build_event(
                request_id=f"req-{i}",
                ip="192.168.1.1",
                endpoint="/api/test",
                method="GET",
                attack_type="XSS"
            )
            for i in range(50)
        ]
        
        event_ids = [e["event_id"] for e in events]
        assert len(event_ids) == len(set(event_ids)), "Event IDs should be unique"

    def test_all_fields_present(self):
        """build_event should return all expected fields."""
        from security.events import build_event
        
        event = build_event(
            request_id="req-123",
            ip="10.0.0.1",
            endpoint="/api/admin",
            method="DELETE",
            attack_type="Privilege Escalation",
            severity="Critical",
            detection_type="Rule-based",
            blocked=True,
            reason="Blocked by WAF",
            snippet="malicious payload"
        )
        
        expected_fields = [
            "event_id", "timestamp", "request_id", "ip", "endpoint",
            "method", "attack_type", "severity", "detection_type",
            "blocked", "reason", "snippet"
        ]
        
        for field in expected_fields:
            assert field in event, f"Missing field: {field}"
        
        assert event["request_id"] == "req-123"
        assert event["ip"] == "10.0.0.1"
        assert event["endpoint"] == "/api/admin"
        assert event["method"] == "DELETE"
        assert event["attack_type"] == "Privilege Escalation"
        assert event["severity"] == "Critical"
        assert event["detection_type"] == "Rule-based"
        assert event["blocked"] is True
        assert event["reason"] == "Blocked by WAF"
        assert event["snippet"] == "malicious payload"
