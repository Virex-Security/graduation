"""
اختبارات الوحدة لكاشفات CSRF و SSRF — VIREX WAF
Unit tests for detections/csrf.py and detections/ssrf.py
"""

import sys
import os

# أضف مسار المشروع لـ sys.path لتمكين الاستيراد المباشر
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest
from detections.csrf import detect_csrf
from detections.ssrf import detect_ssrf


# ═══════════════════════════════════════════════════════════════════════════
#  Helpers
# ═══════════════════════════════════════════════════════════════════════════

def _make_csrf_req(
    method: str = "POST",
    path: str = "/api/orders",
    header_token: str | None = None,
    cookie_token: str | None = None,
    body_token: str | None = None,
) -> dict:
    """يبني طلب للاختبار مع CSRF tokens اختيارية."""
    headers = {}
    if header_token is not None:
        headers["X-CSRF-Token"] = header_token

    cookies = {}
    if cookie_token is not None:
        cookies["csrftoken"] = cookie_token

    body = {}
    if body_token is not None:
        body["csrf_token"] = body_token

    return {
        "method": method,
        "path": path,
        "headers": headers,
        "body": body,
        "query_params": {},
        "cookies": cookies,
        "ip": "203.0.113.5",
        "user_agent": "Mozilla/5.0",
    }


def _make_ssrf_req(
    body: dict | None = None,
    query_params: dict | None = None,
    headers: dict | None = None,
) -> dict:
    """يبني طلب للاختبار مع بيانات SSRF محتملة."""
    return {
        "method": "POST",
        "path": "/api/data",
        "headers": headers or {},
        "body": body or {},
        "query_params": query_params or {},
        "cookies": {},
        "ip": "203.0.113.5",
        "user_agent": "Mozilla/5.0",
    }


# ═══════════════════════════════════════════════════════════════════════════
#  CSRF — طلبات شرعية
# ═══════════════════════════════════════════════════════════════════════════

class TestCSRFLegitimate:
    """حالات شرعية — يجب ألا يُكتشف فيها CSRF."""

    def test_get_request_always_allowed(self):
        """طلبات GET لا تحتاج CSRF token."""
        req = _make_csrf_req(method="GET")
        result = detect_csrf(req)
        assert result["detected"] is False

    def test_head_request_always_allowed(self):
        """طلبات HEAD لا تحتاج CSRF token."""
        req = _make_csrf_req(method="HEAD")
        result = detect_csrf(req)
        assert result["detected"] is False

    def test_options_request_always_allowed(self):
        """طلبات OPTIONS (preflight) لا تحتاج CSRF token."""
        req = _make_csrf_req(method="OPTIONS")
        result = detect_csrf(req)
        assert result["detected"] is False

    def test_valid_synchronizer_token(self):
        """POST مع header token يطابق cookie token → شرعي."""
        token = "my-secure-token-abc123"
        req = _make_csrf_req(
            method="POST",
            header_token=token,
            cookie_token=token,
        )
        result = detect_csrf(req)
        assert result["detected"] is False

    def test_valid_synchronizer_token_put(self):
        """PUT مع header token صحيح → شرعي."""
        token = "put-token-xyz"
        req = _make_csrf_req(
            method="PUT",
            header_token=token,
            cookie_token=token,
        )
        result = detect_csrf(req)
        assert result["detected"] is False

    def test_valid_double_submit_cookie(self):
        """POST مع body token يطابق cookie → double-submit pattern شرعي."""
        token = "csrf-body-token-999"
        req = _make_csrf_req(
            method="POST",
            cookie_token=token,
            body_token=token,
        )
        result = detect_csrf(req)
        assert result["detected"] is False

    def test_exempt_login_path(self):
        """مسار /api/login معفى من فحص CSRF (يستخدم JWT)."""
        req = _make_csrf_req(method="POST", path="/api/login")
        # لا يوجد token — لكن المسار معفى
        result = detect_csrf(req)
        assert result["detected"] is False

    def test_header_token_only_no_cookie_allowed(self):
        """طلب API بهيدر فقط (بدون كوكي) — SPA pattern مقبول."""
        req = _make_csrf_req(
            method="POST",
            header_token="spa-jwt-token-111",
            cookie_token=None,
        )
        result = detect_csrf(req)
        assert result["detected"] is False


# ═══════════════════════════════════════════════════════════════════════════
#  CSRF — طلبات خبيثة
# ═══════════════════════════════════════════════════════════════════════════

class TestCSRFMalicious:
    """حالات CSRF — يجب اكتشافها وإيقافها."""

    def test_post_no_token_no_cookie(self):
        """POST بدون أي token أو cookie → CSRF واضح."""
        req = _make_csrf_req(method="POST")
        result = detect_csrf(req)
        assert result["detected"] is True
        assert result["type"] == "CSRF"
        assert result["severity"] == "High"
        assert result["confidence"] > 80

    def test_delete_no_token(self):
        """DELETE request بدون حماية CSRF → خطر."""
        req = _make_csrf_req(method="DELETE")
        result = detect_csrf(req)
        assert result["detected"] is True

    def test_patch_no_token(self):
        """PATCH request بدون حماية CSRF → خطر."""
        req = _make_csrf_req(method="PATCH")
        result = detect_csrf(req)
        assert result["detected"] is True

    def test_mismatched_header_and_cookie(self):
        """Header token لا يطابق cookie token → هجوم CSRF محتمل."""
        req = _make_csrf_req(
            method="POST",
            header_token="attacker-fake-token",
            cookie_token="real-server-token",
        )
        result = detect_csrf(req)
        assert result["detected"] is True
        assert result["confidence"] >= 90
        assert "mismatch" in result["reason"].lower()

    def test_mismatched_body_and_cookie(self):
        """Body token لا يطابق cookie token → double-submit attack."""
        req = _make_csrf_req(
            method="POST",
            cookie_token="correct-token",
            body_token="wrong-token",
        )
        result = detect_csrf(req)
        assert result["detected"] is True
        assert result["confidence"] >= 85

    def test_cookie_only_no_token_field(self):
        """Cookie موجود لكن لا يوجد header أو body token → مشبوه."""
        req = _make_csrf_req(
            method="POST",
            cookie_token="some-token",
            header_token=None,
            body_token=None,
        )
        result = detect_csrf(req)
        assert result["detected"] is True

    def test_result_has_recommendation(self):
        """نتيجة الكشف يجب أن تحتوي على توصية."""
        req = _make_csrf_req(method="POST")
        result = detect_csrf(req)
        assert result["detected"] is True
        assert len(result["recommendation"]) > 10


# ═══════════════════════════════════════════════════════════════════════════
#  SSRF — طلبات شرعية
# ═══════════════════════════════════════════════════════════════════════════

class TestSSRFLegitimate:
    """حالات شرعية — لا ينبغي أن يُكتشف فيها SSRF."""

    def test_no_urls_in_body(self):
        """طلب عادي بدون أي URLs → آمن."""
        req = _make_ssrf_req(body={"name": "Ahmed", "age": 25})
        result = detect_ssrf(req)
        assert result["detected"] is False

    def test_external_public_url(self):
        """URL لموقع عام → آمن."""
        req = _make_ssrf_req(body={"avatar_url": "https://cdn.example.com/avatar.png"})
        result = detect_ssrf(req)
        assert result["detected"] is False

    def test_empty_body(self):
        """طلب فارغ → آمن."""
        req = _make_ssrf_req(body={})
        result = detect_ssrf(req)
        assert result["detected"] is False

    def test_public_api_webhook(self):
        """Webhook لـ HTTPS عام → آمن."""
        req = _make_ssrf_req(body={"webhook": "https://hooks.slack.com/abc123"})
        result = detect_ssrf(req)
        assert result["detected"] is False

    def test_no_query_params(self):
        """طلب بدون query parameters → آمن."""
        req = _make_ssrf_req(query_params={})
        result = detect_ssrf(req)
        assert result["detected"] is False

    def test_result_type_is_ssrf(self):
        """نوع نتيجة الكشف يجب أن يكون SSRF دائماً."""
        req = _make_ssrf_req(body={})
        result = detect_ssrf(req)
        assert result["type"] == "SSRF"


# ═══════════════════════════════════════════════════════════════════════════
#  SSRF — طلبات خبيثة
# ═══════════════════════════════════════════════════════════════════════════

class TestSSRFMalicious:
    """حالات SSRF — يجب اكتشافها وإيقافها."""

    def test_localhost_in_body(self):
        """URL يشير إلى localhost → هجوم SSRF."""
        req = _make_ssrf_req(body={"url": "http://localhost/admin"})
        result = detect_ssrf(req)
        assert result["detected"] is True
        assert result["type"] == "SSRF"
        assert result["severity"] in ("High", "Critical")
        assert result["confidence"] > 80

    def test_loopback_ip_127(self):
        """URL يشير إلى 127.0.0.1 → loopback هجوم."""
        req = _make_ssrf_req(body={"source": "http://127.0.0.1:8080/api"})
        result = detect_ssrf(req)
        assert result["detected"] is True
        assert result["confidence"] > 90

    def test_aws_metadata_in_query(self):
        """محاولة الوصول لـ AWS metadata endpoint → خطر حرج."""
        req = _make_ssrf_req(query_params={"img": "http://169.254.169.254/latest/meta-data/"})
        result = detect_ssrf(req)
        assert result["detected"] is True
        assert result["severity"] == "Critical"
        assert result["confidence"] >= 99

    def test_private_ip_192_168(self):
        """URL لشبكة داخلية 192.168.x.x → SSRF على الشبكة الداخلية."""
        req = _make_ssrf_req(body={"webhook": "http://192.168.1.100/internal-api"})
        result = detect_ssrf(req)
        assert result["detected"] is True
        assert result["severity"] == "Critical"

    def test_private_ip_10_x(self):
        """نطاق 10.0.0.0/8 → شبكة RFC-1918 خاصة."""
        req = _make_ssrf_req(body={"fetch_url": "http://10.0.0.1/secret"})
        result = detect_ssrf(req)
        assert result["detected"] is True

    def test_private_ip_172_16(self):
        """نطاق 172.16.x.x → شبكة RFC-1918 خاصة."""
        req = _make_ssrf_req(body={"resource": "http://172.16.0.1/admin"})
        result = detect_ssrf(req)
        assert result["detected"] is True

    def test_gopher_protocol(self):
        """بروتوكول gopher:// يُستخدم لهجمات على Redis/SMTP → خطر حرج."""
        req = _make_ssrf_req(body={"url": "gopher://127.0.0.1:6379/_FLUSHALL"})
        result = detect_ssrf(req)
        assert result["detected"] is True
        assert result["severity"] == "Critical"

    def test_file_protocol(self):
        """بروتوكول file:// لقراءة ملفات السيرفر → خطر حرج."""
        req = _make_ssrf_req(body={"source": "file:///etc/passwd"})
        result = detect_ssrf(req)
        assert result["detected"] is True
        assert result["severity"] == "Critical"

    def test_dict_protocol(self):
        """بروتوكول dict:// → استغلال خدمة DICT."""
        req = _make_ssrf_req(body={"url": "dict://localhost:11211/stat"})
        result = detect_ssrf(req)
        assert result["detected"] is True

    def test_ssrf_in_nested_json(self):
        """SSRF في JSON متداخل → يجب الكشف عنه."""
        req = _make_ssrf_req(body={
            "config": {
                "callback": "http://169.254.169.254/latest/meta-data/iam/"
            }
        })
        result = detect_ssrf(req)
        assert result["detected"] is True
        assert result["severity"] == "Critical"

    def test_ssrf_in_list_value(self):
        """SSRF في list داخل JSON → يجب الكشف عنه."""
        req = _make_ssrf_req(body={
            "urls": ["https://example.com", "http://10.0.0.5/internal"]
        })
        result = detect_ssrf(req)
        assert result["detected"] is True

    def test_ssrf_payload_captured(self):
        """الـ payload يجب أن يُسجَّل في النتيجة للتدقيق."""
        malicious_url = "http://192.168.0.1/api/secret"
        req = _make_ssrf_req(body={"url": malicious_url})
        result = detect_ssrf(req)
        assert result["detected"] is True
        assert result["payload"] is not None
        assert "192.168.0.1" in result["payload"]

    def test_result_has_recommendation(self):
        """نتيجة SSRF يجب أن تحتوي على توصية للإصلاح."""
        req = _make_ssrf_req(body={"url": "http://localhost"})
        result = detect_ssrf(req)
        assert result["detected"] is True
        assert len(result["recommendation"]) > 10

    def test_ssrf_gcp_metadata(self):
        """GCP metadata endpoint → خطر حرج."""
        req = _make_ssrf_req(body={"url": "http://metadata.google.internal/computeMetadata/v1/"})
        result = detect_ssrf(req)
        assert result["detected"] is True
        assert result["severity"] == "Critical"
