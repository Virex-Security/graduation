"""
كاشف هجمات CSRF — Cross-Site Request Forgery
==============================================
يكشف عن طلبات HTTP الخبيثة التي تستغل هوية المستخدم الموثّق
لتنفيذ عمليات غير مصرّح بها من موقع خارجي.

الأنماط المدعومة:
  1. Synchronizer Token Pattern  — مزامنة التوكن بين الهيدر والكوكي
  2. Double-Submit Cookie Pattern — إرسال نفس التوكن في الكوكي والبودي/الهيدر

الاستخدام:
    from detections import detect_csrf
    result = detect_csrf(req_dict)
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import re
from typing import Any

logger = logging.getLogger(__name__)

# ── الإعدادات ──────────────────────────────────────────────────────────────

# الميثودز التي تغيّر الحالة وتحتاج حماية CSRF
STATE_CHANGING_METHODS: frozenset[str] = frozenset(
    {"POST", "PUT", "DELETE", "PATCH"}
)

# أسماء المسارات التي يُستثنى منها فحص CSRF (عادةً endpoints للـ API المحمية بـ JWT)
CSRF_EXEMPT_PATHS: tuple[str, ...] = (
    "/api/health",
    "/api/login",        # تستخدم JWT بدلاً من CSRF
    "/api/security/",    # مراقبة داخلية
    "/api/dashboard/",   # مراقبة داخلية
)

# أسماء الحقول الممكنة لتوكن CSRF في الهيدر
CSRF_HEADER_NAMES: tuple[str, ...] = (
    "x-csrf-token",
    "x-xsrf-token",
    "x-csrftoken",
    "csrf-token",
)

# أسماء الحقول الممكنة في الكوكي
CSRF_COOKIE_NAMES: tuple[str, ...] = (
    "csrftoken",
    "XSRF-TOKEN",
    "csrf_token",
    "_csrf",
)

# أسماء الحقول الممكنة في البودي أو query string
CSRF_BODY_FIELD_NAMES: tuple[str, ...] = (
    "csrf_token",
    "_token",
    "csrfmiddlewaretoken",
    "authenticity_token",
    "_csrf",
)


# ── الدوال المساعدة ────────────────────────────────────────────────────────


def _get_header(headers: dict[str, str], *names: str) -> str | None:
    """يسترجع قيمة الهيدر بغض النظر عن حالة الأحرف (case-insensitive)."""
    lower_headers = {k.lower(): v for k, v in headers.items()}
    for name in names:
        val = lower_headers.get(name.lower())
        if val:
            return val.strip()
    return None


def _get_cookie(cookies: dict[str, str], *names: str) -> str | None:
    """يسترجع قيمة الكوكي بالأسماء المعطاة."""
    for name in names:
        val = cookies.get(name)
        if val:
            return val.strip()
    return None


def _get_body_field(body: Any, *names: str) -> str | None:
    """يبحث عن حقل CSRF في البودي (dict أو قيمة مبسّطة)."""
    if not isinstance(body, dict):
        return None
    for name in names:
        val = body.get(name)
        if val:
            return str(val).strip()
    return None


def _tokens_match(token_a: str | None, token_b: str | None) -> bool:
    """
    مقارنة التوكنات بطريقة آمنة ضد هجمات Timing Attack.
    يستخدم hmac.compare_digest لضمان المقارنة الثابتة الزمن.
    """
    if not token_a or not token_b:
        return False
    return hmac.compare_digest(
        token_a.encode("utf-8"),
        token_b.encode("utf-8"),
    )


def _is_exempt(path: str) -> bool:
    """يتحقق هل المسار معفى من فحص CSRF."""
    return any(path.startswith(p) for p in CSRF_EXEMPT_PATHS)


# ── الدالة الرئيسية ────────────────────────────────────────────────────────


def detect_csrf(request: dict) -> dict:
    """
    يكشف عن هجمات CSRF في الطلب الوارد.

    المعاملات:
        request (dict): بيانات الطلب تحتوي على:
            - method      (str)  : ميثود HTTP
            - path        (str)  : مسار الطلب
            - headers     (dict) : هيدرات الطلب
            - body        (Any)  : محتوى البودي (dict أو None)
            - query_params(dict) : معاملات URL
            - cookies     (dict) : كوكيز الطلب
            - ip          (str)  : عنوان IP للمرسل
            - user_agent  (str)  : User-Agent string

    العائد:
        dict: نتيجة الكشف بالتنسيق الموحّد للـ WAF
    """
    # القيمة الافتراضية: لا تهديد
    _safe = _build_result(detected=False, reason="Request appears legitimate")

    method: str = str(request.get("method", "GET")).upper()
    path: str = str(request.get("path", "/"))
    headers: dict = request.get("headers") or {}
    body: Any = request.get("body")
    cookies: dict = request.get("cookies") or {}

    # ── الخطوة 1: هل الميثود يغيّر الحالة؟ ──────────────────────────────
    if method not in STATE_CHANGING_METHODS:
        # GET/HEAD/OPTIONS لا تحتاج حماية CSRF
        return _safe

    # ── الخطوة 2: هل المسار معفى؟ ────────────────────────────────────────
    if _is_exempt(path):
        return _safe

    # ── الخطوة 3: استخراج التوكنات ────────────────────────────────────────
    header_token = _get_header(headers, *CSRF_HEADER_NAMES)
    cookie_token = _get_cookie(cookies, *CSRF_COOKIE_NAMES)
    body_token   = _get_body_field(body, *CSRF_BODY_FIELD_NAMES)

    # ── الخطوة 4: التحقق من غياب الكوكي ──────────────────────────────────
    # إذا لم يكن هناك كوكي CSRF أصلاً، لا يمكن التحقق → نعتبره مشبوهاً
    if not cookie_token:
        # لكن إذا كان هناك هيدر وحده (SPA بدون كوكي) نقبله بثقة منخفضة
        if header_token:
            logger.debug("[CSRF] Header token present but no cookie — partial trust")
            return _safe  # نقبل واجهات API التي تعتمد على JWT + header فقط
        return _build_result(
            detected=True,
            confidence=85.0,
            payload=None,
            reason=f"CSRF token cookie missing on {method} {path}. "
                   "No csrftoken/XSRF-TOKEN cookie found.",
            recommendation=(
                "تأكد من إرسال كوكي CSRF مع كل طلب يغيّر الحالة. "
                "Set a csrftoken cookie on login and include it in every POST/PUT/DELETE/PATCH."
            ),
        )

    # ── الخطوة 5: نمط Synchronizer Token (الهيدر vs الكوكي) ──────────────
    if header_token:
        if _tokens_match(header_token, cookie_token):
            logger.debug("[CSRF] Synchronizer token pattern: VALID")
            return _safe
        else:
            return _build_result(
                detected=True,
                confidence=95.0,
                payload=f"header_token={(header_token or '')[:20]}…  cookie_token={(cookie_token or '')[:20]}…",
                reason=(
                    f"CSRF token mismatch (Synchronizer Pattern) on {method} {path}. "
                    "X-CSRF-Token header does not match csrftoken cookie."
                ),
                recommendation=(
                    "تأكد أن التوكن في الهيدر يطابق التوكن في الكوكي تماماً. "
                    "Regenerate the CSRF token on session start and keep both values in sync."
                ),
            )

    # ── الخطوة 6: نمط Double-Submit Cookie (البودي vs الكوكي) ────────────
    if body_token:
        if _tokens_match(body_token, cookie_token):
            logger.debug("[CSRF] Double-submit cookie pattern: VALID")
            return _safe
        else:
            return _build_result(
                detected=True,
                confidence=90.0,
                payload=f"body_token={(body_token or '')[:20]}…  cookie_token={(cookie_token or '')[:20]}…",
                reason=(
                    f"CSRF token mismatch (Double-Submit Cookie) on {method} {path}. "
                    "Body field csrf_token does not match csrftoken cookie."
                ),
                recommendation=(
                    "تأكد من نسخ التوكن بدقة من الكوكي إلى حقل النموذج. "
                    "Use a secure random token generator (secrets.token_urlsafe) "
                    "and avoid predictable values."
                ),
            )

    # ── الخطوة 7: لا يوجد توكن في الهيدر ولا البودي ─────────────────────
    return _build_result(
        detected=True,
        confidence=88.0,
        payload=None,
        reason=(
            f"CSRF protection missing on {method} {path}. "
            "Neither X-CSRF-Token header nor csrf_token body field was found."
        ),
        recommendation=(
            "أضف توكن CSRF في هيدر الطلب (X-CSRF-Token) أو كحقل مخفي في النموذج. "
            "Implement CSRF protection using Flask-WTF or a custom token middleware."
        ),
    )


# ── بناء نتيجة الكشف ──────────────────────────────────────────────────────


def _build_result(
    *,
    detected: bool,
    confidence: float = 0.0,
    payload: str | None = None,
    reason: str = "",
    recommendation: str = "",
) -> dict:
    """يبني dict النتيجة الموحّد للـ WAF."""
    return {
        "detected":       detected,
        "type":           "CSRF",
        "severity":       "High",          # CSRF دائماً تصنيف عالي
        "confidence":     confidence,
        "payload":        payload,
        "reason":         reason,
        "recommendation": recommendation,
    }
