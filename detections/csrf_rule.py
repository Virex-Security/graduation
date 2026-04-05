"""
Pure Rule-Based CSRF Detection
==============================
Deterministic, fast, high confidence.
Checks for missing or invalid CSRF token in POST/PUT/DELETE/PATCH requests.
"""

import hmac
import logging
from typing import Any, Dict

logger = logging.getLogger(__name__)

STATE_CHANGING_METHODS = frozenset({"POST", "PUT", "DELETE", "PATCH"})

CSRF_EXEMPT_PATHS = (
    "/api/health",
    "/api/login",
    "/api/security/",
    "/api/dashboard/",
)

CSRF_HEADER_NAMES = ("x-csrf-token", "x-xsrf-token", "x-csrftoken", "csrf-token")
CSRF_COOKIE_NAMES = ("csrftoken", "XSRF-TOKEN", "csrf_token", "_csrf")
CSRF_BODY_FIELD_NAMES = ("csrf_token", "_token", "csrfmiddlewaretoken", "authenticity_token", "_csrf")

def _get_header(headers: dict, *names: str) -> str | None:
    lower_headers = {k.lower(): v for k, v in headers.items()}
    for name in names:
        val = lower_headers.get(name.lower())
        if val:
            return val.strip()
    return None

def _get_cookie(cookies: dict, *names: str) -> str | None:
    for name in names:
        val = cookies.get(name)
        if val:
            return val.strip()
    return None

def _get_body_field(body: Any, *names: str) -> str | None:
    if not isinstance(body, dict):
        return None
    for name in names:
        val = body.get(name)
        if val:
            return str(val).strip()
    return None

def _tokens_match(token_a: str | None, token_b: str | None) -> bool:
    if not token_a or not token_b:
        return False
    return hmac.compare_digest(token_a.encode("utf-8"), token_b.encode("utf-8"))

def _is_exempt(path: str) -> bool:
    return any(path.startswith(p) for p in CSRF_EXEMPT_PATHS)

def detect_csrf_rule(request: Dict[str, Any]) -> Dict[str, Any]:
    """
    Layer 1: Deterministic Rule-Based CSRF Detection.
    """
    _safe = {"detected": False, "type": "CSRF", "severity": "High", "reason": "No rule triggered"}

    method: str = str(request.get("method", "GET")).upper()
    path: str = str(request.get("path", "/"))
    headers: dict = request.get("headers") or {}
    body: Any = request.get("body")
    cookies: dict = request.get("cookies") or {}

    if method not in STATE_CHANGING_METHODS:
        return _safe

    if _is_exempt(path):
        return _safe

    header_token = _get_header(headers, *CSRF_HEADER_NAMES)
    cookie_token = _get_cookie(cookies, *CSRF_COOKIE_NAMES)
    body_token = _get_body_field(body, *CSRF_BODY_FIELD_NAMES)

    if not cookie_token:
        if header_token:
            return _safe # Accept API with JWT+Header typically
        return {
            "detected": True, "type": "CSRF", "severity": "High",
            "reason": f"CSRF token cookie missing on {method} {path}.",
            "payload": None
        }

    if header_token:
        if _tokens_match(header_token, cookie_token):
            return _safe
        return {
            "detected": True, "type": "CSRF", "severity": "High",
            "reason": f"CSRF token mismatch (Header Validation) on {method} {path}.",
            "payload": f"header_token={(header_token or '')[:20]} mismatch"
        }

    if body_token:
        if _tokens_match(body_token, cookie_token):
            return _safe
        return {
            "detected": True, "type": "CSRF", "severity": "High",
            "reason": f"CSRF token mismatch (Body Validation) on {method} {path}.",
            "payload": f"body_token={(body_token or '')[:20]} mismatch"
        }

    return {
        "detected": True, "type": "CSRF", "severity": "High",
        "reason": f"CSRF protection missing on {method} {path}. No header or body token found.",
        "payload": None
    }
