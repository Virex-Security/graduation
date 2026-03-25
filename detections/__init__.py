"""
حزمة الكشف عن التهديدات المتقدمة — VIREX WAF
Advanced Threat Detection Package

تصدّر دوال الكشف الخاصة بـ CSRF و SSRF
"""

from .csrf import detect_csrf
from .ssrf import detect_ssrf

__all__ = ["detect_csrf", "detect_ssrf"]
