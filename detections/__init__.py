"""
حزمة الكشف عن التهديدات المتقدمة — VIREX WAF
Advanced Threat Detection Package

تصدّر دوال الكشف الخاصة بـ CSRF و SSRF
"""

from .csrf_rule import detect_csrf_rule as detect_csrf
from .ssrf_rule import detect_ssrf_rule as detect_ssrf

__all__ = ["detect_csrf", "detect_ssrf"]
