"""
كاشف هجمات SSRF — Server-Side Request Forgery
===============================================
يكشف عن محاولات إجبار السيرفر على إرسال طلبات HTTP لموارد داخلية
أو خدمات محمية (metadata، شبكات خاصة، بروتوكولات خطرة).

يفحص:
  - البودي (JSON/form)
  - query parameters
  - هيدرات الطلب المخصصة
  - أي حقل URL متداخل داخل JSON

الاستخدام:
    from detections import detect_ssrf
    result = detect_ssrf(req_dict)
"""

from __future__ import annotations

import ipaddress
import logging
import re
import urllib.parse
from typing import Any, Generator

logger = logging.getLogger(__name__)

# ── أنماط الاكتشاف ────────────────────────────────────────────────────────

# بروتوكولات خطرة غير HTTP العادي
DANGEROUS_SCHEMES: frozenset[str] = frozenset(
    {
        "gopher",   # يستخدم لشنّ هجمات على Redis/SMTP
        "file",     # قراءة ملفات السيرفر
        "dict",     # استغلال خدمة DICT
        "ftp",      # نقل ملفات داخلية
        "ldap",     # هجمات LDAP injection
        "ldaps",
        "sftp",
        "tftp",
        "jar",      # Java Archive — استغلال JVM
        "netdoc",   # Java internal  
        "mailto",   # إساءة استخدام SMTP
    }
)

# نطاقات IP الخاصة/المحجوزة التي لا يجب الوصول إليها من الخارج
PRIVATE_IP_NETWORKS: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = [
    ipaddress.ip_network("127.0.0.0/8"),       # loopback
    ipaddress.ip_network("10.0.0.0/8"),        # RFC-1918 private
    ipaddress.ip_network("172.16.0.0/12"),     # RFC-1918 private
    ipaddress.ip_network("192.168.0.0/16"),    # RFC-1918 private
    ipaddress.ip_network("169.254.0.0/16"),    # link-local (AWS/GCP metadata!)
    ipaddress.ip_network("0.0.0.0/8"),         # "this" network
    ipaddress.ip_network("::1/128"),           # IPv6 loopback
    ipaddress.ip_network("fc00::/7"),          # IPv6 unique local
    ipaddress.ip_network("fe80::/10"),         # IPv6 link-local
]

# أسماء نطاقات خدمات الميتاداتا السحابية
CLOUD_METADATA_HOSTS: frozenset[str] = frozenset(
    {
        "169.254.169.254",                # AWS/GCP/Azure metadata service
        "metadata.google.internal",       # GCP metadata
        "169.254.170.2",                  # ECS credentials endpoint
        "100.100.100.200",                # Alibaba Cloud metadata
        "fd00:ec2::254",                  # AWS IPv6 metadata
    }
)

# كلمات مفتاحية توحي بأن الحقل يحتوي على URL
URL_HINT_KEYS: tuple[str, ...] = (
    "url", "uri", "href", "src", "source", "destination", "dest",
    "target", "redirect", "next", "callback", "webhook", "endpoint",
    "proxy", "fetch", "load", "resource", "image_url", "avatar_url",
    "file_url", "download", "import", "feed", "return_url",
)

# هيدرات عادةً تحتوي على URLs قد تُستغل
URL_CARRYING_HEADERS: tuple[str, ...] = (
    "x-forwarded-for",
    "x-original-url",
    "x-rewrite-url",
    "x-forwarded-host",
    "x-host",
    "referer",
)

# Regex لاستخراج URLs من نصوص عشوائية
_URL_REGEX = re.compile(
    r"""(?:(?:https?|ftp|gopher|file|dict|ldaps?|sftp|tftp|jar|netdoc|mailto|data)://|"""
    r"""(?:\/\/))"""
    r"""[^\s"'<>{}|\\^`\[\]]{3,}""",
    re.IGNORECASE,
)

# Regex للتعرف على IPs مكتوبة بأشكال مشوّهة (Hex, Octal, etc.)
_SUSPICIOUS_IP_PATTERN = re.compile(
    r"""(?:
        0x[0-9a-fA-F]{1,8}   # hex IP like 0x7f000001
      | 0[0-7]{9,11}         # octal IP
      | \d{8,10}             # decimal IP like 2130706433 = 127.0.0.1
    )""",
    re.VERBOSE | re.IGNORECASE,
)


# ── الدوال المساعدة ────────────────────────────────────────────────────────


def _extract_urls(value: Any, key_hint: str = "") -> Generator[tuple[str, str], None, None]:
    """
    يستخرج URLs من أي قيمة (نص، dict، list) بشكل تكراري.

    العائد:
        Generator يُنتج (url_string, source_description)
    """
    if isinstance(value, dict):
        for k, v in value.items():
            # إذا كان اسم الحقل يوحي بـ URL، نعطيه أولوية
            hint = k.lower()
            yield from _extract_urls(v, key_hint=hint)

    elif isinstance(value, list):
        for item in value:
            yield from _extract_urls(item, key_hint=key_hint)

    elif isinstance(value, str) and value:
        # 1) الحقل نفسه يبدو URL مباشر
        if key_hint in URL_HINT_KEYS:
            if re.match(r"https?://|ftp://|//", value, re.IGNORECASE):
                yield (value, f"field:{key_hint}")
            elif "/" in value or "." in value:
                # قد يكون نسبياً أو مسار ملف
                yield (value, f"field:{key_hint}")

        # 2) ابحث داخل النص عن URLs مضمّنة
        for match in _URL_REGEX.finditer(value):
            yield (match.group(), f"embedded-in:{key_hint or 'text'}")


def _is_private_ip(host: str) -> bool:
    """يتحقق هل عنوان IP ضمن النطاقات الخاصة/المحجوزة."""
    try:
        ip = ipaddress.ip_address(host)
        return any(ip in net for net in PRIVATE_IP_NETWORKS)
    except ValueError:
        return False


def _is_cloud_metadata(host: str) -> bool:
    """يتحقق هل العنوان هو نقطة نهاية خدمة ميتاداتا سحابية."""
    return host.lower() in CLOUD_METADATA_HOSTS


def _parse_host(url: str) -> str | None:
    """
    يحلّل URL ويستخرج الـ hostname منه.
    يتعامل مع الحالات الخاصة مثل //host/path.
    """
    try:
        if url.startswith("//"):
            url = "http:" + url
        parsed = urllib.parse.urlparse(url)
        return parsed.hostname  # يُعيد None إذا لم يجد
    except Exception:
        return None


def _has_dangerous_scheme(url: str) -> str | None:
    """يتحقق هل URL يستخدم بروتوكولاً خطراً. يُعيد اسم البروتوكول أو None."""
    try:
        if url.startswith("//"):
            return None  # نسبي — فحصه بالـ host
        parsed = urllib.parse.urlparse(url)
        scheme = parsed.scheme.lower()
        if scheme in DANGEROUS_SCHEMES:
            return scheme
    except Exception:
        pass
    return None


def _check_suspicious_encoding(url: str) -> bool:
    """
    يكشف عن IPs مشفّرة بطرق غير تقليدية (Hex/Octal/Decimal).
    هجوم SSRF متقدم يتجاوز الفلاتر البسيطة.
    """
    return bool(_SUSPICIOUS_IP_PATTERN.search(url))


# ── الدالة الرئيسية ────────────────────────────────────────────────────────


def detect_ssrf(request: dict) -> dict:
    """
    يكشف عن هجمات SSRF في الطلب الوارد.

    المعاملات:
        request (dict): بيانات الطلب تحتوي على:
            - method       (str)  : ميثود HTTP
            - path         (str)  : مسار الطلب
            - headers      (dict) : هيدرات الطلب
            - body         (Any)  : محتوى البودي
            - query_params (dict) : معاملات URL
            - cookies      (dict) : كوكيز الطلب
            - ip           (str)  : IP المرسل
            - user_agent   (str)  : User-Agent

    العائد:
        dict: نتيجة الكشف بالتنسيق الموحّد للـ WAF
    """
    headers: dict     = request.get("headers") or {}
    body: Any         = request.get("body")
    query_params: dict = request.get("query_params") or {}

    # نجمع مصادر الفحص مع وصف لكل مصدر
    sources: list[tuple[Any, str]] = [
        (body,          "body"),
        (query_params,  "query_params"),
    ]

    # أضف قيم الهيدرات ذات الصلة بالـ URL
    lower_headers = {k.lower(): v for k, v in headers.items()}
    for hdr_name in URL_CARRYING_HEADERS:
        if hdr_name in lower_headers:
            sources.append((lower_headers[hdr_name], f"header:{hdr_name}"))

    # ── المسح ─────────────────────────────────────────────────────────────
    for data_source, source_name in sources:
        for url_str, field_info in _extract_urls(data_source):
            # --- فحص البروتوكول الخطر ---
            dangerous_scheme = _has_dangerous_scheme(url_str)
            if dangerous_scheme:
                return _build_result(
                    detected=True,
                    severity="Critical",
                    confidence=97.0,
                    payload=url_str[:200],
                    reason=(
                        f"SSRF: Dangerous protocol '{dangerous_scheme}://' detected "
                        f"in {source_name} → {field_info}. "
                        "This protocol can be used to reach internal services."
                    ),
                    recommendation=(
                        "ابتُ URL allowlist تسمح فقط بـ https:// لنطاقات موثوقة. "
                        "Never pass user-supplied URLs directly to server-side HTTP clients. "
                        "Use a URL allowlist instead of a denylist."
                    ),
                )

            # --- فحص الـ Host ---
            host = _parse_host(url_str)
            if not host:
                continue

            # كشف خدمة الميتاداتا السحابية
            if _is_cloud_metadata(host):
                return _build_result(
                    detected=True,
                    severity="Critical",
                    confidence=99.0,
                    payload=url_str[:200],
                    reason=(
                        f"SSRF: Cloud metadata endpoint targeted: '{host}' "
                        f"in {source_name} → {field_info}. "
                        "This can expose IAM credentials and cloud secrets."
                    ),
                    recommendation=(
                        "احجب الوصول إلى 169.254.169.254 على مستوى الشبكة وعلى مستوى الكود. "
                        "Use IMDSv2 (token-based) on AWS and restrict outbound HTTP from app servers."
                    ),
                )

            # كشف IP خاص/داخلي
            if _is_private_ip(host):
                return _build_result(
                    detected=True,
                    severity="Critical",
                    confidence=96.0,
                    payload=url_str[:200],
                    reason=(
                        f"SSRF: Private/internal IP address targeted: '{host}' "
                        f"in {source_name} → {field_info}. "
                        "This may allow access to internal infrastructure."
                    ),
                    recommendation=(
                        "استخدم DNS resolution + IP validation قبل أي طلب خارجي. "
                        "Reject all requests targeting RFC-1918 and loopback address ranges."
                    ),
                )

            # كشف localhost بكل صوره
            if host.lower() in ("localhost", "ip6-localhost", "ip6-loopback"):
                return _build_result(
                    detected=True,
                    severity="Critical",
                    confidence=98.0,
                    payload=url_str[:200],
                    reason=(
                        f"SSRF: 'localhost' targeted in {source_name} → {field_info}. "
                        "Attacker is attempting to reach the server itself."
                    ),
                    recommendation=(
                        "ابتُ blocklist صريح يمنع localhost و 127.x.x.x. "
                        "Validate and resolve hostnames server-side before use."
                    ),
                )

            # كشف IPs مشفّرة (تجاوز فلاتر النصوص)
            if _check_suspicious_encoding(url_str):
                return _build_result(
                    detected=True,
                    severity="High",
                    confidence=80.0,
                    payload=url_str[:200],
                    reason=(
                        f"SSRF: Suspicious IP encoding detected in {source_name} → {field_info}. "
                        "Value contains hex/octal/decimal-encoded IP patterns typical of filter bypass."
                    ),
                    recommendation=(
                        "قم بتطبيع جميع عناوين URLs وتحويلها لصيغتها القانونية قبل التحقق. "
                        "Always normalize URLs (decode percent-encoding, expand hex/octal) "
                        "before applying security checks."
                    ),
                )

    # لم يُكتشف أي تهديد
    return {
        "detected":       False,
        "type":           "SSRF",
        "severity":       "High",
        "confidence":     0.0,
        "payload":        None,
        "reason":         "No SSRF indicators found in request",
        "recommendation": "",
    }


# ── بناء نتيجة الكشف ──────────────────────────────────────────────────────


def _build_result(
    *,
    detected: bool,
    severity: str = "High",
    confidence: float = 0.0,
    payload: str | None = None,
    reason: str = "",
    recommendation: str = "",
) -> dict:
    """يبني dict النتيجة الموحّد للـ WAF."""
    return {
        "detected":       detected,
        "type":           "SSRF",
        "severity":       severity,
        "confidence":     confidence,
        "payload":        payload,
        "reason":         reason,
        "recommendation": recommendation,
    }
