"""
Pure Rule-Based SSRF Detection
==============================
Deterministic, fast, high confidence.
Checks for internal IPs, localhost, metadata endpoints, dangerous protocols.
"""

import re
import ipaddress
import urllib.parse
from typing import Any, Dict, Generator

DANGEROUS_SCHEMES = frozenset({"gopher", "file", "dict", "ftp", "ldap", "ldaps", "sftp", "tftp", "jar", "netdoc", "mailto"})

PRIVATE_IP_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]

CLOUD_METADATA_HOSTS = frozenset({
    "169.254.169.254",
    "metadata.google.internal",
    "169.254.170.2",
    "100.100.100.200",
    "fd00:ec2::254",
})

URL_HINT_KEYS = ("url", "uri", "href", "src", "target", "redirect", "proxy", "fetch", "endpoint", "callback", "webhook")
URL_CARRYING_HEADERS = ("x-forwarded-for", "x-original-url", "x-rewrite-url", "x-forwarded-host", "referer")

_URL_REGEX = re.compile(
    r"""(?:(?:https?|ftp|gopher|file|dict|ldaps?|sftp|tftp|jar|netdoc|mailto|data)://|(?:\/\/))[^\s"'<>{}|\\^`\[\]]{3,}""",
    re.IGNORECASE,
)

_SUSPICIOUS_IP_PATTERN = re.compile(
    r"""(?:0x[0-9a-fA-F]{1,8}|0[0-7]{9,11}|\d{8,10})""",
    re.VERBOSE | re.IGNORECASE,
)

def _extract_urls(value: Any, key_hint: str = "") -> Generator[tuple[str, str], None, None]:
    if isinstance(value, dict):
        for k, v in value.items():
            yield from _extract_urls(v, key_hint=k.lower())
    elif isinstance(value, list):
        for item in value:
            yield from _extract_urls(item, key_hint=key_hint)
    elif isinstance(value, str) and value:
        if key_hint in URL_HINT_KEYS:
            if re.match(r"https?://|ftp://|//", value, re.IGNORECASE) or "/" in value or "." in value:
                yield (value, f"field:{key_hint}")
        for match in _URL_REGEX.finditer(value):
            yield (match.group(), f"embedded-in:{key_hint or 'text'}")

def _is_private_ip(host: str) -> bool:
    try:
        ip = ipaddress.ip_address(host)
        return any(ip in net for net in PRIVATE_IP_NETWORKS)
    except ValueError:
        return False

def _parse_host(url: str) -> str | None:
    try:
        if url.startswith("//"): url = "http:" + url
        return urllib.parse.urlparse(url).hostname
    except Exception:
        return None

def detect_ssrf_rule(request: Dict[str, Any]) -> Dict[str, Any]:
    """
    Layer 1: Deterministic Rule-Based SSRF Detection.
    """
    _safe = {"detected": False, "type": "SSRF", "severity": "High", "reason": "No rule triggered"}

    headers: dict = request.get("headers") or {}
    body: Any = request.get("body")
    query_params: dict = request.get("query_params") or {}

    sources: list[tuple[Any, str]] = [(body, "body"), (query_params, "query_params")]
    lower_headers = {k.lower(): v for k, v in headers.items()}
    for hdr_name in URL_CARRYING_HEADERS:
        if hdr_name in lower_headers:
            sources.append((lower_headers[hdr_name], f"header:{hdr_name}"))

    for data_source, source_name in sources:
        for url_str, field_info in _extract_urls(data_source):
            try:
                scheme = urllib.parse.urlparse("http:" + url_str if url_str.startswith("//") else url_str).scheme.lower()
                if scheme in DANGEROUS_SCHEMES:
                    return {
                        "detected": True, "type": "SSRF", "severity": "Critical",
                        "reason": f"Dangerous protocol '{scheme}://' detected in {source_name}.",
                        "payload": url_str[:200]
                    }
            except Exception: pass

            host = _parse_host(url_str)
            if not host:
                continue

            if host.lower() in CLOUD_METADATA_HOSTS:
                return {
                    "detected": True, "type": "SSRF", "severity": "Critical",
                    "reason": f"Cloud metadata endpoint targeted in {source_name}.",
                    "payload": url_str[:200]
                }

            if host.lower() in ("localhost", "127.0.0.1", "ip6-localhost", "ip6-loopback") or _is_private_ip(host):
                return {
                    "detected": True, "type": "SSRF", "severity": "Critical",
                    "reason": f"Private/internal IP or localhost targeted in {source_name}.",
                    "payload": url_str[:200]
                }

            if bool(_SUSPICIOUS_IP_PATTERN.search(url_str)):
                return {
                    "detected": True, "type": "SSRF", "severity": "High",
                    "reason": f"Suspicious IP encoding detected in {source_name}.",
                    "payload": url_str[:200]
                }

    return _safe
