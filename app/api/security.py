"""
Security Manager - Request security validation and threat detection
"""
import time
import re
import logging
import requests
import threading
from collections import defaultdict, deque
import os
from flask import request
from dotenv import load_dotenv
from app.ml import ml_detect
from app.security import build_event

load_dotenv("env")

logger = logging.getLogger(__name__)


class SimpleSecurityManager:
    """Simplified security manager for testing with ML integration"""

    def __init__(self):
        self.total_requests = 0
        self.blocked_requests = 0
        self.sql_injection_count = 0
        # track ML detections separately for metrics/logging
        self.ml_detections = 0
        self.xss_count = 0
        self.brute_force_count = 0
        self.rate_limit_hits = 0
        self.rate_limit_storage = defaultdict(deque)
        self.start_time = time.time()
        self.dashboard_url = os.getenv("DASHBOARD_URL", "http://127.0.0.1:8070")

        # Robust patterns
        self.sql_patterns = [
            r"(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|UNION|EXEC|TRUNCATE|GRANT|REVOKE)",
            r"(\bOR\b|\bAND\b).+(\=|\bLIKE\b|\bIN\b)",
            r"(--|#|/\*|\*/|;|@@|\bSLEEP\b|\bBENCHMARK\b|\bWAITFOR\b)",
            r"('|%27).+(\bOR\b|\bAND\b).+",
            r"UNION\s+SELECT",
        ]

        self.xss_patterns = [
            r"<script.*?>.*?</script>",
            r"javascript:",
            r"onerror\s*=",
            r"onload\s*=",
            r"onclick\s*=",
            r"<iframe.*?>",
            r"<svg.*?>",
            r"<img.*?onerror",
            r"<body.*?onload",
            r"alert\(.*\)",
        ]

        self.compiled_sql_patterns = [re.compile(p, re.IGNORECASE) for p in self.sql_patterns]
        self.compiled_xss_patterns = [re.compile(p, re.IGNORECASE) for p in self.xss_patterns]

    # ================= DASHBOARD =================
    def log_to_dashboard(
        self,
        threat_type,
        ip,
        description,
        severity="Medium",
        endpoint="",
        method="",
        snippet="",
        detection_type="Other",
        blocked=True,
        request_id="",
    ):
        def send_log():
            try:
                logger.debug(f"[TRACE] sending to dashboard request_id={request_id} type={threat_type} ip={ip}")
                requests.post(
                    f"{self.dashboard_url}/api/dashboard/threat",
                    json={
                        "type": threat_type,
                        "ip": ip,
                        "description": description,
                        "severity": severity,
                        "endpoint": endpoint,
                        "method": method,
                        "snippet": snippet,
                        "detection_type": detection_type,
                        "blocked": blocked,
                        "request_id": request_id,
                    },
                    timeout=2,
                )
            except Exception:
                pass

        threading.Thread(target=send_log, daemon=True).start()

    def update_dashboard_stats(self):
        # Disabled pushing local memory stats to dashboard
        # Dashboard recalculates its own accurate stats from siem_audit.json
        pass

    # ================= REGEX =================
    def detect_sql_injection(self, text, ip):
        for pattern in self.compiled_sql_patterns:
            if pattern.search(text):
                self.sql_injection_count += 1
                logger.info(f"[REGEX-SQLi] Blocked {ip} — {text[:80]}")
                logger.debug(f"[REGEX-SQL] raw_text='{text[:80]}'")
                self.log_to_dashboard(
                    "SQL Injection",
                    ip,
                    f"[REGEX] SQL Injection detected — pattern matched in: {text[:60]}",
                    "High",
                    endpoint=request.path,
                    method=request.method,
                    snippet=text[:100],
                    detection_type="Signature-based",
                    blocked=True,
                    request_id=getattr(request, "request_id", ""),
                )
                return True
        return False

    def detect_xss(self, text, ip):
        for pattern in self.compiled_xss_patterns:
            if pattern.search(text):
                self.xss_count += 1
                logger.info(f"[REGEX-XSS] Blocked {ip} — {text[:80]}")
                logger.debug(f"[REGEX-XSS] raw_text='{text[:80]}'")
                self.log_to_dashboard(
                    "XSS",
                    ip,
                    f"[REGEX] XSS detected — pattern matched in: {text[:60]}",
                    "High",
                    endpoint=request.path,
                    method=request.method,
                    snippet=text[:100],
                    detection_type="Signature-based",
                    blocked=True,
                    request_id=getattr(request, "request_id", ""),
                )
                return True
        return False

    # ================= RATE LIMIT =================
    def check_rate_limit(self, ip):
        now = time.time()
        q = self.rate_limit_storage[ip]

        # 10 second window
        while q and now - q[0] > 10:
            q.popleft()

        if len(q) >= 10:
            self.rate_limit_hits += 1
            logger.debug(f"[RATE] limit hit for ip={ip}")
            self.log_to_dashboard(
                "Rate Limit",
                ip,
                "Rate limit exceeded",
                "Medium",
                endpoint=request.path,
                method=request.method,
                detection_type="Rule-based",
                blocked=True,
                request_id=getattr(request, "request_id", ""),
            )
            return False

        q.append(now)
        return True

    # ================= MAIN SECURITY =================
    def check_request_security(self, data, ip):
        def classify_ml_attack(text):
            t = str(text)
            for patt in self.compiled_sql_patterns:
                if patt.search(t):
                    return "SQL Injection"
            for patt in self.compiled_xss_patterns:
                if patt.search(t):
                    return "XSS"
            if re.search(r"(password|login|user|admin)", t, re.IGNORECASE):
                return "Brute Force"
            return "Unknown"

        def scan(value):
            if isinstance(value, dict):
                for v in value.values():
                    if not scan(v):
                        return False
            elif isinstance(value, list):
                for item in value:
                    if not scan(item):
                        return False
            elif value is not None:
                text = str(value)

                # Regex FIRST
                if self.detect_sql_injection(text, ip):
                    return False
                if self.detect_xss(text, ip):
                    return False

                # ML SECOND
                is_mal, raw_pred = ml_detect(text)
                if is_mal:
                    self.ml_detections += 1
                    attack_label = classify_ml_attack(text)
                    detection_method = "ML Model"
                    logger.info(f"[ML-MODEL] {attack_label} flagged for {ip} (raw={raw_pred})")

                    logger.debug(
                        f"[ML-RAW] text='{text[:100]}', attack_type='{attack_label}', "
                        f"detection_method='{detection_method}', prediction={raw_pred}"
                    )

                    self.log_to_dashboard(
                        attack_label,
                        ip,
                        f"[ML] Anomaly detected — suspicious payload: {text[:60]}",
                        "High",
                        endpoint=request.path,
                        method=request.method,
                        snippet=text[:100],
                        detection_type=detection_method,
                        blocked=True,
                        request_id=getattr(request, "request_id", ""),
                    )
                    return False

            return True

        if not scan(data):
            return False, "Malicious content detected"

        return True, "OK"
