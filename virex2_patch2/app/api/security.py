"""
Security Manager - Request security validation and threat detection
"""
import re
import os
import time
import logging
import requests
import threading
from collections import defaultdict, deque
from flask import request
from dotenv import load_dotenv
from app.ml.inference import ml_analyze, MLDecision
from app.security import build_event

load_dotenv()

logger = logging.getLogger(__name__)


class SimpleSecurityManager:
    """Security manager with ML Risk Score + persistent stats."""

    def __init__(self):
        # ── Load persisted stats ──────────────────────────────
        from app.api.persistence import load_stats
        _s = load_stats()
        self.total_requests       = _s.get("total_requests", 0)
        self.blocked_requests     = _s.get("blocked_requests", 0)

        self.sql_injection_count  = 0
        self.ml_detections        = 0
        self.ml_monitor_count     = 0
        self.xss_count            = 0
        self.cmd_injection_count  = 0
        self.path_traversal_count = 0
        self.brute_force_count    = 0
        self.rate_limit_hits      = 0
        self.rate_limit_storage   = defaultdict(deque)
        self.start_time           = time.time()
        self.dashboard_url        = os.getenv("DASHBOARD_URL", "http://127.0.0.1:8070")
        self._stats_lock          = threading.Lock()

        # ── Regex Patterns ────────────────────────────────────
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
        self.cmd_patterns = [
            r"(;|\|{1,2}|&&|`)\s*(cat|ls|rm|wget|curl|nc|bash|sh|python|perl|ruby|php)\b",
            r"\$\(.*\)",
            r"`[^`]+`",
            r"(\/etc\/passwd|\/etc\/shadow|\/proc\/self)",
        ]
        self.path_patterns = [
            r"\.\./",
            r"\.\.\\",
            r"%2e%2e[%2f%5c]",
            r"(etc/passwd|etc/shadow|windows/system32|boot\.ini)",
        ]

        self.compiled_sql_patterns  = [re.compile(p, re.IGNORECASE | re.DOTALL) for p in self.sql_patterns]
        self.compiled_xss_patterns  = [re.compile(p, re.IGNORECASE | re.DOTALL) for p in self.xss_patterns]
        self.compiled_cmd_patterns  = [re.compile(p, re.IGNORECASE) for p in self.cmd_patterns]
        self.compiled_path_patterns = [re.compile(p, re.IGNORECASE) for p in self.path_patterns]

    # ── Persist stats periodically ────────────────────────────
    def _persist_stats(self):
        try:
            from app.api.persistence import save_stats
            save_stats(self.total_requests, self.blocked_requests)
        except Exception as e:
            logger.error(f"[STATS] persist failed: {e}")

    # ── Dashboard ─────────────────────────────────────────────
    def log_to_dashboard(self, threat_type, ip, description, severity="Medium",
                         endpoint="", method="", snippet="", detection_type="Other",
                         blocked=True, request_id="", risk_score=None):
        payload = {
            "type": threat_type, "ip": ip, "description": description,
            "severity": severity, "endpoint": endpoint, "method": method,
            "snippet": snippet, "detection_type": detection_type,
            "blocked": blocked, "request_id": request_id,
        }
        if risk_score is not None:
            payload["risk_score"] = round(risk_score * 100, 1)

        def send():
            try:
                requests.post(f"{self.dashboard_url}/api/dashboard/threat", json=payload, timeout=2)
            except Exception:
                pass

        threading.Thread(target=send, daemon=True).start()

    def update_dashboard_stats(self):
        pass

    # ── Regex Detectors ───────────────────────────────────────
    def _regex_detect(self, patterns, text, ip, attack_name, counter_attr, severity="High"):
        for pattern in patterns:
            if pattern.search(text):
                setattr(self, counter_attr, getattr(self, counter_attr) + 1)
                logger.info(f"[REGEX-{attack_name.upper()}] Blocked {ip} — {text[:80]}")
                self.log_to_dashboard(
                    attack_name, ip,
                    f"[REGEX] {attack_name} detected: {text[:60]}",
                    severity,
                    endpoint=request.path, method=request.method,
                    snippet=text[:100], detection_type="Signature-based",
                    blocked=True, request_id=getattr(request, "request_id", ""),
                )
                # ── Persist to user_attacks ───────────────────
                try:
                    from app.api.persistence import append_user_attack
                    user_key = getattr(request, "current_username", ip)
                    append_user_attack(user_key, attack_name, ip, request.path, request.method, severity)
                except Exception:
                    pass
                return True
        return False

    def detect_sql_injection(self, text, ip):
        return self._regex_detect(self.compiled_sql_patterns, text, ip,
                                  "SQL Injection", "sql_injection_count", "High")

    def detect_xss(self, text, ip):
        return self._regex_detect(self.compiled_xss_patterns, text, ip,
                                  "XSS", "xss_count", "High")

    def detect_command_injection(self, text, ip):
        return self._regex_detect(self.compiled_cmd_patterns, text, ip,
                                  "Command Injection", "cmd_injection_count", "Critical")

    def detect_path_traversal(self, text, ip):
        return self._regex_detect(self.compiled_path_patterns, text, ip,
                                  "Path Traversal", "path_traversal_count", "High")

    # ── Rate Limit ────────────────────────────────────────────
    def check_rate_limit(self, ip):
        now = time.time()
        q   = self.rate_limit_storage[ip]
        while q and now - q[0] > 10:
            q.popleft()
        if len(q) >= 10:
            self.rate_limit_hits += 1
            self.log_to_dashboard(
                "Rate Limit", ip, "Rate limit exceeded", "Medium",
                endpoint=request.path, method=request.method,
                detection_type="Rule-based", blocked=True,
                request_id=getattr(request, "request_id", ""),
            )
            return False
        q.append(now)
        return True

    # ── Main Security Check ───────────────────────────────────
    def check_request_security(self, data, ip):
        def scan(value):
            if isinstance(value, dict):
                return all(scan(v) for v in value.values())
            if isinstance(value, list):
                return all(scan(item) for item in value)
            if value is None:
                return True

            text = str(value)

            # Layer 1: Rules
            if self.detect_sql_injection(text, ip):    return False
            if self.detect_xss(text, ip):              return False
            if self.detect_command_injection(text, ip): return False
            if self.detect_path_traversal(text, ip):   return False

            # Layer 2: ML
            decision: MLDecision = ml_analyze(text)

            if decision.should_block:
                self.ml_detections += 1
                logger.info(f"[ML-BLOCK] {decision.attack_type} ip={ip} score={decision.risk_score:.2%}")
                self.log_to_dashboard(
                    decision.attack_type, ip,
                    f"[ML] Blocked score={decision.risk_score:.0%}: {text[:60]}",
                    "High", endpoint=request.path, method=request.method,
                    snippet=text[:100], detection_type="ML Model",
                    blocked=True, request_id=getattr(request, "request_id", ""),
                    risk_score=decision.risk_score,
                )
                try:
                    from app.api.persistence import append_user_attack, log_ml_detection
                    user_key = getattr(request, "current_username", ip)
                    append_user_attack(user_key, decision.attack_type, ip,
                                       request.path, request.method, "High")
                    log_ml_detection(text[:120], decision.risk_score, "block",
                                     decision.attack_type, ip, request.path)
                except Exception:
                    pass
                return False

            elif decision.should_monitor:
                self.ml_monitor_count += 1
                logger.info(f"[ML-MONITOR] {decision.attack_type} ip={ip} score={decision.risk_score:.2%}")
                self.log_to_dashboard(
                    decision.attack_type, ip,
                    f"[ML-MONITOR] score={decision.risk_score:.0%}: {text[:60]}",
                    "Medium", endpoint=request.path, method=request.method,
                    snippet=text[:100], detection_type="ML Model",
                    blocked=False, request_id=getattr(request, "request_id", ""),
                    risk_score=decision.risk_score,
                )
                try:
                    from app.api.persistence import log_ml_detection
                    log_ml_detection(text[:120], decision.risk_score, "monitor",
                                     decision.attack_type, ip, request.path)
                except Exception:
                    pass

            return True

        if not scan(data):
            return False, "Malicious content detected"
        return True, "OK"
