import os
import hmac
import time
import requests
import logging
import threading
import re
from flask import request
from app.ml.inference import ml_analyze
from app.repositories.threat_repo import ThreatRepository
from app.repositories.rule_repo import RuleRepository
from app.repositories.rate_limit_repo import RateLimitRepository

logger = logging.getLogger(__name__)

class ThreatService:
    """Business logic for threat detection, processing, and management."""
    
    def __init__(self):
        self.dashboard_url = os.getenv("DASHBOARD_URL", "http://127.0.0.1:8070")
        self.rl_repo = RateLimitRepository()

    def check_rate_limit(self, ip, endpoint):
        """Checks if a request exceeds the configured rate limits."""
        window = int(os.getenv("RATE_LIMIT_WINDOW", "60"))
        limit  = int(os.getenv("RATE_LIMIT_MAX",    "100"))
        
        # Specific limits for auth/login
        if any(p in endpoint for p in ["/api/auth/login", "/api/auth/refresh"]):
            limit = 5 # Strict limit for auth
            window = 60
            
        key = f"rl:{ip}:{endpoint}"
        allowed = self.rl_repo.check_and_increment(key, window, limit)
        
        if not allowed:
            self.notify_dashboard("Rate Limit", ip, f"Rate limit exceeded (Max {limit}/{window}s)", "Medium",
                                   endpoint, "Unknown", "", "Rule-based", True, getattr(request, "request_id", ""))
            return False
        return True

    def scan_request_context(self, ip, endpoint, method, request_id):
        """Checks request metadata (path, method) for early-stage threats like scanners."""
        # Scanner Detection (Sensitive Paths)
        sensitive_paths = ["/admin", "/wp-admin", "/phpmyadmin", "/.env", "/config", "/backup", "/etc/passwd"]
        normalized_path = endpoint.lower()
        if any(normalized_path.startswith(p) for p in sensitive_paths):
            self.notify_dashboard(
                "Scanner", ip, f"Sensitive path: {endpoint}", "Medium",
                endpoint=endpoint, method=method, detection_type="Scanner",
                blocked=True, request_id=request_id
            )
            ThreatRepository.log_threat(
                attack_type="Scanner", ip_address=ip, endpoint=endpoint,
                method=method, severity="Medium", description=f"Scanner attempt: {endpoint}",
                blocked=True, detection_type="Scanner"
            )
            return False, "Not Found" # Mimic 404 for scanners
        return True, "OK"

    def scan_request_data(self, data, ip, endpoint, method, request_id):
        """Recursively scans incoming request data (dict, list, str) for threats."""
        def scan(value):
            if isinstance(value, dict):
                return all(scan(v) for v in value.values())
            if isinstance(value, list):
                return all(scan(item) for item in value)
            if value is None:
                return True

            text = str(value)
            
            # 1. Signature-based (Rules)
            rules = RuleRepository.get_all(active_only=True)
            for rule in rules:
                pattern = rule.get("pattern", "")
                if not pattern: continue
                try:
                    if re.search(pattern, text, re.IGNORECASE | re.DOTALL):
                        threat_type = rule.get("type", "unknown")
                        severity = rule.get("severity", "High").title()
                        action = rule.get("action", "block").lower()
                        
                        threat_log_id = ThreatRepository.log_threat(
                            attack_type=threat_type, ip_address=ip,
                            endpoint=endpoint, method=method,
                            payload=text[:500], severity=severity,
                            description=f"[RULE] {rule.get('name', 'Unknown')}",
                            blocked=(action == "block"), detection_type="Signature-based"
                        )
                        
                        if action == "block":
                            ThreatRepository.log_blocked_event(ip, threat_type, severity, threat_log_id=threat_log_id)
                            ThreatRepository.block_ip(ip, duration_seconds=3600, reason=f"Triggered rule: {rule.get('name')}")
                        
                        self.notify_dashboard(threat_type, ip, f"Rule: {rule.get('name')}", severity,
                                               endpoint, method, text[:100], "Signature-based", action == "block", request_id)
                        
                        if action == "block":
                            return False # Found a blocking threat
                except Exception as e:
                    logger.error(f"Rule regex error: {e}")

            # 2. ML-based (Anomaly)
            ml_score, ml_label = ml_analyze(text)
            if ml_score >= 0.7:  # Threshold
                action = "block" if ml_score >= 0.9 else "monitor"
                threat_type = f"ML Detection ({ml_label})"
                severity = "Critical" if ml_score >= 0.95 else "High"
                
                threat_log_id = ThreatRepository.log_threat(
                    attack_type=threat_type, ip_address=ip,
                    endpoint=endpoint, method=method, payload=text[:500],
                    severity=severity, description=f"ML Anomaly (score={ml_score:.2f})",
                    blocked=(action == "block"), ml_detected=True, confidence=ml_score,
                    detection_type="ML Model"
                )
                
                if action == "block":
                    ThreatRepository.log_blocked_event(ip, threat_type, severity, ml_detected=True, confidence=ml_score, threat_log_id=threat_log_id)
                    ThreatRepository.block_ip(ip, duration_seconds=7200, reason=f"ML Block (score={ml_score:.2f})")
                    
                self.notify_dashboard(threat_type, ip, f"ML Score: {ml_score:.2f}", severity,
                                       endpoint, method, text[:100], "ML Model", action == "block", request_id, ml_score)
                
                if action == "block":
                    return False

            return True

        if not scan(data):
            return False, "Malicious content detected"
        return True, "OK"

    def notify_dashboard(self, threat_type, ip, description, severity, endpoint, method, snippet, detection_type, blocked, request_id, risk_score=None):
        """Asynchronous notification to the dashboard."""
        payload = {
            "type": threat_type, "ip": ip, "description": description,
            "severity": severity or "Medium", "endpoint": endpoint, "method": method,
            "snippet": snippet, "detection_type": detection_type,
            "blocked": blocked, "request_id": request_id,
        }
        if risk_score is not None:
            payload["risk_score"] = round(risk_score * 100, 1)

        def send():
            secret = os.getenv("INTERNAL_API_SECRET")
            if not secret: return
            timestamp = str(time.time())
            signature = hmac.new(secret.encode(), timestamp.encode(), 'sha256').hexdigest()
            headers = {"X-Internal-Timestamp": timestamp, "X-Internal-Token": signature}
            try:
                requests.post(f"{self.dashboard_url}/api/dashboard/threat", json=payload, headers=headers, timeout=5)
            except Exception:
                pass

        threading.Thread(target=send, daemon=True).start()

    def get_stats(self):
        return ThreatRepository.get_stats()
