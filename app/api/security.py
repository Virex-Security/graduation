"""
Security Manager - Request security validation and threat detection
"""
import re
import os
import time
import logging
import requests
import hmac
import threading

from collections import defaultdict, deque
from flask import request
from dotenv import load_dotenv
import redis

from app import config
from app.ml.inference import ml_analyze, MLDecision

from app.security import build_event

load_dotenv()

logger = logging.getLogger(__name__)


class SimpleSecurityManager:
    """Thin wrapper around ThreatService for backward compatibility."""

    def __init__(self):
        from app.services.threat_service import ThreatService
        from app.services.rule_service import RuleService
        self.threat_service = ThreatService()
        self.rule_service = RuleService()
        self.rule_service.initialize_rules()

    @property
    def total_requests(self):
        return self.threat_service.get_stats().get("total_requests", 0)

    @property
    def blocked_requests(self):
        return self.threat_service.get_stats().get("blocked_requests", 0)

    def check_rate_limit(self, ip, window=None, limit=None):
        return self.threat_service.check_rate_limit(ip, request.path)

    def log_to_dashboard(self, *args, **kwargs):
        return self.threat_service.notify_dashboard(*args, **kwargs)

    def check_request_security(self, data, ip):
        return self.threat_service.scan_request_data(
            data, ip, request.path, request.method, getattr(request, "request_id", "")
        )

    def _persist_stats(self):
        pass # Now live in DB
      )
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
                    log_ml_detection(
                        text[:120], decision.risk_score, "monitor",
                        decision.attack_type, ip, request.path
                    )
                except Exception:
                    pass

            return True

        if not scan(data):
            return False, "Malicious content detected"
        return True, "OK"
