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
    """Security manager with DB-rules (Layer 1) + ML Risk Score (Layer 2)."""

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
<<<<<<< HEAD
        self.rate_limit_storage   = defaultdict(deque)
=======
>>>>>>> 4c5ae8566bbeb2af6ffddd6da0dc25f97d5a40fa
        self.start_time           = time.time()
        self.dashboard_url        = os.getenv("DASHBOARD_URL", "http://127.0.0.1:8070")
        self._stats_lock          = threading.Lock()

        # ── Load WAF rules from DB ────────────────────────────
        self._load_db_rules()

    # ── DB Rule Loader ────────────────────────────────────────
    def _load_db_rules(self):
        """
        Load rules from the 'rules' DB table and compile their regex patterns.
        Populates self._compiled_db_rules: {type -> [(compiled, rule_dict), ...]}
        """
        from app.api.persistence import get_rules
        from app import database as _db

        # Ensure rules table exists and is seeded BEFORE querying
        _db._seed_rules_table()

        db_rules = get_rules(active_only=True)
        logger.debug("[DEBUG] SimpleSecurityManager: loaded {len(db_rules)} rule(s) from DB")

        self._db_rules = db_rules  # keep raw list for reference

        # type -> list of (compiled_pattern, rule_dict)
        self._compiled_db_rules: dict = {}
        for rule in db_rules:
            rtype   = rule.get("type", "unknown").lower()
            pattern = rule.get("pattern", "")
            if not pattern:
                continue
            try:
                compiled = re.compile(pattern, re.IGNORECASE | re.DOTALL)
                self._compiled_db_rules.setdefault(rtype, []).append((compiled, rule))
            except re.error as exc:
                logger.debug("[DEBUG] Bad regex in rule '{rule.get('name)}': {exc}")

        # DB severity (lowercase) -> display severity (Title case)
        self._severity_map = {
            "critical": "Critical",
            "high":     "High",
            "medium":   "Medium",
            "low":      "Low",
        }

        # DB type -> stats counter attribute name
        self._type_counter_map = {
            "sql_injection":     "sql_injection_count",
            "xss":               "xss_count",
            "command_injection": "cmd_injection_count",
            "path_traversal":    "path_traversal_count",
        }

        # DB type -> human-readable display name
        self._type_display_map = {
            "sql_injection":     "SQL Injection",
            "xss":               "XSS",
            "command_injection": "Command Injection",
            "path_traversal":    "Path Traversal",
        }

        total_patterns = sum(len(v) for v in self._compiled_db_rules.values())
        logger.debug(
            f"[DEBUG] Compiled {total_patterns} pattern(s) across "
            f"{len(self._compiled_db_rules)} rule type(s): "
            f"{list(self._compiled_db_rules.keys())}"
        )

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
                requests.post(
                    f"{self.dashboard_url}/api/dashboard/threat",
                    json=payload, timeout=2
                )
            except Exception:
                pass

        threading.Thread(target=send, daemon=True).start()

    def update_dashboard_stats(self):
        pass

    # ── DB Rule Detector ──────────────────────────────────────
    def _apply_db_rules(self, text: str, ip: str) -> bool:
        """
        Scan *text* against all active rules loaded from the DB.
        Returns True if a rule matched → request should be BLOCKED.
        Prints debug info on every triggered match.

        Field names match DB columns:
          rule["type"]     → attack category  (e.g. "sql_injection")
          rule["severity"] → threat level     (e.g. "high")
          rule["pattern"]  → compiled regex
          rule["name"]     → human-readable name
          rule["action"]   → "block" | "monitor"
        """
        for rtype, rule_entries in self._compiled_db_rules.items():
            for compiled_pattern, rule in rule_entries:
                if compiled_pattern.search(text):
                    display_name = self._type_display_map.get(
                        rtype, rtype.replace("_", " ").title()
                    )
                    severity_raw = rule.get("severity", "high").lower()
                    severity     = self._severity_map.get(severity_raw, "High")
                    counter_attr = self._type_counter_map.get(rtype)
                    rule_name    = rule.get("name", "Unknown Rule")
                    action       = rule.get("action", "block").lower()

                    logger.debug(
                        f"[DEBUG] Rule TRIGGERED: '{rule_name}' | type={rtype} | "
                        f"severity={severity} | action={action} | ip={ip} | "
                        f"snippet={text[:60]!r}"
                    )

                    if counter_attr and hasattr(self, counter_attr):
                        setattr(self, counter_attr, getattr(self, counter_attr) + 1)

                    logger.info(
                        f"[RULE-{rtype.upper()}] Blocked {ip} — "
                        f"rule='{rule_name}' — {text[:80]}"
                    )

                    self.log_to_dashboard(
                        display_name, ip,
                        f"[RULE] {rule_name}: {text[:60]}",
                        severity,
                        endpoint=request.path, method=request.method,
                        snippet=text[:100], detection_type="Signature-based",
                        blocked=(action == "block"),
                        request_id=getattr(request, "request_id", ""),
                    )

                    # Persist to threat_logs / user_attacks
                    try:
                        from app.api.persistence import append_user_attack
                        user_key = getattr(request, "current_username", ip)
                        append_user_attack(
                            user_key, display_name, ip,
                            request.path, request.method, severity
                        )
                    except Exception:
                        pass

                    # Only block if action is "block"
                    return action == "block"

        return False  # no rule matched

    # ── Backwards-compat shims ────────────────────────────────
    def detect_sql_injection(self, text, ip):
        rules = {k: v for k, v in self._compiled_db_rules.items() if k == "sql_injection"}
        tmp, self._compiled_db_rules = self._compiled_db_rules, rules
        result = self._apply_db_rules(text, ip)
        self._compiled_db_rules = tmp
        return result

    def detect_xss(self, text, ip):
        rules = {k: v for k, v in self._compiled_db_rules.items() if k == "xss"}
        tmp, self._compiled_db_rules = self._compiled_db_rules, rules
        result = self._apply_db_rules(text, ip)
        self._compiled_db_rules = tmp
        return result

    def detect_command_injection(self, text, ip):
        rules = {k: v for k, v in self._compiled_db_rules.items() if k == "command_injection"}
        tmp, self._compiled_db_rules = self._compiled_db_rules, rules
        result = self._apply_db_rules(text, ip)
        self._compiled_db_rules = tmp
        return result

    def detect_path_traversal(self, text, ip):
        rules = {k: v for k, v in self._compiled_db_rules.items() if k == "path_traversal"}
        tmp, self._compiled_db_rules = self._compiled_db_rules, rules
        result = self._apply_db_rules(text, ip)
        self._compiled_db_rules = tmp
        return result

    # ── Rate Limit ────────────────────────────────────────────
    def check_rate_limit(self, ip, window: int = None, limit: int = None):
<<<<<<< HEAD
        """
        Sliding-window rate limiter.

        Default window/limit are loaded from environment to allow tuning
        without code changes. Sensible defaults: 100 req/60s per IP.
        Override per call for sensitive endpoints (e.g. login: 5/60s).
        """
        import os
        window = window or int(os.getenv("RATE_LIMIT_WINDOW", "60"))
        limit  = limit  or int(os.getenv("RATE_LIMIT_MAX",    "100"))

        now = time.time()
        q   = self.rate_limit_storage[ip]
        while q and now - q[0] > window:
            q.popleft()
        if len(q) >= limit:
            self.rate_limit_hits += 1
            self.log_to_dashboard(
                "Rate Limit", ip, "Rate limit exceeded", "Medium",
=======
        """Persistent rate limiter using SQLite."""
        import os
        from app import database as _db
        window = window or int(os.getenv("RATE_LIMIT_WINDOW", "60"))
        limit  = limit  or int(os.getenv("RATE_LIMIT_MAX",    "100"))

        # Unique key for this IP and endpoint combination
        key = f"{ip}:{request.path}"
        
        hit_count = _db.get_api_hit_count(key, window)
        if hit_count >= limit:
            self.rate_limit_hits += 1
            self.log_to_dashboard(
                "Rate Limit", ip, f"Rate limit exceeded for {request.path}", "Medium",
>>>>>>> 4c5ae8566bbeb2af6ffddd6da0dc25f97d5a40fa
                endpoint=request.path, method=request.method,
                detection_type="Rule-based", blocked=True,
                request_id=getattr(request, "request_id", ""),
            )
            return False
<<<<<<< HEAD
        q.append(now)
=======
            
        _db.log_api_hit(key)
>>>>>>> 4c5ae8566bbeb2af6ffddd6da0dc25f97d5a40fa
        return True

    # ── Main Security Check ───────────────────────────────────
    def check_request_security(self, data, ip):
        """
        Two-layer check:
          Layer 1 — DB Rules  (regex patterns from the 'rules' table)
          Layer 2 — ML Model  (risk score from the trained model)
        """
        def scan(value):
            if isinstance(value, dict):
                return all(scan(v) for v in value.values())
            if isinstance(value, list):
                return all(scan(item) for item in value)
            if value is None:
                return True

            text = str(value)

            # ── Layer 1: DB Rules ─────────────────────────────
            logger.debug("[DEBUG] Scanning value (len={len(text)}): {text[:80]!r}")
            if self._apply_db_rules(text, ip):
                return False

            # ── Layer 2: ML ───────────────────────────────────
            decision: MLDecision = ml_analyze(text)

            if decision.should_block:
                self.ml_detections += 1
                logger.info(
                    f"[ML-BLOCK] {decision.attack_type} ip={ip} "
                    f"score={decision.risk_score:.2%}"
                )
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
                    append_user_attack(
                        user_key, decision.attack_type, ip,
                        request.path, request.method, "High"
                    )
                    log_ml_detection(
                        text[:120], decision.risk_score, "block",
                        decision.attack_type, ip, request.path
                    )
                except Exception:
                    pass
                return False

            elif decision.should_monitor:
                self.ml_monitor_count += 1
                logger.info(
                    f"[ML-MONITOR] {decision.attack_type} ip={ip} "
                    f"score={decision.risk_score:.2%}"
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
