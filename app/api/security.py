"""
Security Manager - Request security validation and threat detection
"""
import re
import os
import time
import logging
import requests
import threading
from concurrent.futures import ThreadPoolExecutor
from collections import defaultdict, deque
from flask import request
from dotenv import load_dotenv
from app.ml.inference import ml_analyze, MLDecision
from app.security import build_event

# Initialize a bounded thread pool to prevent DoS-induced memory exhaustion
executor = ThreadPoolExecutor(max_workers=10)

load_dotenv()

logger = logging.getLogger(__name__)


def calculate_severity(attack_type: str, ml_confidence: float = 0.0,
                       endpoint: str = "", ip_hit_count: int = 1) -> str:
    base_scores = {
        "command injection": 9, "command_injection": 9,
        "log4shell": 9,
        "sql injection": 8, "sql_injection": 8,
        "ssti": 8,
        "ssrf": 7,
        "xss": 7,
        "csrf": 7,
        "xxe": 7,
        "path traversal": 6, "path_traversal": 6,
        "brute force": 5, "brute_force": 5,
        "scanner": 2,
        "rate limit": 2,
        "rate limit exceeded": 2,
    }
    at_lower = attack_type.lower().replace("_", " ")
    score = base_scores.get(at_lower, 4)

    if ml_confidence >= 0.90:
        score += 3
    elif ml_confidence >= 0.70:
        score += 2
    elif ml_confidence > 0:
        score += 1

    sensitive = ["/login", "/admin", "/api/users", "/api/auth", "/reset", "/wp-admin", "/phpmyadmin", "/.env", "/config"]
    if any(s in endpoint for s in sensitive):
        score += 2

    if ip_hit_count > 5:
        score += 3
    elif ip_hit_count > 2:
        score += 1

    # Threshold for blocking
    if score >= 9:
        return "Critical"
    elif score >= 6:
        return "High"
    elif score >= 3:
        return "Medium"
    else:
        return "Low"


def should_block_attack(attack_type: str, ml_confidence: float = 0.0,
                        endpoint: str = "", ip_hit_count: int = 1) -> bool:
    severity = calculate_severity(attack_type, ml_confidence, endpoint, ip_hit_count)
    return severity in ("Critical", "High")


class SimpleSecurityManager:
    """Security manager with DB-rules (Layer 1) + ML Risk Score (Layer 2)."""

    def __init__(self):
        # ── Load persisted stats ──────────────────────────────
        from app.api.persistence import load_stats
        _s = load_stats()
        self.total_requests       = _s.get("total_requests", 0)
        self.blocked_requests     = _s.get("blocked_requests", 0)
        self.normal_request_count = _s.get("normal_requests_count", 0)

        self.sql_injection_count  = 0
        self.ssrf_count           = 0
        self.xxe_count            = 0
        self.ssti_count           = 0
        self.log4shell_count      = 0
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
        self.internal_secret      = os.getenv("INTERNAL_API_SECRET")
        self._stats_lock          = threading.Lock()
        self.rate_limit_lock      = threading.Lock()

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
        _db._seed_rules()

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
            "ssrf":              "ssrf_count",
            "xxe":               "xxe_count",
            "ssti":              "ssti_count",
            "log4shell":         "log4shell_count",
        }

        # DB type -> human-readable display name
        self._type_display_map = {
            "sql_injection":     "SQL Injection",
            "xss":               "Cross-Site Scripting (XSS)",
            "command_injection": "Command Injection",
            "path_traversal":    "Path Traversal",
            "ssrf":              "SSRF",
            "xxe":               "XXE",
            "ssti":              "SSTI",
            "log4shell":         "Log4Shell",
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
            save_stats(self.total_requests, self.blocked_requests, normal_requests_count=self.normal_request_count)
            self.update_dashboard_stats()
        except Exception as e:
            logger.error(f"[STATS] persist failed: {e}")

    def log_normal_request(self, ip, endpoint, method):
        """Log a normal/clean request (memory + database)."""
        self.normal_request_count += 1
        self.total_requests += 1
        
        # Asynchronously write to DB to avoid WAF filtering latency
        def run():
            try:
                from app import database as db
                db.log_normal_request(ip, endpoint, method)
            except Exception as e:
                logger.error(f"Failed async db write for normal request: {e}")

        executor.submit(run)

    # ── Dashboard ─────────────────────────────────────────────
    def log_to_dashboard(self, threat_type, ip, description, severity="Medium",
                         endpoint="", method="", snippet="", detection_type="Other",
                         blocked=True, request_id="", risk_score=None):
        payload = {
            "type": threat_type, "ip": ip, "description": description,
            "severity": severity, "endpoint": endpoint, "method": method,
            "snippet": snippet, "detection_type": detection_type,
            "blocked": blocked, "request_id": request_id,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
        }
        if risk_score is not None:
            payload["risk_score"] = round(risk_score * 100, 1)

        def send():
            try:
                headers = {"X-Internal-Token": self.internal_secret} if self.internal_secret else {}
                requests.post(
                    f"{self.dashboard_url}/api/dashboard/threat",
                    json=payload, timeout=2, headers=headers
                )
            except Exception as e:
                logger.error(f"Failed to push threat log to dashboard: {e}")

        executor.submit(send)

    def update_dashboard_stats(self):
        payload = {
            "total_requests": self.total_requests,
            "blocked_requests": self.blocked_requests,
            "normal_requests_count": self.normal_request_count,
        }
        def send():
            try:
                headers = {"X-Internal-Token": self.internal_secret} if self.internal_secret else {}
                requests.post(
                    f"{self.dashboard_url}/api/dashboard/stats",
                    json=payload, timeout=2, headers=headers
                )
            except Exception as e:
                logger.error(f"Failed to update dashboard stats: {e}")

        executor.submit(send)

    def reset(self):
        with self._stats_lock:
            self.total_requests = 0
            self.blocked_requests = 0
            self.normal_request_count = 0
            self.sql_injection_count = 0
            self.ssrf_count = 0
            self.xxe_count = 0
            self.ssti_count = 0
            self.log4shell_count = 0
            self.ml_detections = 0
            self.ml_monitor_count = 0
            self.xss_count = 0
            self.cmd_injection_count = 0
            self.path_traversal_count = 0
            self.brute_force_count = 0
            self.rate_limit_hits = 0
            self._persist_stats()

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
        # ── 1. Run strict, dedicated HTML/XSS tag pattern matching FIRST ──
        # Dedicated HTML/XSS tag patterns
        _XSS_PATTERNS = [
            re.compile(r"<script[\s>][\s\S]*?</script>", re.IGNORECASE | re.DOTALL),
            re.compile(r"<script[\s>]/?[^>]*?>", re.IGNORECASE),
            re.compile(r"(href|src)=[\"']?\s*javascript:", re.IGNORECASE),
            re.compile(r"\b(onerror|onload|onclick|onmouseover|onfocus|onchange|onunload|onkeypress|onkeydown|onkeyup)\s*=\s*['\"]*[\"'()]*", re.IGNORECASE),
            re.compile(r"document\.cookie", re.IGNORECASE),
            re.compile(r"javascript\s*:", re.IGNORECASE),
        ]

        is_xss = False
        matched_rule_name = "Strict XSS Signature"
        matched_severity = "High"
        matched_action = "block"

        for pattern in _XSS_PATTERNS:
            if pattern.search(text):
                is_xss = True
                break

        if not is_xss:
            # Also check DB rules for XSS
            xss_db_entries = self._compiled_db_rules.get("xss", [])
            for compiled_pattern, rule in xss_db_entries:
                if compiled_pattern.search(text):
                    is_xss = True
                    matched_rule_name = rule.get("name", "XSS Rule")
                    matched_severity = self._severity_map.get(rule.get("severity", "high").lower(), "High")
                    matched_action = rule.get("action", "block").lower()
                    break

        if is_xss:
            display_name = "Cross-Site Scripting (XSS)"
            self.xss_count += 1
            try:
                request.is_attack = True
            except Exception:
                pass

            logger.info(
                f"[RULE-XSS] Blocked {ip} — "
                f"rule='{matched_rule_name}' — {text[:80]}"
            )

            # Store match metadata for the caller to persist once
            try:
                request._rule_match_info = {
                    "display_name": display_name,
                    "severity": matched_severity,
                    "rule_name": matched_rule_name,
                    "rtype": "xss",
                    "action": matched_action,
                }
            except Exception:
                pass

            return matched_action == "block"

        # ── 2. Run SQL Injection rules SECOND ──
        sqli_db_entries = self._compiled_db_rules.get("sql_injection", [])
        for compiled_pattern, rule in sqli_db_entries:
            if compiled_pattern.search(text):
                display_name = "SQL Injection"
                severity_raw = rule.get("severity", "critical").lower()
                severity     = self._severity_map.get(severity_raw, "Critical")
                rule_name    = rule.get("name", "SQL Injection Rule")
                action       = rule.get("action", "block").lower()

                self.sql_injection_count += 1
                try:
                    request.is_attack = True
                except Exception:
                    pass

                logger.info(
                    f"[RULE-SQLI] Blocked {ip} — "
                    f"rule='{rule_name}' — {text[:80]}"
                )

                # Store match metadata for the caller to persist once
                try:
                    request._rule_match_info = {
                        "display_name": display_name,
                        "severity": severity,
                        "rule_name": rule_name,
                        "rtype": "sql_injection",
                        "action": action,
                    }
                except Exception:
                    pass

                return action == "block"

        # ── 3. Check all other DB rules ──
        other_categories = [k for k in self._compiled_db_rules.keys() if k not in ("xss", "sql_injection")]
        for rtype in other_categories:
            for compiled_pattern, rule in self._compiled_db_rules[rtype]:
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

                    try:
                        request.is_attack = True
                    except Exception:
                        pass

                    logger.info(
                        f"[RULE-{rtype.upper()}] Blocked {ip} — "
                        f"rule='{rule_name}' — {text[:80]}"
                    )

                    # Store match metadata for the caller to persist once
                    try:
                        request._rule_match_info = {
                            "display_name": display_name,
                            "severity": severity,
                            "rule_name": rule_name,
                            "rtype": rtype,
                            "action": action,
                        }
                    except Exception:
                        pass

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
        """
        Centralized distributed sliding-window rate limiter.
        Tries Redis-based Sorted Sets (ZSET) sliding-window.
        If Redis is not available, falls back to Database-based rate limiting.
        """
        import os
        import random
        from app import database as db
        from sqlalchemy import text

        window = window or int(os.getenv("RATE_LIMIT_WINDOW", "60"))
        limit  = limit  or int(os.getenv("RATE_LIMIT_MAX",    "100"))
        now = time.time()

        # ── 1. Attempt Redis ──────────────────────────────────
        redis_url = os.getenv("REDIS_URL")
        if redis_url:
            try:
                import redis
                # Establish connection with timeout to prevent blocking WAF
                r = redis.Redis.from_url(redis_url, socket_connect_timeout=2, socket_timeout=2)
                key = f"rate_limit:{ip}"
                
                # Setup transaction pipeline
                pipe = r.pipeline()
                # Clear expired elements outside the sliding window
                pipe.zremrangebyscore(key, 0, now - window)
                # Count current requests in window
                pipe.zcard(key)
                # Execute pipeline to get count BEFORE adding the current request
                results = pipe.execute()
                current_count = results[1]
                
                if current_count >= limit:
                    self.rate_limit_hits += 1
                    try:
                        request.is_attack = True
                    except Exception:
                        pass
                    return False
                
                # Add current request to window and refresh expiration
                pipe = r.pipeline()
                pipe.zadd(key, {f"{now}:{random.random()}": now})
                pipe.expire(key, window + 5)
                pipe.execute()
                return True
            except Exception as e:
                logger.warning(f"[RATE LIMIT] Redis check failed, falling back to Database: {e}")

        # ── 2. Database Fallback Rate Limiter ────────────────
        try:
            with db._db() as conn:
                # Remove expired records for this IP address
                conn.execute(text("""
                    DELETE FROM rate_limits 
                    WHERE ip_address = :ip AND timestamp < :cutoff
                """), {"ip": ip, "cutoff": now - window})

                # Count remaining requests in the window
                row = conn.execute(text("""
                    SELECT COUNT(*) FROM rate_limits 
                    WHERE ip_address = :ip
                """), {"ip": ip}).fetchone()
                current_count = row[0] if row else 0

                if current_count >= limit:
                    self.rate_limit_hits += 1
                    try:
                        request.is_attack = True
                    except Exception:
                        pass
                    conn.commit()
                    return False

                # Register the new request
                conn.execute(text("""
                    INSERT INTO rate_limits (ip_address, timestamp)
                    VALUES (:ip, :ts)
                """), {"ip": ip, "ts": now})
                conn.commit()
                return True
        except Exception as e:
            logger.error(f"[RATE LIMIT] Centralized database fallback rate limiter failed: {e}")
            
            # Local fallback just in case database connection fails to avoid completely taking down the app
            with self.rate_limit_lock:
                q = self.rate_limit_storage[ip]
                while q and now - q[0] > window:
                    q.popleft()
                if len(q) >= limit:
                    self.rate_limit_hits += 1
                    try:
                        request.is_attack = True
                    except Exception:
                        pass
                    return False
                q.append(now)
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
                # Consolidate persistence: log the rule match exactly once
                try:
                    from app.api.persistence import append_user_attack
                    match_info = getattr(request, '_rule_match_info', None)
                    if match_info:
                        user_key = getattr(request, "current_username", ip)
                        append_user_attack(
                            user_key, match_info["display_name"], ip,
                            request.path, request.method, match_info["severity"]
                        )
                except Exception:
                    pass
                return False

            # ── Layer 2: ML ───────────────────────────────────
            decision: MLDecision = ml_analyze(text)

            if decision.should_block:
                self.ml_detections += 1
                try:
                    request.is_attack = True
                except Exception:
                    pass
                logger.info(
                    f"[ML-BLOCK] {decision.attack_type} ip={ip} "
                    f"score={decision.risk_score:.2%}"
                )
                try:
                    from app.api.persistence import append_user_attack, log_ml_detection
                    user_key = getattr(request, "current_username", ip)
                    severity = calculate_severity(
                        decision.attack_type,
                        ml_confidence=decision.risk_score,
                        endpoint=request.path
                    )
                    append_user_attack(
                        user_key, decision.attack_type, ip,
                        request.path, request.method, severity
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
                # NOTE: do NOT set request.is_attack = True here — monitored requests
                # are logged for analysis but are allowed through (not blocked).
                # Only the should_block path above sets is_attack = True.
                logger.info(
                    f"[ML-MONITOR] {decision.attack_type} ip={ip} "
                    f"score={decision.risk_score:.2%}"
                )
                try:
                    from app.api.persistence import append_user_attack, log_ml_detection
                    user_key = getattr(request, "current_username", ip)
                    severity = calculate_severity(
                        decision.attack_type,
                        ml_confidence=decision.risk_score,
                        endpoint=request.path
                    )
                    append_user_attack(
                        user_key, decision.attack_type, ip,
                        request.path, request.method, severity
                    )
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
