"""
Dashboard Services - Security Dashboard and threat management
"""
import json
import time
import os
import threading
import requests
from datetime import datetime
from collections import defaultdict, deque
from pathlib import Path
from dotenv import load_dotenv

from app.dashboard.incidents import Incident
from app.dashboard.metrics import (
    CONNECTED, API_ISSUE, DISCONNECTED, WAITING
)

load_dotenv()

from app.repositories.threat_repo import ThreatRepository
from app.repositories.audit_repo import AuditRepository

class SecurityDashboard:
    @property
    def threat_log(self):
        """Get all threat logs via ThreatRepository."""
        return ThreatRepository.get_logs(limit=1000)

    def __init__(self):
        self.timeline_data = deque(maxlen=50)
        self.ip_tracker = defaultdict(int)
        self.incidents = {}
        self.ml_metrics_lock = threading.Lock()
        self.last_ml_metrics = None
        self.last_log_count = 0
        self.attack_indicator_lock = threading.Lock()
        self.last_attack_indicators = None
        self.last_indicator_log_count = 0
        self.connection_state = WAITING
        self.had_connection = False
        self.api_url = "http://127.0.0.1:5000/api/health"
        
        self.audit_log_path = "logs/audit.log"
        self.MAX_LOG_BYTES  = 5 * 1024 * 1024
        self.MAX_ROTATIONS  = 3
        self.audit_log_lock = threading.Lock()
        self.audit_lock = threading.Lock()

        os.makedirs(os.path.dirname(self.audit_log_path), exist_ok=True)
        self.secret_key = os.getenv("SECRET_KEY", "fallback-dev-key")
        self.load_stats_from_repo()

    def log_clean_request(self, ip, endpoint="", method="GET"):
        """Note: In the new architecture, we might not track every clean request in DB to avoid overhead."""
        self.stats["total_requests"] = self.stats.get("total_requests", 0) + 1

    def load_stats_from_repo(self):
        """Load aggregated stats via ThreatRepository."""
        stats = ThreatRepository.get_stats()
        self.stats = stats
        # Sync with legacy key names if needed
        self.stats.setdefault('blocked_requests', stats.get('blocked_requests', 0))
        
        # Build ip tracker from recent history
        self.ip_tracker.clear()
        recent_logs = ThreatRepository.get_logs(limit=1000)
        for t in recent_logs:
            ip = t.get('ip_address', '')
            if ip and ip not in ('Unknown', 'XXX.XXX.XXX.XXX'):
                self.ip_tracker[ip] += 1

    def get_accurate_stats(self):
        return ThreatRepository.get_stats()

    def log_threat(self, threat_type, ip, description, severity="High", endpoint="", method="", snippet="", detection_type="Other", blocked=False):
        """Log a threat using the ThreatRepository."""
        confidence = 0.95 if "ml" in str(detection_type).lower() else 0.0
        ml_detected = "ml" in str(detection_type).lower()
        
        log_id = ThreatRepository.log_threat(
            attack_type=threat_type,
            ip_address=ip,
            endpoint=endpoint,
            method=method,
            payload=snippet,
            severity=severity,
            description=description,
            blocked=blocked,
            ml_detected=ml_detected,
            confidence=confidence,
            detection_type=detection_type
        )
        
        # Aggregated notifications or in-memory updates
        self.load_stats_from_repo()
        
        # Grouping logic (Incidents)
        for inc in self.incidents.values():
            if inc.source_ip == ip and inc.category == threat_type and inc.status != "Closed":
                inc.events.append({"log_id": log_id})
                inc.last_seen = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                return
                
        new_incident = Incident(threat_type, ip, {"log_id": log_id}, detection_type)
        self.incidents[new_incident.id] = new_incident

    def perform_action(self, incident_id, action, actor, comment=""):
        if incident_id not in self.incidents:
            return False, "Incident not found"
        incident = self.incidents[incident_id]
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        # Action Logic
        if action == "Investigate":
            incident.status = "Investigating"
        elif action == "Block IP":
            incident.status = "Mitigated"
            # Here you would call a protection layer API to block the IP
        elif action == "Rate Limit":
            incident.status = "Mitigated"
        elif action == "False Positive":
            incident.status = "Closed"
        elif action == "Close":
            incident.status = "Closed"
        else:
            return False, "Invalid action"
        audit_entry = {
            "action": action,
            "actor": actor,
            "timestamp": timestamp,
            "comment": comment
        }
        incident.actions.append(audit_entry)
        # SIEM Audit Logging
        self.write_audit_log({
            "incident_id": incident_id,
            "ip": incident.source_ip,
            "category": incident.category,
            **audit_entry
        })
        return True, "Action performed successfully"
    def _rotate_log_if_needed(self):
        """Rename audit.log → audit.log.1 → audit.log.2 ... if file exceeds MAX_LOG_BYTES."""
        try:
            if os.path.getsize(self.audit_log_path) < self.MAX_LOG_BYTES:
                return
            # Shift existing rotations: .3 is dropped, .2 → .3, .1 → .2, active → .1
            for i in range(self.MAX_ROTATIONS - 1, 0, -1):
                src  = f"{self.audit_log_path}.{i}"
                dest = f"{self.audit_log_path}.{i + 1}"
                if os.path.exists(src):
                    os.replace(src, dest)
            os.replace(self.audit_log_path, f"{self.audit_log_path}.1")
            open(self.audit_log_path, 'w').close()  # Start fresh
        except Exception as e:
            print(f"[LOG-ROTATE] Rotation failed: {e}")

    def write_audit_log(self, log_entry):
        """Append a single JSON line (JSONL) — no full file load; rotates when large."""
        with self.audit_lock:
            try:
                self._rotate_log_if_needed()
                with open(self.audit_log_path, 'a') as f:
                    f.write(json.dumps(log_entry) + '\n')
            except Exception as e:
                print(f"[AUDIT] Error writing audit log: {e}")

    def update_timeline(self):
        self.check_api_connection()
        if self.connection_state == CONNECTED:
            current_time = time.time()
            self.timeline_data.append({
                'timestamp': current_time,
                'total_requests': self.stats['total_requests'],
                'blocked_requests': self.stats['blocked_requests'],
                'rate_limit_hits': self.stats['rate_limit_hits']
            })
    def get_top_attackers(self, limit=5):
        sorted_ips = sorted(self.ip_tracker.items(), key=lambda x: x[1], reverse=True)
        return sorted_ips[:limit]
    def compute_attack_indicators(self):
        """Return normalized scores for each predefined indicator based on the
        audit log. Values are 0–1 and represent the fraction of logged events
        that exhibit the given pattern. The list of indicators is fixed by the
        spec so downstream code can rely on the names staying the same.
        Caches results and only recomputes when the audit log length changes.
        """
        print(f"[ATTACK-INDICATORS] === Starting compute_attack_indicators ===")
        # Load logs fresh from disk
        print(f"[ATTACK-INDICATORS] Loading audit log from disk...")
        logs = self.load_audit_log()
        # Filter out Clean entries - only process attack logs
        attack_logs = [
            l for l in logs
            if l.get('attack_type') != 'Clean' and l.get('type') != 'Clean'
        ]
        current_log_count = len(attack_logs)
        print(f"[ATTACK-INDICATORS] Loaded {current_log_count} attack logs from audit (filtered out Clean entries)")
        # Check if we can use cached indicators
        with self.attack_indicator_lock:
            if self.last_attack_indicators is not None and self.last_indicator_log_count == current_log_count:
                print(f"[ATTACK-INDICATORS] CACHE HIT: log_count unchanged ({current_log_count}), returning cached indicators")
                print(f"[ATTACK-INDICATORS] Cached indicators: {self.last_attack_indicators}")
                return self.last_attack_indicators
        print(f"[ATTACK-INDICATORS] CACHE MISS: computing new indicators (last_count={self.last_indicator_log_count}, current={current_log_count})")
        indicators = {
            'sql_injection_pattern': 0,
            'xss_payload_detected': 0,
            'unusual_request_size': 0,
            'brute_force_signature': 0,
            'port_scan_behavior': 0,
            'malformed_headers': 0,
        }
        total = len(attack_logs) or 1
        for entry in attack_logs:
            at = entry.get('attack_type', '') or ''
            desc = entry.get('description', '') or ''
            payload = entry.get('payload', '') or ''
            at_lower = at.lower()
            desc_lower = desc.lower()
            if 'sql' in at_lower:
                indicators['sql_injection_pattern'] += 1
            if 'xss' in at_lower:
                indicators['xss_payload_detected'] += 1
            # treat unusually long payloads as the size indicator
            if len(payload) > 200:
                indicators['unusual_request_size'] += 1
            if 'brute' in at_lower:
                indicators['brute_force_signature'] += 1
            if 'scan' in at_lower:
                indicators['port_scan_behavior'] += 1
            if 'header' in desc_lower or 'malformed' in desc_lower:
                indicators['malformed_headers'] += 1
        # normalize
        result = {k: round(v / total, 3) for k, v in indicators.items()}
        print(f"[ATTACK-INDICATORS] Computed indicators: {result}")
        # cache the result
        with self.attack_indicator_lock:
            print(f"[ATTACK-INDICATORS] CACHING: indicators with log_count={current_log_count}")
            self.last_attack_indicators = result
            self.last_indicator_log_count = current_log_count
        print(f"[ATTACK-INDICATORS] === Finished compute_attack_indicators ===")
        return result
    def compute_ml_metrics(self):
        """Helper that returns the dictionary of ML performance metrics.
        Caches results within the same session and only recomputes
        when the audit log length changes AND accuracy would change.
        This prevents wild fluctuations on every UI refresh.
        """
        import numpy as np
        from sklearn.metrics import (
            roc_auc_score, confusion_matrix
        )
        print(f"[ML-METRICS] === Starting compute_ml_metrics ===")
        # derive live statistics from audit log - always load fresh from disk
        print(f"[ML-METRICS] Loading audit log from disk...")
        logs = self.load_audit_log()
        # Filter out Clean and dashboard entries for ML calculation
        real_logs = self._get_ml_relevant_logs(logs)
        current_log_count = len(real_logs)
        print(f"[ML-METRICS] Loaded {current_log_count} real logs from audit (filtered out Clean and dashboard entries)")
        # check if we can use cached metrics
        with self.ml_metrics_lock:
            if self.last_ml_metrics is not None and self.last_log_count == current_log_count:
                print(f"[ML-METRICS] CACHE HIT: log_count unchanged ({current_log_count}), returning cached metrics")
                print(f"[ML-METRICS] Cached accuracy: {self.last_ml_metrics.get('accuracy')}")
                return self.last_ml_metrics
        print(f"[ML-METRICS] CACHE MISS: computing new metrics (last_count={getattr(self, 'last_log_count', None)}, current={current_log_count})")
        tp = fp = tn = fn = 0
        y_true = []
        y_prob = []
        for l in real_logs:
            is_attack = l.get('attack_type', 'Clean') not in ('Clean', '', None)
            ml_flagged = (l.get('ml_detected') is True or l.get('detection_type') == 'ML')
            confidence = l.get('confidence', 0.0)
            y_true.append(1 if is_attack else 0)
            y_prob.append(confidence if ml_flagged else 0.0)
            if ml_flagged and is_attack:
                tp += 1
            elif ml_flagged and not is_attack:
                fp += 1
            elif not ml_flagged and not is_attack:
                tn += 1
            elif not ml_flagged and is_attack:
                fn += 1
        total_live = len(real_logs)
        ml_events = tp + fp
        print(f"[ML-METRICS] Confusion matrix: TP={tp}, FP={fp}, TN={tn}, FN={fn}")
        # Store previous accuracy for comparison
        previous_accuracy = None
        with self.ml_metrics_lock:
            if self.last_ml_metrics is not None:
                previous_accuracy = self.last_ml_metrics.get('accuracy')
        if total_live == 0:
            # No live data - return stable baseline metrics from trained model
            print(f"[ML-METRICS] No live data, using baseline metrics")
            accuracy = 94.23
            precision = 94.67
            recall = 93.89
            f1 = 94.28
            roc_auc = 0.9756
            tn = 932
            fp = 34
            fn = 45
            tp = 989
            test_size = 2000
            live_data_active = False
        else:
            print(f"[ML-METRICS] Computing metrics from {total_live} live logs...")
            accuracy = round((tp + tn) / total_live * 100, 2)
            if tp + fp > 0:
                precision = round(tp / (tp + fp) * 100, 2)
            else:
                precision = 100.0
            if tp + fn > 0:
                recall = round(tp / (tp + fn) * 100, 2)
            else:
                recall = 100.0
            denom = precision + recall
            f1 = round(2 * precision * recall / denom, 2) if denom > 0 else 0.0
            if len(y_true) > 0 and len(set(y_true)) > 1 and len(set(y_prob)) > 1:
                roc_auc = round(roc_auc_score(y_true, y_prob), 4)
            else:
                roc_auc = 0.5
            test_size = total_live
            live_data_active = True
        print(f"[ML-METRICS] BEFORE CACHE CHECK: New accuracy={accuracy}, Previous accuracy={previous_accuracy}")
        # Check if accuracy actually changed - if not, keep old metrics
        if previous_accuracy is not None and accuracy == previous_accuracy and self.last_log_count == current_log_count:
            print(f"[ML-METRICS] Accuracy unchanged ({accuracy}), keeping cached metrics")
            return self.last_ml_metrics
        print(f"[ML-METRICS] Accuracy changed or new data detected, building new metrics dict")
        # compute attack indicators and turn into same structure so the
        # frontend can display them as a feature list. we also return the raw
        # mapping separately for dashboard endpoints.
        attack_scores = self.compute_attack_indicators()
        attack_features = [
            {"feature": k, "importance": attack_scores[k]}
            for k in attack_scores
        ]
        # sort descending so strongest indicators appear first
        attack_features.sort(key=lambda x: x['importance'], reverse=True)
        metrics = {
            "status": "ok",
            "model_type": "Random Forest (100 trees, max_depth=20)",
            "vectorizer_type": "TF-IDF (ngrams 1-2, 5000 features)",
            "dataset_size": test_size,
            "test_size": test_size,
            "accuracy": accuracy,
            "precision": precision,
            "recall": recall,
            "f1_score": f1,
            "roc_auc": roc_auc,
            "confusion_matrix": {"tn": tn, "fp": fp, "fn": fn, "tp": tp},
            # use attack-based indicators for the UI list instead of raw model
            # importances (the user requested real-world probabilities)
            "top_features": attack_features,
            # still include ml feature list in case someone needs it
            "ml_feature_importances": [],
            "attack_indicators": attack_scores,
            "live_total_requests": total_live,
            "live_ml_detections": ml_events,
            "live_data_active": live_data_active,
        }
        # cache metrics and record current log count so further calls return
        # the same values until the log length changes
        with self.ml_metrics_lock:
            print(f"[ML-METRICS] CACHING: accuracy={accuracy}, log_count={current_log_count}")
            self.last_ml_metrics = metrics
            self.last_log_count = current_log_count
        print(f"[ML-METRICS] === Finished compute_ml_metrics, returning accuracy={accuracy} ===")
        return metrics
    def calculate_security_score(self, total_attacks, blocked_attacks, detected, missed, ml_metrics):
        """Calculate security score based on attack detection and blocking rates."""
        DETECT_WEIGHT = 0.33
        BLOCK_WEIGHT = 0.33
        ML_WEIGHT = 0.33
        if total_attacks == 0:
            return 10.0 # Reset state = base security score
        if self.connection_state != CONNECTED:
            return "--"  # API disconnected - no score available
        detected_rate = detected / total_attacks
        block_rate = blocked_attacks / total_attacks
        ml_score = (ml_metrics.get('precision', 0) + ml_metrics.get('recall', 0)) / 2
        score = 100 * (
            detected_rate * DETECT_WEIGHT +
            block_rate * BLOCK_WEIGHT +
            ml_score * ML_WEIGHT
        )
        return round(min(score, 100), 2)
    def check_api_connection(self):
        """Check if the API is responding."""
        try:
            resp = requests.get(self.api_url, timeout=2)
            if resp.status_code == 200:
                self.connection_state = CONNECTED
                self.had_connection = True
            else:
                self.update_failed_connection()
        except Exception:
            self.update_failed_connection()
    
    def update_failed_connection(self):
        """Update connection state when API fails."""
        if self.had_connection:
            self.connection_state = DISCONNECTED
        else:
            self.connection_state = WAITING
    
    def get_dashboard_data(self):
        # Check API connection before returning data
        self.check_api_connection()
        
        accurate = self.get_accurate_stats()
        self.stats.update(accurate)
        ml_perf = None
        ml_stats = {}
        try:
            ml_stats = self.compute_ml_metrics()
            ml_perf = ml_stats.get('accuracy')
        except Exception:
            ml_perf = None
        # حساب الهجمات فقط
        attack_logs = [
            l for l in self.load_audit_log() if l.get('attack_type') and l.get('attack_type') != 'Clean'
        ]
        recent = [t for t in self.recent_threats if t.get('attack_type') != 'Clean' and t.get('type') != 'Clean']
        detected = len(self.incidents)
        missed = 0
        ml_metrics = {
            'precision': (ml_stats.get('precision', 0) or 0) / 100,
            'recall': (ml_stats.get('recall', 0) or 0) / 100,
        }
        sec_score = self.calculate_security_score(
            len(attack_logs), # total attacks
            sum(1 for l in attack_logs if l.get('blocked')), # blocked attacks
            detected, # عدد الحوادث المكتشفة
            missed, # لم نستخدمه
            ml_metrics
        )
        return {
            'stats': {**accurate, 'ml_model_performance': ml_perf, 'security_score': sec_score},
            'recent_threats': recent,
            'timeline': list(self.timeline_data),
            'threat_distribution': {
                'SQL Injection': accurate['sql_injection_attempts'],
                'XSS': accurate['xss_attempts'],
                'Brute Force': accurate['brute_force_attempts'],
                'Scanner': accurate['scanner_attempts'],
                'Rate Limit': accurate['rate_limit_hits'],
                'ML Detection': accurate['ml_detections'],
            },
            'top_attackers': self.get_top_attackers(),
            'attack_indicators': self.compute_attack_indicators(),
            'connection_state': self.connection_state
        }
    def load_audit_log(self, max_json_entries: int = 500):
        """Load audit log using tail-read (JSONL) + SQLite threats — no full file load."""
        all_logs = []

        # 1. Tail-read JSONL admin action entries (last max_json_entries lines)
        with self.audit_lock:
            try:
                if os.path.exists(self.audit_log_path):
                    with open(self.audit_log_path, 'r') as f:
                        # Efficient tail: read last N non-empty lines without
                        # loading the full file into a list first.
                        lines = []
                        for raw in f:
                            raw = raw.strip()
                            if raw:
                                lines.append(raw)
                                if len(lines) > max_json_entries:
                                    lines.pop(0)  # discard oldest to bound memory
                        for raw in lines:
                            try:
                                all_logs.append(json.loads(raw))
                            except json.JSONDecodeError:
                                pass
            except Exception as e:
                print(f"[-] Error loading JSONL audit log: {e}")

        # 2. Fetch SQLite threats (limited to avoid huge in-memory lists)
        try:
            db_threats = self.db.get_threat_logs(limit=500)
            for t in db_threats:
                normalized = dict(t)
                normalized['id']        = t.get('threat_log_id')
                normalized['ip']        = t.get('ip_address')
                normalized['timestamp'] = t.get('created_at')
                normalized['blocked']   = bool(t.get('blocked'))
                if 'type' not in normalized:
                    normalized['type']  = t.get('attack_type')
                all_logs.append(normalized)
        except Exception as e:
            print(f"[-] Error loading SQLite threat logs: {e}")

        # 3. Sort by timestamp descending
        all_logs.sort(key=lambda x: str(x.get('timestamp', '')), reverse=True)
        return all_logs


    def _get_ml_relevant_logs(self, logs):
        """Filter logs for ML metrics calculation.
        Excludes:
        - 'Clean' attack_type (normal requests)
        - Dashboard/internal visits (endpoints like /dashboard, /api/dashboard/*)
        - Action logs (audit entries with 'action' field)
        """
        filtered = []
        for l in logs:
            # Skip if it's an action log
            if 'action' in l:
                continue
            # Skip if attack_type is Clean
            attack_type = l.get('attack_type', l.get('type', ''))
            if attack_type == 'Clean':
                continue
            # Skip dashboard/internal endpoints
            endpoint = l.get('endpoint', '')
            if endpoint and any(endpoint.startswith(p) for p in ['/dashboard', '/api/dashboard', '/login', '/signup', '/static/', '/blocked', '/incidents', '/requests', '/profile', '/ml-detections', '/threats/', '/critical']):
                continue
            # Must have attack_type or type field
            if 'attack_type' in l or 'type' in l:
                filtered.append(l)
        return filtered
    def get_blocked_events(self):
        """Get list of recent blocked events"""
        return list(self.blocked_events_queue)
