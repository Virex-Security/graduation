from flask import Flask, render_template, jsonify, request, redirect, url_for, make_response
import json
import time
from datetime import datetime, timedelta
import threading
import requests
import random
import os
from dotenv import load_dotenv
from collections import defaultdict, deque

load_dotenv()
import jwt
from functools import wraps
from roles import Role
from models import user_manager
from decorators import admin_required, token_required, require_role
from auth import login_user, logout_user

# Connection States
CONNECTED = "Connected"
WAITING = "Waiting for API"
DISCONNECTED = "Disconnected"


class SecurityDashboard:
    def __init__(self):
        self.threat_log = deque(maxlen=100)
        self.blocked_events_queue = deque(maxlen=100)  # For real-time blocked events
        self.stats = {
            'total_requests': 0,
            'blocked_requests': 0,
            'ml_detections': 0,
            'sql_injection_attempts': 0,
            'xss_attempts': 0,
            'brute_force_attempts': 0,
            'scanner_attempts': 0,
            'rate_limit_hits': 0
        }
        self.recent_threats = []
        self.timeline_data = deque(maxlen=50)
        self.ip_tracker = defaultdict(int)
        self.incidents = {}
        self.audit_log_path = "siem_audit.json"
        # lock to protect file operations on the audit log; the Flask
        # development server is multi-threaded by default and without a
        # lock two requests can read/write the json file at the same time,
        # causing parsing failures and an empty file. when the dashboard
        # later recalculates stats from the log (get_accurate_stats) an
        # empty audit file results in all counters dropping to zero – the
        # "mysterious reset" the user reported.
        self.audit_lock = threading.Lock()
        
        self.connection_state = WAITING
        self.had_connection = False
        self.api_url = "http://127.0.0.1:5000/api/health"

        if not os.path.exists(self.audit_log_path):
            with open(self.audit_log_path, "w") as f:
                json.dump([], f)
        
        self.secret_key = os.getenv("SECRET_KEY", "fallback-dev-key-change-in-production")

        # Restore stats from disk on startup
        self.load_stats_from_audit()

    
    def log_clean_request(self, ip, endpoint="", method="GET"):
        """Log a normal (non-attack) request."""
        entry = {
            'timestamp':      datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'type':           'Clean',
            'attack_type':    'Clean',
            'ip':             ip,
            'description':    'Normal request',
            'severity':       'Clean',
            'endpoint':       endpoint,
            'method':         method,
            'snippet':        '',
            'payload':        '',
            'detection_type': 'None',
            'blocked':        False,
            'ml_detected':    False,
            'confidence':     0.0,
        }
        # always keep a full audit history, but only surface non‑clean
        # events in the "recent threats" list shown on the dashboard.
        self.threat_log.append(entry)
        self.recent_threats = [t for t in self.threat_log if t.get('attack_type') != 'Clean'][-10:]
        # clean requests contribute to the total request count only; we do
        # *not* increment the attacker tracker so they won't pollute the
        # Top Threat Actors widget.
        self.stats['total_requests'] += 1
        # write new entry in a thread-safe fashion; we always grab the
        # audit_lock before touching the file to avoid races that would
        # otherwise leave a truncated/empty file and make the dashboard
        # appear to reset itself later when stats are rebuilt.
        with self.audit_lock:
            try:
                with open(self.audit_log_path, 'r') as f:
                    audit_logs = json.load(f)
            except Exception:
                audit_logs = []
            audit_logs.append(entry)
            try:
                with open(self.audit_log_path, 'w') as f:
                    json.dump(audit_logs, f, indent=2)
            except Exception:
                pass

    def load_stats_from_audit(self):
        """Called at startup to restore stats from siem_audit.json."""
        logs = self.load_audit_log()
        req_logs = [
            l for l in logs
            if ('attack_type' in l or 'type' in l) and 'action' not in l
        ]
        stat_map = {
            'SQL Injection': 'sql_injection_attempts',
            'XSS':           'xss_attempts',
            'Brute Force':   'brute_force_attempts',
            'Scanner':       'scanner_attempts',
            'Rate Limit':    'rate_limit_hits',
            'ML Detection':  'ml_detections',
        }
        counts = {v: 0 for v in stat_map.values()}
        for l in req_logs:
            t = l.get('attack_type') or l.get('type', '')
            if t in stat_map:
                counts[stat_map[t]] += 1

        self.stats['total_requests']         = len(req_logs)
        self.stats['blocked_requests']       = sum(1 for l in req_logs if l.get('blocked') is True)
        self.stats['ml_detections']          = counts['ml_detections']
        self.stats['sql_injection_attempts'] = counts['sql_injection_attempts']
        self.stats['xss_attempts']           = counts['xss_attempts']
        self.stats['brute_force_attempts']   = counts['brute_force_attempts']
        self.stats['scanner_attempts']       = counts['scanner_attempts']
        self.stats['rate_limit_hits']        = counts['rate_limit_hits']

        threat_entries = [l for l in req_logs if l.get('attack_type', 'Clean') != 'Clean']
        self.recent_threats = threat_entries[-10:]
        # build ip tracker only from non-clean events so Top Attackers
        # ignores benign traffic. total_requests already counts all logs.
        for l in req_logs:
            if l.get('attack_type') == 'Clean' or l.get('type') == 'Clean':
                continue
            ip = l.get('ip', '')
            if ip and ip not in ('Unknown', 'XXX.XXX.XXX.XXX'):
                self.ip_tracker[ip] += 1

    def get_accurate_stats(self):
        """Recalculate all stats from the persistent audit log."""
        logs = self.load_audit_log()
        req_logs = [
            l for l in logs
            if ('attack_type' in l or 'type' in l) and 'action' not in l
        ]
        # map non-ML attack types to their stat keys; ML is counted separately
        stat_map = {
            'SQL Injection': 'sql_injection_attempts',
            'XSS':           'xss_attempts',
            'Brute Force':   'brute_force_attempts',
            'Scanner':       'scanner_attempts',
            'Rate Limit':    'rate_limit_hits',
        }
        counts = {v: 0 for v in stat_map.values()}
        ml_count = 0
        for l in req_logs:
            t = l.get('attack_type') or l.get('type', '')
            if t in stat_map:
                counts[stat_map[t]] += 1
            det = l.get('detection_type', '')
            if isinstance(det, str) and det.lower().startswith('ml'):
                ml_count += 1
        counts['ml_detections'] = ml_count
        return {
            'total_requests':         len(req_logs),
            'blocked_requests':       sum(1 for l in req_logs if l.get('blocked') is True),
            'ml_detections':          counts['ml_detections'],
            'sql_injection_attempts': counts['sql_injection_attempts'],
            'xss_attempts':           counts['xss_attempts'],
            'brute_force_attempts':   counts['brute_force_attempts'],
            'scanner_attempts':       counts['scanner_attempts'],
            'rate_limit_hits':        counts['rate_limit_hits'],
        }

    def log_threat(self, threat_type, ip, description, severity="Medium", endpoint="", method="", snippet="", detection_type="Other", blocked=False):
        threat = {
            'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'type': threat_type,
            'ip': ip,
            'description': description,
            'severity': severity,
            'endpoint': endpoint,
            'method': method,
            'snippet': snippet,
            'detection_type': detection_type,
            'blocked': blocked,
            # mark ml_detected when detection_type indicates ML (prefix match)
            'ml_detected': isinstance(detection_type, str) and detection_type.lower().startswith("ml"),
            'attack_type': threat_type,
            'payload': snippet,
            'confidence': 0.95 if isinstance(detection_type, str) and detection_type.lower().startswith("ml") else 0.0
        }
        self.threat_log.append(threat)
        # refresh recent_threats but ignore any clean entries that may have
        # been logged previously
        self.recent_threats = [t for t in self.threat_log if t.get('attack_type') != 'Clean' and t.get('type') != 'Clean'][-10:]
        
        # only track IPs for non-clean threats
        if threat_type != 'Clean':
            self.ip_tracker[ip] += 1
        
        # Update stats
        self.stats['total_requests'] += 1
        if blocked:
            self.stats['blocked_requests'] += 1
            # Add to real-time blocked events queue
            self.blocked_events_queue.append(threat)
            
        stat_map = {
            'SQL Injection': 'sql_injection_attempts',
            'XSS': 'xss_attempts',
            'Brute Force': 'brute_force_attempts',
            'Scanner': 'scanner_attempts',
            'Rate Limit': 'rate_limit_hits',
            'ML Detection': 'ml_detections'
        }
        if threat_type in stat_map:
            self.stats[stat_map[threat_type]] += 1
        
        # Save to audit log
        # same locking logic for threats
        with self.audit_lock:
            try:
                with open(self.audit_log_path, 'r') as f:
                    audit_logs = json.load(f)
            except Exception:
                audit_logs = []
            
            audit_logs.append(threat)
            
            try:
                with open(self.audit_log_path, 'w') as f:
                    json.dump(audit_logs, f, indent=2)
            except Exception:
                pass

        # Group into Incidents
        incident_key = f"{ip}_{threat_type}"
        if incident_key not in self.incidents:
            new_incident = Incident(threat_type, ip, threat, detection_type)
            self.incidents[new_incident.id] = new_incident
            # Use a dummy mapping for quick lookup if needed, but for now ID is enough
        else:
            # Find existing incident for this IP and Type that is not Closed
            found = False
            for inc in self.incidents.values():
                if inc.source_ip == ip and inc.category == threat_type and inc.status != "Closed":
                    inc.events.append(threat)
                    inc.last_seen = threat['timestamp']
                    inc.severity = severity # Update to latest severity
                    found = True
                    break
            
            if not found:
                new_incident = Incident(threat_type, ip, threat, detection_type)
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

    def write_audit_log(self, log_entry):
        # central helper used by role actions etc. ensure thread safety
        with self.audit_lock:
            try:
                # use r+ to preserve existing content; if the file is
                # malformed we fall back to recreating it with only the new
                # entry rather than blowing it away entirely.
                with open(self.audit_log_path, 'r+') as f:
                    try:
                        logs = json.load(f)
                    except Exception:
                        logs = []
                    logs.append(log_entry)
                    f.seek(0)
                    json.dump(logs, f, indent=4)
                    f.truncate()
            except Exception as e:
                print(f"Error writing audit log: {e}")
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

    def check_api_connection(self):
        try:
            resp = requests.get(self.api_url, timeout=2)
            if resp.status_code == 200:
                self.connection_state = CONNECTED
                self.had_connection = True
            else:
                self.update_failed_connection()
        except:
            self.update_failed_connection()

    def update_failed_connection(self):
        if self.had_connection:
            self.connection_state = DISCONNECTED
        else:
            self.connection_state = WAITING
    
    def get_top_attackers(self, limit=5):
        sorted_ips = sorted(self.ip_tracker.items(), key=lambda x: x[1], reverse=True)
        return sorted_ips[:limit]

    def compute_attack_indicators(self):
        """Return normalized scores for each predefined indicator based on the
        audit log.  Values are 0–1 and represent the fraction of logged events
        that exhibit the given pattern.  The list of indicators is fixed by the
        spec so downstream code can rely on the names staying the same.
        """
        indicators = {
            'sql_injection_pattern':     0,
            'xss_payload_detected':      0,
            'unusual_request_size':      0,
            'brute_force_signature':     0,
            'port_scan_behavior':        0,
            'malformed_headers':         0,
        }

        logs = self.load_audit_log()
        total = len(logs) or 1

        for entry in logs:
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
        return {k: round(v / total, 3) for k, v in indicators.items()}


    def compute_ml_metrics(self):
        """Helper that returns the dictionary of ML performance metrics.

        This mirrors the logic inside the ``ml_stats`` route but without
        Flask decorators or JSONification. The dashboard uses it so that
        the small accuracy KPI remains in sync with the full ML report.
        """
        import joblib
        import numpy as np

        from sklearn.metrics import (
            accuracy_score, precision_score, recall_score,
            f1_score, roc_auc_score, confusion_matrix
        )
        import pandas as pd
        from sklearn.model_selection import train_test_split

        # load model and data (exceptions propagate outwards)
        model_obj = joblib.load("model.pkl")
        vectorizer_obj = joblib.load("vectorizer.pkl")
        data = pd.read_csv("ml_training_data.csv")

        # baseline test split from training set
        _, X_test_raw, _, y_test = train_test_split(
            data['text'], data['label'],
            test_size=0.2, random_state=42, stratify=data['label']
        )
        X_test_vec = vectorizer_obj.transform(X_test_raw)
        y_pred_base = model_obj.predict(X_test_vec)
        y_prob_base = model_obj.predict_proba(X_test_vec)[:, 1]

        base_auc = round(roc_auc_score(y_test, y_prob_base), 4)
        cm_b = confusion_matrix(y_test, y_pred_base)
        tn_b, fp_b, fn_b, tp_b = cm_b.ravel()

        # derive live statistics from audit log
        logs = self.load_audit_log()
        real_logs = [
            l for l in logs
            if ('attack_type' in l or 'type' in l) and 'action' not in l
        ]

        tp_live = fp_live = tn_live = fn_live = 0
        for l in real_logs:
            is_attack   = l.get('attack_type', 'Clean') not in ('Clean', '', None)
            ml_flagged  = (l.get('ml_detected') is True or l.get('detection_type') == 'ML')

            if ml_flagged and is_attack:
                tp_live += 1
            elif ml_flagged and not is_attack:
                fp_live += 1
            elif not ml_flagged and not is_attack:
                tn_live += 1
            elif not ml_flagged and is_attack:
                fn_live += 1

        total_live = len(real_logs)
        ml_events = tp_live + fp_live

        if ml_events >= 10:
            live_precision = round((tp_live / max(tp_live + fp_live, 1)) * 100, 2)
            live_recall    = round((tp_live / max(tp_live + fn_live, 1)) * 100, 2)
            denom          = live_precision + live_recall
            live_f1        = round(2 * live_precision * live_recall / denom, 2) if denom > 0 else 0
            live_accuracy  = round((tp_live + tn_live) / max(total_live, 1) * 100, 2)
            live_auc       = min(round(base_auc + (live_precision - base_auc * 100) * 0.001, 4), 1.0)

            accuracy  = live_accuracy
            precision = live_precision
            recall    = live_recall
            f1        = live_f1
            roc_auc   = live_auc
            tn, fp, fn, tp = tn_live, fp_live, fn_live, tp_live
            test_size = total_live
        else:
            # fallback to baseline
            accuracy  = round(accuracy_score(y_test, y_pred_base) * 100, 2)
            precision = round(precision_score(y_test, y_pred_base) * 100, 2)
            recall    = round(recall_score(y_test, y_pred_base) * 100, 2)
            f1        = round(f1_score(y_test, y_pred_base) * 100, 2)
            roc_auc   = base_auc
            tn, fp, fn, tp = int(tn_b), int(fp_b), int(fn_b), int(tp_b)
            test_size = len(y_test)

        # feature importances (only needed by the full ml_stats route)
        feature_names = vectorizer_obj.get_feature_names_out()
        importances   = model_obj.feature_importances_
        top_idx       = np.argsort(importances)[::-1][:10]
        ml_top_features  = [
            {"feature": str(feature_names[i]), "importance": round(float(importances[i]), 4)}
            for i in top_idx
        ]

        # compute attack indicators and turn into same structure so the
        # frontend can display them as a feature list.  we also return the raw
        # mapping separately for dashboard endpoints.
        attack_scores = self.compute_attack_indicators()
        attack_features = [
            {"feature": k, "importance": attack_scores[k]}
            for k in attack_scores
        ]
        # sort descending so strongest indicators appear first
        attack_features.sort(key=lambda x: x['importance'], reverse=True)

        return {
            "status":          "ok",
            "model_type":      "Random Forest (100 trees, max_depth=20)",
            "vectorizer_type": "TF-IDF (ngrams 1-2, 5000 features)",
            "dataset_size":    len(data),
            "test_size":       test_size,
            "accuracy":        accuracy,
            "precision":       precision,
            "recall":          recall,
            "f1_score":        f1,
            "roc_auc":         roc_auc,
            "confusion_matrix": {"tn": tn, "fp": fp, "fn": fn, "tp": tp},
            # use attack-based indicators for the UI list instead of raw model
            # importances (the user requested real-world probabilities)
            "top_features":    attack_features,
            # still include ml feature list in case someone needs it
            "ml_feature_importances": ml_top_features,
            "attack_indicators": attack_scores,
            "live_total_requests": total_live,
            "live_ml_detections":  ml_events,
            "live_data_active":    ml_events >= 10,
        }
    
    def calculate_security_score(self, total_requests, blocked_requests, detected_incidents, missed_incidents, ml_metrics):
        """Score using detection/block/ML weights supplied by user.

        Formula:
            score = 100 * (
                detect_rate * 0.5 +
                block_rate  * 0.3 +
                ml_score    * 0.2
            )
        where
            detect_rate = detected_incidents / (total_requests + 1)
            block_rate  = blocked_requests  / (total_requests + 1)
            ml_score    = (precision + recall) / 2

        ``missed_incidents`` is accepted for API compatibility but currently
        unused in the calculation.
        """
        DETECT_WEIGHT = 0.5
        BLOCK_WEIGHT = 0.3
        ML_WEIGHT = 0.2

        detect_rate = detected_incidents / (total_requests + 1)
        block_rate = blocked_requests / (total_requests + 1)
        ml_score = (ml_metrics.get('precision', 0) + ml_metrics.get('recall', 0)) / 2

        score = 100 * (
            detect_rate * DETECT_WEIGHT +
            block_rate  * BLOCK_WEIGHT +
            ml_score    * ML_WEIGHT
        )

        return round(score, 2)

    def get_dashboard_data(self):
        accurate = self.get_accurate_stats()
        self.stats.update(accurate)
        # Obtain the most up‑to‑date ML metrics (accuracy, precision, recall).
        ml_perf = None
        ml_stats = {}
        try:
            ml_stats = self.compute_ml_metrics()
            ml_perf = ml_stats.get('accuracy')
        except Exception:
            ml_perf = None

        # filter out any lingering 'Clean' records before sending to UI
        recent = [t for t in self.recent_threats if t.get('attack_type') != 'Clean' and t.get('type') != 'Clean']

        # calculate security score using updated detection-based formula
        detected = len(self.incidents)
        # "missed" value is not tracked separately, pass zero
        missed = 0
        # convert precision/recall from percent to 0-1
        ml_metrics = {
            'precision': (ml_stats.get('precision', 0) or 0) / 100,
            'recall':    (ml_stats.get('recall', 0) or 0) / 100,
        }
        sec_score = self.calculate_security_score(
            accurate.get('total_requests', 0),
            accurate.get('blocked_requests', 0),
            detected,
            missed,
            ml_metrics,
        )

        return {
            'stats': {**accurate, 'ml_model_performance': ml_perf, 'security_score': sec_score},
            'recent_threats': recent,
            'timeline': list(self.timeline_data),
            'threat_distribution': {
                'SQL Injection': accurate['sql_injection_attempts'],
                'XSS':           accurate['xss_attempts'],
                'Brute Force':   accurate['brute_force_attempts'],
                'Scanner':       accurate['scanner_attempts'],
                'Rate Limit':    accurate['rate_limit_hits'],
                'ML Detection':  accurate['ml_detections'],
            },
            'top_attackers': self.get_top_attackers(),
            'attack_indicators': self.compute_attack_indicators()
        }
    
    def load_audit_log(self):
        # reading the audit log should also be serialized to avoid
        # grabbing a partially-written file.
        with self.audit_lock:
            try:
                if os.path.exists(self.audit_log_path):
                    with open(self.audit_log_path, 'r') as f:
                        return json.load(f)
            except Exception:
                pass
        return []
    
    def get_blocked_events(self):
        """Get list of recent blocked events"""
        return list(self.blocked_events_queue)

class Incident:
    def __init__(self, category, source_ip, initial_event, detection_type="Other"):
        self.id = f"INC-{int(time.time())}-{random.randint(100, 999)}"
        self.category = category
        self.source_ip = source_ip
        self.detection_type = detection_type
        self.status = "Detected"
        self.severity = initial_event.get('severity', 'Medium')
        self.first_seen = initial_event['timestamp']
        self.last_seen = initial_event['timestamp']
        self.events = [initial_event]
        self.actions = []

dashboard = SecurityDashboard()


from dobby_chat import SecurityChatbot

# Initialize Dobby — Rule-based NLP Security Assistant
# NOTE: Dobby uses keyword detection & pattern matching (NOT a generative AI / LLM)
security_bot = SecurityChatbot(dashboard)

def create_dashboard_app():
    app = Flask(__name__)
    app.config['SECRET_KEY'] = dashboard.secret_key

    def log_action(current_user, action, details=""):
        """Centralized logging for role-based actions"""
        log_entry = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "user_id": current_user.get('id'),
            "username": current_user.get('username'),
            "role": current_user.get('role'),
            "action": action,
            "details": details
        }
        print(f"[AUDIT] {log_entry}")
        dashboard.write_audit_log(log_entry)

    # ----------------------------------------------------------
    # TRAFFIC LOGGER â€” intercepts every request automatically
    # ----------------------------------------------------------
    SKIP_PREFIXES = ('/static/', '/api/dashboard/', '/favicon', '/api/auth/', '/api/critical-threats', '/api/chat', '/api/ml/', '/api/user', '/api/incidents', '/api/critical')

    # Dashboard internal pages - should not be counted as traffic
    SKIP_EXACT = {
        '/dashboard', '/critical', '/blocked', '/incidents',
        '/requests', '/profile', '/ml-detections',
        '/threats/sql-injection', '/threats/xss',
        '/threats/ml-detection', '/threats/brute-force',
        '/threats/scanner', '/threats/rate-limit',
        '/login', '/signup', '/',
    }

    @app.before_request
    def track_request():
        path = request.path
        if any(path.startswith(p) for p in SKIP_PREFIXES):
            return
        if path in SKIP_EXACT:
            return
        ip = request.headers.get('X-Forwarded-For', request.remote_addr) or 'Unknown'
        ip = ip.split(',')[0].strip()
        dashboard.log_clean_request(ip=ip, endpoint=path, method=request.method)

    @app.route('/api/auth/login', methods=['POST'])
    def login():
        auth = request.get_json()
        if not auth or not auth.get('username') or not auth.get('password'):
            return jsonify({'message': 'Missing credentials'}), 401
        
        resp, status = login_user(auth.get('username'), auth.get('password'))
        if status == 200:
            user = user_manager.get_user(auth.get('username'))
            log_action(user, "Login")
        return resp, status

    @app.route('/api/auth/signup', methods=['POST'])
    def signup():
        auth = request.get_json()
        if not auth or not auth.get('username') or not auth.get('password'):
            return jsonify({'message': 'Missing username or password'}), 400
        
        username = auth.get('username').strip()
        password = auth.get('password')

        # Validation
        if len(username) < 3:
            return jsonify({'message': 'Username must be at least 3 characters'}), 400
        
        if len(password) < 8:
            return jsonify({'message': 'Password must be at least 8 characters'}), 400

        # Check if user already exists
        if user_manager.get_user(username):
            return jsonify({'message': 'Username already exists'}), 409

        # Add new user with USER role
        success, message = user_manager.add_user(username, password, Role.USER)
        
        if success:
            # Log the new user creation
            new_user = user_manager.get_user(username)
            log_action(new_user, "Account Created")
            return jsonify({'message': 'Account created successfully'}), 201
        else:
            return jsonify({'message': message}), 400

    @app.route('/api/auth/logout')
    def logout():
        token = request.cookies.get('auth_token')
        if token:
            try:
                data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
                user = user_manager.get_user(data['user'])
                if user:
                    log_action(user, "Logout")
            except:
                pass
        return logout_user()

    @app.route('/')
    def index_page():
        token = request.cookies.get('auth_token')
        if token:
            try:
                jwt.decode(token, app.config.get('SECRET_KEY'), algorithms=['HS256'])
                return redirect(url_for('dashboard_page'))
            except Exception:
                return render_template('landing.html')
        return render_template('landing.html')
    
    @app.route('/dashboard')
    @token_required
    def dashboard_page(current_user):
        return render_template('dashboard.html', user=current_user)
    
    @app.route('/login')
    def login_page():
        token = request.cookies.get('auth_token')
        if token:
            try:
                jwt.decode(token, app.config.get('SECRET_KEY'), algorithms=['HS256'])
                return redirect(url_for('dashboard_page'))
            except Exception:
                pass
        return render_template('login.html')
    
    @app.route('/signup')
    def signup_page():
        token = request.cookies.get('auth_token')
        if token:
            try:
                jwt.decode(token, app.config.get('SECRET_KEY'), algorithms=['HS256'])
                return redirect(url_for('dashboard_page'))
            except Exception:
                pass
        return render_template('signup.html')
    
    @app.route('/api/dashboard/data')
    @token_required
    def dashboard_data(current_user):
        global dashboard
        data = dashboard.get_dashboard_data()
        data['connection_state'] = dashboard.connection_state
        
        # previously we masked IP addresses for non-admin users; the requirement
        # now is to display the source IP in full, so we simply return the data
        # as-is.  snippet/payload may still be hidden by the frontend if desired.
        return jsonify(data)
    
    @app.route('/api/dashboard/threat', methods=['POST'])
    def log_threat_api():
        global dashboard
        data = request.get_json()
        dashboard.log_threat(
            data.get('type', 'Unknown'),
            data.get('ip', 'Unknown'),
            data.get('description', 'No description'),
            data.get('severity', 'Medium'),
            data.get('endpoint', ''),
            data.get('method', ''),
            data.get('snippet', ''),
            data.get('detection_type', 'Other'),
            data.get('blocked', False)
        )
        return jsonify({'status': 'logged'})
    
    @app.route('/api/dashboard/stats', methods=['POST'])
    def update_stats():
        global dashboard
        data = request.get_json()
        if 'total_requests' in data:
            dashboard.stats['total_requests'] = data['total_requests']
        if 'blocked_requests' in data:
            dashboard.stats['blocked_requests'] = data['blocked_requests']
        if 'rate_limit_hits' in data:
            dashboard.stats['rate_limit_hits'] = data['rate_limit_hits']
        return jsonify({'status': 'updated'})

    @app.route('/api/dashboard/reset', methods=['POST'])
    @admin_required
    def reset_stats(current_user):
        global dashboard
        log_action(current_user, "Reset Stats", "Cleared all memory stats and audit logs")
        
        for key in dashboard.stats:
            dashboard.stats[key] = 0
        dashboard.ip_tracker.clear()
        dashboard.threat_log.clear()
        dashboard.blocked_events_queue.clear()
        dashboard.recent_threats = []
        dashboard.timeline_data.clear()
        dashboard.incidents.clear()
        
        try:
            with open(dashboard.audit_log_path, 'w') as f:
                json.dump([], f)
        except Exception as e:
            print(f"[-] Error clearing audit log: {e}")
        
        return jsonify({'status': 'stats_reset', 'message': 'All stats and logs cleared'})

    @app.route('/api/user')
    @token_required
    def get_current_user(current_user):
        """Return current user information for permission checks"""
        return jsonify({
            'username': current_user.get('username'),
            'role': current_user.get('role'),
            'email': current_user.get('email', '')
        })

    @app.route('/api/ml/stats')
    @token_required
    def ml_stats(current_user):
        """
        ML performance metrics built DIRECTLY from siem_audit.json (live traffic).

        How the confusion matrix is derived from the audit log:
          TP  = ML flagged (detection_type==ML) AND it was a real attack (attack_type != Clean)
          FP  = ML flagged AND the request was actually Clean (false alarm)
          TN  = Not ML flagged AND request was Clean (correct pass)
          FN  = Not ML flagged AND request was a real attack (missed attack)

        If not enough live data yet (<10 ML events), falls back to training baseline.
        """
        try:
            stats = dashboard.compute_ml_metrics()
            return jsonify(stats)
        except FileNotFoundError as e:
            # can't load model/vectorizer but we still want indicator values returned
            indicators = dashboard.compute_attack_indicators()
            return jsonify({
                "status": "error",
                "message": f"Model file not found: {e}",
                "attack_indicators": indicators
            }), 200
        except Exception as e:
            # on any other failure, return error flag but still include indicators
            indicators = dashboard.compute_attack_indicators()
            return jsonify({
                "status": "error",
                "message": str(e),
                "attack_indicators": indicators
            }), 200

    @app.route('/incidents')
    @token_required
    def incidents_page(current_user):
        global dashboard
        incidents_list = []
        for inc in dashboard.incidents.values():
            incident_dict = {
                'id': inc.id,
                'category': inc.category,
                'source_ip': inc.source_ip,
                'detection_type': inc.detection_type,
                'status': inc.status,
                'severity': inc.severity,
                'first_seen': inc.first_seen,
                'last_seen': inc.last_seen,
                'events': inc.events,
                'actions': inc.actions
            }
            incidents_list.append(incident_dict)
        
        distribution = defaultdict(int)
        for inc in incidents_list:
            distribution[inc['detection_type']] += 1
        
        return render_template('incident_list.html', 
                             incidents=incidents_list,
                             distribution=dict(distribution),
                             total_incidents=len(incidents_list),
                             user=current_user)

    @app.route('/incident/<id>')
    @token_required
    def incident_details_page(current_user, id):
        global dashboard
        if id not in dashboard.incidents:
            return redirect('/incidents')
        
        inc = dashboard.incidents[id]
        incident_data = {
            'id': inc.id,
            'category': inc.category,
            'source_ip': inc.source_ip,
            'detection_type': inc.detection_type,
            'status': inc.status,
            'severity': inc.severity,
            'first_seen': inc.first_seen,
            'last_seen': inc.last_seen,
            'events': inc.events,
            'actions': inc.actions
        }
        return render_template('incident_details.html', incident=incident_data, user=current_user)

    @app.route('/api/incidents')
    @admin_required
    def get_incidents(current_user):
        global dashboard
        incidents_data = []
        for inc in dashboard.incidents.values():
            incidents_data.append(inc.__dict__)
        return jsonify(incidents_data)

    @app.route('/api/incident/<id>')
    @admin_required
    def get_incident_details(current_user, id):
        global dashboard
        if id not in dashboard.incidents:
            return jsonify({'error': 'Not found'}), 404
        return jsonify(dashboard.incidents[id].__dict__)

    @app.route('/api/incident/<id>/action', methods=['POST'])
    @admin_required
    def incident_action(current_user, id):
        global dashboard
        data = request.get_json()
        action = data.get('action')
        comment = data.get('comment', '')
        actor = current_user['username']
        
        log_action(current_user, f"Incident Action: {action}", f"Incident ID: {id}, Comment: {comment}")
        success, message = dashboard.perform_action(id, action, actor, comment)
        return jsonify({'status': 'success' if success else 'error', 'message': message})

    @app.route('/api/incident/<id>/export')
    @admin_required
    def export_incident(current_user, id):
        global dashboard
        if id not in dashboard.incidents:
            return jsonify({'error': 'Not found'}), 404
        return jsonify(dashboard.incidents[id].__dict__)

    @app.route('/api/reports/distribution')
    @token_required
    def report_distribution(current_user):
        global dashboard
        start_date = request.args.get('start_date')
        end_date = request.args.get('end_date')
        
        dist = defaultdict(int)
        for inc in dashboard.incidents.values():
            if start_date and inc.first_seen < start_date:
                continue
            if end_date and inc.first_seen > end_date:
                continue
                
            dist[inc.detection_type] += 1
        return jsonify(dist)

    @app.route('/requests')
    @token_required
    def requests_page(current_user):
        logs = dashboard.load_audit_log()
        logs.sort(key=lambda x: x.get('timestamp', ''), reverse=True)
        return render_template('requests.html', logs=logs, title="Total Requests", user=current_user)

    @app.route('/api/blocked-events')
    @admin_required
    def blocked_events_stream(current_user):
        def generate():
            last_count = 0
            while True:
                blocked_events = dashboard.get_blocked_events()
                if len(blocked_events) > last_count:
                    for event in blocked_events[last_count:]:
                        yield f"data: {json.dumps(event)}\n\n"
                    last_count = len(blocked_events)
                time.sleep(0.5)
        
        return app.response_class(
            generate(),
            mimetype='text/event-stream',
            headers={
                'Cache-Control': 'no-cache',
                'X-Accel-Buffering': 'no',
                'Connection': 'keep-alive'
            }
        )

    @app.route('/threats/<category>')
    @token_required
    def threats_page(current_user, category):
        logs = dashboard.load_audit_log()
        category_map = {
            'sql-injection': 'SQL Injection',
            'xss': 'XSS',
            'brute-force': 'Brute Force',
            'scanner': 'Scanner',
            'rate-limit': 'Rate Limit',
            'ml-detection': 'ML Detection'
        }
        filter_value = category_map.get(category, category)
        filtered_logs = [l for l in logs if l.get('attack_type') == filter_value or l.get('type') == filter_value]
        
        # Filter by IP if provided in URL parameters
        filter_ip = request.args.get('ip')
        if filter_ip:
            filtered_logs = [l for l in filtered_logs if l.get('ip') == filter_ip or l.get('source_ip') == filter_ip]
        
        filtered_logs.sort(key=lambda x: x.get('timestamp', ''), reverse=True)
        
        # Data Masking for Users
        if current_user['role'] != Role.ADMIN:
            masked_logs = []
            for log in filtered_logs:
                masked_log = log.copy()
                masked_log['ip'] = "XXX.XXX.XXX.XXX"
                masked_log['payload'] = "[HIDDEN]"
                masked_log['snippet'] = "[HIDDEN]"
                masked_log['endpoint'] = "[HIDDEN]"
                masked_logs.append(masked_log)
            filtered_logs = masked_logs

        total_count = len(filtered_logs)
        blocked_count = len([l for l in filtered_logs if l.get('blocked') is True])
        critical_count = len([l for l in filtered_logs if l.get('severity') == 'High'])
        unique_ips = len(set(l.get('ip', '') for l in filtered_logs if l.get('ip')))
        
        descriptions = {
            'SQL Injection': 'SQL Injection attempts detected and analyzed',
            'XSS': 'Cross-Site Scripting (XSS) attacks detected',
            'Brute Force': 'Brute force authentication attempts',
            'Scanner': 'Security scanner and reconnaissance activities',
            'Rate Limit': 'Rate limit violations and abuse attempts',
            'ML Detection': 'Anomalies detected by machine learning model'
        }
        
        return render_template('threat_details.html', 
            logs=filtered_logs, 
            title=filter_value,
            description=descriptions.get(filter_value, f'{filter_value} detections'),
            total_count=total_count,
            blocked_count=blocked_count,
            critical_count=critical_count,
            unique_ips=unique_ips,
            user=current_user
        )

    @app.route('/blocked')
    @token_required
    def blocked_page(current_user):
        logs = dashboard.load_audit_log()
        blocked_logs = [l for l in logs if l.get('blocked') is True]
        blocked_logs.sort(key=lambda x: x.get('timestamp', ''), reverse=True)
        
        total_count = len(blocked_logs)
        critical_count = len([l for l in blocked_logs if l.get('severity') == 'High'])
        unique_ips = len(set(l.get('ip', '') for l in blocked_logs if l.get('ip')))
        
        return render_template('blocked.html', 
            logs=blocked_logs, 
            title="Blocked Requests",
            total_count=total_count,
            critical_count=critical_count,
            unique_ips=unique_ips,
            user=current_user
        )

    @app.route('/ml-detections')
    @token_required
    def ml_detections_page(current_user):
        logs = dashboard.load_audit_log()
        # select entries that were flagged by ML (explicit flag) or whose
        # detection method indicates ML. attack_type no longer used for
        # filtering since it now contains the actual attack classification.
        ml_logs = [l for l in logs if l.get('ml_detected') is True or
                   (l.get('detection_type', '').lower().startswith('ml'))]
        ml_logs.sort(key=lambda x: x.get('timestamp', ''), reverse=True)
        
        # Data Masking for Users
        if current_user['role'] != Role.ADMIN:
            masked_logs = []
            for log in ml_logs:
                masked_log = log.copy()
                masked_log['ip'] = "XXX.XXX.XXX.XXX"
                masked_log['payload'] = "[HIDDEN]"
                masked_log['snippet'] = "[HIDDEN]"
                masked_log['endpoint'] = "[HIDDEN]"
                masked_logs.append(masked_log)
            ml_logs = masked_logs
            
        return render_template('ml_detections.html', logs=ml_logs, title="ML Detections", user=current_user)

    @app.route('/ml-performance')
    @token_required
    def ml_performance_page(current_user):
        """Dedicated ML Model Performance Dashboard"""
        return render_template('ml_performance.html', user=current_user)

    @app.route('/profile')
    @token_required
    def profile_page(current_user):
        # Render dedicated profile page
        return render_template('profile.html', user=current_user)

    @app.route('/api/profile')
    @token_required
    def get_profile_data(current_user):
        """Return user profile data for profile page"""
        return jsonify({
            'status': 'success',
            'user': {
                'username': current_user.get('username'),
                'email': current_user.get('email', ''),
                'role': current_user.get('role'),
                'id': current_user.get('id', ''),
                'full_name': current_user.get('full_name', current_user.get('username')),
                'department': current_user.get('department', 'Security Operations'),
                'created_at': current_user.get('created_at', ''),
                'last_login': current_user.get('last_login', ''),
                'active_sessions': current_user.get('active_sessions', 1),
                'security_score': current_user.get('security_score', 85)
            }
        })

    @app.route('/api/profile/activity')
    @token_required
    def get_profile_activity(current_user):
        """Return user activity data"""
        # Mock activity data - replace with real data from your logs
        return jsonify({
            'status': 'success',
            'activity': [
                {'action': 'Login', 'timestamp': '2025-01-15 09:30:00', 'ip': '192.168.1.100'},
                {'action': 'View Dashboard', 'timestamp': '2025-01-15 10:15:00', 'ip': '192.168.1.100'},
                {'action': 'Security Check', 'timestamp': '2025-01-15 11:45:00', 'ip': '192.168.1.100'}
            ]
        })

    @app.route('/api/profile/sessions')
    @token_required
    def get_profile_sessions(current_user):
        """Return user active sessions"""
        # Mock session data - replace with real session data
        return jsonify({
            'status': 'success',
            'sessions': [
                {
                    'id': 'session_001',
                    'device': 'Chrome on Windows',
                    'ip': '192.168.1.100',
                    'location': 'Cairo, Egypt',
                    'login_time': '2025-01-15 09:30:00',
                    'status': 'active',
                    'current': True
                }
            ]
        })

    @app.route('/api/profile/update', methods=['POST'])
    @token_required
    def update_profile(current_user):
        """Update user profile"""
        data = request.get_json()
        # Here you would update the user in your database
        log_action(current_user, "Profile Updated", f"Updated profile information")
        return jsonify({'status': 'success', 'message': 'Profile updated successfully'})

    @app.route('/api/profile/change-password', methods=['POST'])
    @token_required
    def change_password_profile(current_user):
        """Change user password"""
        data = request.get_json()
        current_password = data.get('current_password')
        new_password = data.get('new_password')
        
        # Here you would validate and update the password
        if current_password and new_password:
            log_action(current_user, "Password Changed", "User changed their password")
            return jsonify({'status': 'success', 'message': 'Password changed successfully'})
        
        return jsonify({'status': 'error', 'message': 'Invalid request'})

    @app.route('/api/profile/logout-session', methods=['POST'])
    @token_required
    def logout_session(current_user):
        """Logout a specific session"""
        session_id = request.get_json().get('session_id')
        log_action(current_user, "Session Revoked", f"Revoked session: {session_id}")
        return jsonify({'status': 'success', 'message': 'Session revoked successfully'})

    @app.route('/critical')
    @token_required
    def critical_page(current_user):
        return render_template('critical.html', user=current_user)

    @app.route('/api/critical-threats')
    @token_required
    def get_critical_threats(current_user):
        """Get critical level threats with dynamic scoring"""
        critical_threats = []
        logs = dashboard.load_audit_log()
        
        for threat in logs:
            if threat.get('type', 'Clean') == 'Clean' and threat.get('attack_type', 'Clean') == 'Clean':
                continue
                
            threat_score = calculate_threat_score(threat)
            
            # Include if Critical severity or high score or escalated
            if threat.get('severity') == 'Critical' or threat_score >= 80:
                threat_with_score = threat.copy()
                threat_with_score['threat_score'] = threat_score
                threat_with_score['threat_id'] = f"THR-{len(critical_threats) + 1:03d}"
                threat_with_score['ml_confidence'] = int(threat.get('confidence', 0) * 100)
                threat_with_score['frequency'] = dashboard.ip_tracker.get(threat.get('ip', ''), 1)
                threat_with_score['status'] = determine_threat_status(threat)
                critical_threats.append(threat_with_score)
        
        # Sort by threat score descending
        critical_threats.sort(key=lambda x: x.get('threat_score', 0), reverse=True)
        
        # Data masking for non-admin users
        if current_user['role'] != Role.ADMIN:
            for threat in critical_threats:
                threat['ip'] = "XXX.XXX.XXX.XXX"
                threat['snippet'] = "[HIDDEN]"
                threat['payload'] = "[HIDDEN]"
        
        return jsonify({
            'total': len(critical_threats),
            'new_24h': len([t for t in critical_threats if is_recent(t.get('timestamp', ''))]),
            'affected_assets': len(set(t.get('endpoint', '') for t in critical_threats if t.get('endpoint'))),
            'threats': critical_threats
        })

    @app.route('/api/chat', methods=['POST'])
    @token_required
    def chat(current_user):
        data = request.get_json()
        message = data.get('message', '')
        incident_id = data.get('incident_id')
        page_context = data.get('page_context')
        history = data.get('history', [])
        
        if not message:
            return jsonify({'error': 'Message required'}), 400
            
        print(f"[NLP] Chat request from {current_user['username']} ({current_user['role']}): {message}")
        response_text = security_bot.generate_response(message, incident_id, page_context, history, role=current_user['role'])
        
        return jsonify({
            'response': response_text,
            'timestamp': datetime.now().strftime("%H:%M")
        })

    return app

def calculate_threat_score(threat):
    """Calculate threat score based on multiple factors (0-100)"""
    score = 50  # Base score
    
    # Severity multiplier
    severity_map = {'Low': 0.5, 'Medium': 0.7, 'High': 0.85, 'Critical': 1.0}
    severity = threat.get('severity', 'Medium')
    score *= severity_map.get(severity, 0.7)
    
    # ML detection boost
    if threat.get('ml_detected'):
        score += 20
    
    # Confidence boost
    confidence = threat.get('confidence', 0)
    score += confidence * 10
    
    # Blocked incident boost
    if threat.get('blocked'):
        score += 15
    
    return min(int(score), 100)  # Cap at 100

def is_recent(timestamp_str):
    """Check if timestamp is within last 24 hours"""
    try:
        threat_time = datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S")
        now = datetime.now()
        return (now - threat_time).total_seconds() < 86400  # 24 hours
    except:
        return False

def determine_threat_status(threat):
    """Determine threat status based on properties"""
    if threat.get('blocked'):
        return 'Blocked'
    
    # Check if threat is recent (within 5 minutes = ongoing)
    try:
        threat_time = datetime.strptime(threat.get('timestamp', ''), "%Y-%m-%d %H:%M:%S")
        now = datetime.now()
        if (now - threat_time).total_seconds() < 300:
            return 'Ongoing'
    except:
        pass
    
    return 'Dormant'

def run_timeline_updates():
    while True:
        dashboard.update_timeline()
        time.sleep(5)

if __name__ == '__main__':
    print("Security Dashboard Started")
    print("Dashboard: http://localhost:8070")
    
    # Start timeline update thread
    threading.Thread(target=run_timeline_updates, daemon=True).start()
    
    app = create_dashboard_app()
    app.run(host='0.0.0.0', port=8070, debug=True, use_reloader=False)