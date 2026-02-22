from flask import Flask, render_template, jsonify, request, redirect, url_for, make_response
import json
import time
from datetime import datetime, timedelta
import threading
import requests
import random
import os
from collections import defaultdict, deque
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
        
        self.connection_state = WAITING
        self.had_connection = False
        self.api_url = "http://127.0.0.1:5000/api/health"

        if not os.path.exists(self.audit_log_path):
            with open(self.audit_log_path, "w") as f:
                json.dump([], f)
        
        self.secret_key = "super-secret-key-for-jwt" # In production, use env var

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
        self.threat_log.append(entry)
        self.recent_threats = list(self.threat_log)[-10:]
        self.ip_tracker[ip] += 1
        self.stats['total_requests'] += 1
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
        for l in req_logs:
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
            'ml_detected': detection_type == "ML",
            'attack_type': threat_type,
            'payload': snippet,
            'confidence': 0.95 if detection_type == "ML" else 0.0
        }
        self.threat_log.append(threat)
        self.recent_threats = list(self.threat_log)[-10:]
        
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
        try:
            with open(self.audit_log_path, 'r') as f:
                audit_logs = json.load(f)
        except:
            audit_logs = []
        
        audit_logs.append(threat)
        
        try:
            with open(self.audit_log_path, 'w') as f:
                json.dump(audit_logs, f, indent=2)
        except:
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
        try:
            with open(self.audit_log_path, 'r+') as f:
                logs = json.load(f)
                logs.append(log_entry)
                f.seek(0)
                json.dump(logs, f, indent=4)
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
    
    def get_dashboard_data(self):
        accurate = self.get_accurate_stats()
        self.stats.update(accurate)
        return {
            'stats': accurate,
            'recent_threats': self.recent_threats,
            'timeline': list(self.timeline_data),
            'threat_distribution': {
                'SQL Injection': accurate['sql_injection_attempts'],
                'XSS':           accurate['xss_attempts'],
                'Brute Force':   accurate['brute_force_attempts'],
                'Scanner':       accurate['scanner_attempts'],
                'Rate Limit':    accurate['rate_limit_hits'],
                'ML Detection':  accurate['ml_detections'],
            },
            'top_attackers': self.get_top_attackers()
        }
    
    def load_audit_log(self):
        try:
            if os.path.exists(self.audit_log_path):
                with open(self.audit_log_path, 'r') as f:
                    return json.load(f)
        except:
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
    SKIP_PREFIXES = ('/static/', '/api/dashboard/', '/favicon')

    @app.before_request
    def track_request():
        path = request.path
        if any(path.startswith(p) for p in SKIP_PREFIXES):
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
        
        # Mask sensitive data for non-admin users
        if current_user['role'] != Role.ADMIN:
            for threat in data.get('recent_threats', []):
                threat['ip'] = "XXX.XXX.XXX.XXX"
                threat['snippet'] = "[HIDDEN]"
                threat['payload'] = "[HIDDEN]"
            data['top_attackers'] = [("XXX.XXX.XXX.XXX", count) for ip, count in data.get('top_attackers', [])]
            
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
        ml_logs = [l for l in logs if l.get('ml_detected') is True or l.get('attack_type') == 'ML Detection']
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

    @app.route('/profile')
    @token_required
    def profile_page(current_user):
        # A simple profile page as requested
        return render_template('dashboard.html', user=current_user, profile_mode=True)

    @app.route('/critical')
    @token_required
    def critical_page(current_user):
        return render_template('critical.html', user=current_user)

    @app.route('/api/critical-threats')
    @token_required
    def get_critical_threats(current_user):
        """Get critical level threats with dynamic scoring"""
        critical_threats = []
        
        for threat in dashboard.threat_log:
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
    app.run(host='0.0.0.0', port=8070, debug=True)