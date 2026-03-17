"""
Dashboard Routes - Flask application and route handlers for SIEM Dashboard
"""
from flask import Flask, render_template, jsonify, request, redirect, url_for, g
import json
import time
from datetime import datetime, timedelta
import threading
import os
from pathlib import Path
import jwt

from app.dashboard.services import SecurityDashboard
from app.dashboard.metrics import calculate_threat_score, is_recent, determine_threat_status, run_timeline_updates
from app.chatbot import SecurityChatbot
from app.auth import login_user, logout_user, user_manager, Role, token_required, admin_required, require_role

# Dashboard services and chatbot initialization
dashboard = SecurityDashboard()
security_bot = SecurityChatbot(dashboard)


def create_dashboard_app():
    # Set template and static folders relative to app directory
    project_root = Path(__file__).parent.parent
    template_folder = str(project_root / 'templates')
    static_folder = str(project_root / 'static')
    
    app = Flask(__name__, 
                template_folder=template_folder,
                static_folder=static_folder)
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
        '/dashboard', '/critical', '/blocked', '/blocked_page', '/incidents',
        '/requests', '/profile', '/ml-detections',
        '/threats/sql-injection', '/threats/xss',
        '/threats/ml-detection', '/threats/brute-force',
        '/threats/scanner', '/threats/rate-limit',
        '/login', '/signup', '/',
    }
    @app.before_request
    def load_global_context():
        logs = dashboard.load_audit_log()
        g.logs = logs
        g.global_stats = compute_global_stats(logs)

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
        # as-is. snippet/payload may still be hidden by the frontend if desired.
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
          TP = ML flagged (detection_type==ML) AND it was a real attack (attack_type != Clean)
          FP = ML flagged AND the request was actually Clean (false alarm)
          TN = Not ML flagged AND request was Clean (correct pass)
          FN = Not ML flagged AND request was a real attack (missed attack)
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
    @app.route('/incidents_list')
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
    def _attack_logs_only(logs):
      return [
          l for l in logs
          if "action" not in l
          and l.get("attack_type") not in ("Clean", None, "")
          and l.get("type") not in ("Clean", None, "")
      ]

    def compute_global_stats(logs):
        attack_logs = _attack_logs_only(logs)

        critical_count = sum(
            1 for l in attack_logs
            if l.get("severity") in ("High", "Critical")
        )

        total_attacks = len(attack_logs)
        blocked_count = sum(1 for l in attack_logs if l.get("blocked") is True)

        unique_ips = len(set(
            l.get("ip") for l in attack_logs
            if l.get("ip") and l.get("ip") not in ("Unknown", "XXX.XXX.XXX.XXX")
        ))

        return {
            "critical_count": critical_count,      # نفس اسم التيمبلت القديم
            "total_attacks": total_attacks,
            "blocked_count": blocked_count,
            "unique_ips": unique_ips,
        }
    @app.route('/threats/<category>')
    @token_required
    def threats_page(current_user, category):
        logs = getattr(g, "logs", dashboard.load_audit_log())
        stats = getattr(g, "global_stats", compute_global_stats(logs))

        category_map = {
            'sql-injection': 'SQL Injection',
            'xss': 'XSS',
            'brute-force': 'Brute Force',
            'scanner': 'Scanner',
            'rate-limit': 'Rate Limit',
            'ml-detection': 'ML Detection'
        }
        filter_value = category_map.get(category, category)

        if category == 'ml-detection':
            filtered_logs = [
                l for l in logs
                if l.get('attack_type') == filter_value
                or l.get('type') == filter_value
                or l.get('ml_detected') is True
                or str(l.get('detection_type', '')).lower().startswith('ml')
            ]
        else:
            filtered_logs = [l for l in logs if l.get('attack_type') == filter_value or l.get('type') == filter_value]

        filter_ip = request.args.get('ip')
        if filter_ip:
            filtered_logs = [l for l in filtered_logs if l.get('ip') == filter_ip or l.get('source_ip') == filter_ip]

        filtered_logs.sort(key=lambda x: x.get('timestamp', ''), reverse=True)

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

      

        unique_ips = len(set(l.get('ip', '') for l in filtered_logs if l.get('ip')))

        descriptions = {
            'SQL Injection': 'SQL Injection attempts detected and analyzed',
            'XSS': 'Cross-Site Scripting (XSS) attacks detected',
            'Brute Force': 'Brute force authentication attempts',
            'Scanner': 'Security scanner and reconnaissance activities',
            'Rate Limit': 'Rate limit violations and abuse attempts',
            'ML Detection': 'Anomalies detected by machine learning model'
        }

        return render_template(
          'threat_details.html',
          logs=filtered_logs,
          title=filter_value,
          description=descriptions.get(filter_value, f'{filter_value} detections'),
          total_count=total_count,
          blocked_count=blocked_count,
          unique_ips=unique_ips, #
          critical_count=stats["critical_count"],

          user=current_user
  )

    @app.route('/blocked_page')
    @app.route('/blocked')
    @token_required
    def blocked_page(current_user):
        logs = getattr(g, "logs", dashboard.load_audit_log())
        stats = getattr(g, "global_stats", compute_global_stats(logs))

        blocked_logs = [l for l in logs if l.get('blocked') is True]
        blocked_logs.sort(key=lambda x: x.get('timestamp', ''), reverse=True)

        return render_template(
            'blocked_page.html',
            logs=blocked_logs,
            title="Blocked Requests",
            description="Automatically blocked security events",
            total_count=len(blocked_logs),
            blocked_count=len(blocked_logs),
            critical_count=stats["critical_count"],
            unique_ips=len(set(l.get('ip', '') for l in blocked_logs if l.get('ip'))),
            user=current_user
        )

    @app.route('/ml-detections')
    @token_required
    def ml_detections_page(current_user):
        # Keep this URL for compatibility, but render the exact same page
        # and layout used by /threats/sql-injection.
        return redirect(url_for('threats_page', category='ml-detection'))
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
    score = 50 # Base score
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
    return min(int(score), 100) # Cap at 100
def is_recent(timestamp_str):
    """Check if timestamp is within last 24 hours"""
    try:
        threat_time = datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S")
        now = datetime.now()
        return (now - threat_time).total_seconds() < 86400 # 24 hours
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
