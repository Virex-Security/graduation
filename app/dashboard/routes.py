"""
Dashboard Routes - Flask application and route handlers for SIEM Dashboard
"""
from functools import wraps
import os
import hmac
from venv import logger
from werkzeug.utils import secure_filename

from flask import Flask, current_app, render_template, jsonify, request, redirect, url_for, g
import json
import time
from datetime import datetime, timedelta
import threading
from pathlib import Path
from collections import defaultdict
from functools import wraps
import jwt
import secrets
import bcrypt
from flask_wtf.csrf import CSRFProtect, CSRFError
from app.dashboard.services import SecurityDashboard
mask = CSRFProtect()

from app.dashboard.metrics import calculate_threat_score, is_recent, determine_threat_status, run_timeline_updates

from app.chatbot import SecurityChatbot
from app.auth import login_user, logout_user, refresh_user_tokens, user_manager, Role, token_required, admin_required, require_role
from app.api.security import SimpleSecurityManager
from app.security import new_request_id, is_trivial, is_business_relevant


# Dashboard services and chatbot initialization
dashboard = SecurityDashboard()
security_bot = SecurityChatbot(dashboard)


def create_dashboard_app():
    # Set template and static folders relative to app directory
    project_root = Path(__file__).parent.parent
    template_folder = str(project_root / 'templates')
    static_folder = str(project_root / 'static')
    
    # Try absolute path as fallback
    if not os.path.exists(template_folder):
        # Get absolute path from current working directory
        cwd = Path.cwd()
        template_folder = str(cwd / 'app' / 'templates')
        static_folder = str(cwd / 'app' / 'static')
    
    print(f"Debug - Template folder: {template_folder}")
    print(f"Debug - Static folder: {static_folder}")
    print(f"Debug - Template folder exists: {os.path.exists(template_folder)}")
    print(f"Debug - signup.html exists: {os.path.exists(os.path.join(template_folder, 'signup.html'))}")
    
    app = Flask(__name__, 
                template_folder=template_folder,
                static_folder=static_folder)
    app.config['SECRET_KEY'] = dashboard.secret_key
    app.config['WTF_CSRF_ENABLED'] = True
    app.config['WTF_CSRF_CHECK_DEFAULT'] = True
    csrf = CSRFProtect(app)
    security = SimpleSecurityManager()
    from app.api import responses


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
    # TRAFFIC LOGGER - intercepts every request automatically
    # ----------------------------------------------------------
    @app.before_request
    def load_global_context():
        logs = dashboard.load_audit_log()
        g.logs = logs
        g.global_stats = compute_global_stats(logs)

    # ----------------------------------------------------------
    # GLOBAL SECURITY LAYER - Protects all business-relevant endpoints
    # ----------------------------------------------------------
    @app.before_request

    def security_scan():
        """Strict security scanning using SimpleSecurityManager"""
        request.request_id = new_request_id()
        
        # 1. Strict Allowlist (Skip trivial requests like static files and health checks)
        if is_trivial(request):
            return

        # 2. Extract Real IP
        ip = request.headers.get('X-Forwarded-For', request.remote_addr) or 'Unknown'
        ip = ip.split(',')[0].strip()

        # 3. Rate Limiting Protection (Stricter for auth/login)
        is_auth = request.path.startswith('/api/auth/') or request.path in ('/login', '/api/login')
        window = 60 if is_auth else 900
        limit = 5 if is_auth else 100
        
        if not security.check_rate_limit(ip, window=window, limit=limit):
            security.blocked_requests += 1
            return responses.rate_limited("Rate limit exceeded")

        # 4. Sensitive Path Scanning (Scanner Detection)
        sensitive_paths = ["/admin", "/wp-admin", "/phpmyadmin", "/.env", "/config", "/etc/passwd"]
        if any(request.path.lower().startswith(p) for p in sensitive_paths):
            security.log_to_dashboard(
                "Scanner", ip, f"Sensitive path: {request.path}", "Medium",
                endpoint=request.path, method=request.method,
                detection_type="Scanner", blocked=True,
                request_id=request.request_id
            )
            security.blocked_requests += 1
            return responses.forbidden("Forbidden")

        # 5. Content Security Scan (Args, JSON, Form data)
        data_to_scan = {}
        if request.args: data_to_scan.update(request.args.to_dict())
        if request.is_json:
            j = request.get_json(silent=True)
            if j and isinstance(j, dict): data_to_scan.update(j)
        if request.form: data_to_scan.update(request.form.to_dict())

        if data_to_scan:
            safe, msg = security.check_request_security(data_to_scan, ip)
            if not safe:
                security.blocked_requests += 1
                return responses.bad_request(msg)

        # 6. Global stats and persistent logging
        if is_business_relevant(request):
            security.total_requests += 1
            dashboard.log_clean_request(ip=ip, endpoint=request.path, method=request.method)

    @app.errorhandler(CSRFError)
    def handle_csrf_error(e):
        return responses.bad_request(f'CSRF validation failed: {e.description}')


    @app.route('/api/auth/refresh', methods=['POST'])
    def refresh():
        return refresh_user_tokens()


    @app.route('/api/auth/login', methods=['POST'])
    def login():
        from app.services.auth_service import AuthService
        from app.services.audit_service import AuditService
        
        auth = request.get_json()
        if not auth or not auth.get('username') or not auth.get('password'):
            return responses.unauthorized("Missing credentials")
            
        username = auth.get('username').strip()
        
        # AuthService handles verification, lockout rules, and token generation logic
        resp, status = AuthService.verify_credentials_and_generate_response(username, auth.get('password'))
        
        if status == 200:
            user = AuthService.get_user(username)
            if user:
                ip = _get_real_ip()
                AuditService.log_action(user.get('user_id'), "Login", "Dashboard Access", ip=ip)
        return resp, status

    @app.route('/api/auth/signup', methods=['POST'])
    def signup():
        from app.services.user_service import UserService
        from app.services.audit_service import AuditService
        
        data = request.get_json()
        if not data:
            return responses.bad_request("No input data provided")
            
        username = (data.get('username') or '').strip()
        password = data.get('password')
        
        # Call service to handle registration and business logic
        success, message = UserService.register_user(
            username=username,
            password=password,
            full_name=data.get('fullName', '').strip(),
            email=data.get('email', '').strip(),
            phone=data.get('phone', '').strip(),
            department=data.get('department', '').strip()
        )
        
        if success:
            # Audit log via Service
            AuditService.log_action(None, "Account Created", "User registration", details=f"Username: {username}")
            return responses.created({'message': 'Account created successfully'})
        else:
            return responses.bad_request(message)

    @app.route('/api/auth/logout')
    def logout():
        from app.services.auth_service import AuthService
        from app.services.audit_service import AuditService
        
        token = request.cookies.get('auth_token')
        if token:
            try:
                # Decoupled audit logging
                data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
                user = AuthService.get_user(data['user'])
                if user:
                    AuditService.log_action(user.get('user_id'), "Logout", "Dashboard Session Ended")
            except Exception:
                pass
        
        from app.auth.auth import logout_user
        return logout_user()

    # ── Forgot Password / OTP ─────────────────────────────────
    import random, smtplib
    from email.mime.text import MIMEText
    from app import database as _db

    SMTP_EMAIL    = os.getenv('SMTP_EMAIL')
    from app import config as _cfg
    SMTP_PASSWORD = _cfg.smtp_password()
    SECRET_KEY    = _cfg.secret_key()

    otp_request_tracker = {}

    @app.route('/api/request-reset-otp', methods=['POST'])
    def request_reset_otp():
        from app.services.password_reset_service import PasswordResetService
        from app.repositories.rate_limit_repo import RateLimitRepository
        
        data = request.get_json(silent=True) or {}
        identifier = (data.get('identifier') or data.get('username') or '').strip()
        if not identifier:
            return responses.bad_request('Username or email required')
            
        # Rate Limiting via service-aligned repository
        rl_repo = RateLimitRepository()
        if not rl_repo.check_and_increment(f"otp:{identifier}", window=600, limit=3):
             return responses.rate_limited("Too many requests. Try again later.")
             
        success, message = PasswordResetService.initiate_reset(identifier)
        if success:
            return responses.ok({"message": message})
        else:
            return responses.server_error(message)

    @app.route('/api/verify-reset-otp', methods=['POST'])
    def verify_reset_otp():
        from app.services.password_reset_service import PasswordResetService
        
        data = request.get_json(silent=True) or {}
        identifier = (data.get('identifier') or '').strip()
        otp = (data.get('otp') or '').strip()
        new_password = data.get('new_password')

        if not all([identifier, otp, new_password]):
            # Sometimes frontend uses user_id instead of identifier
            # but our new service prefers identifier (username/email)
            # We'll check if a user_id was passed and resolve it
            user_id = data.get('user_id')
            if user_id:
                from app.repositories.user_repo import UserRepository
                user = UserRepository.get_by_id(user_id)
                if user:
                    identifier = user['username']
            
            if not all([identifier, otp, new_password]):
                return responses.bad_request('Missing fields')
            
        success, message = PasswordResetService.verify_and_reset(identifier, otp, new_password)
        if success:
            return responses.ok({'message': message})
        else:
            return responses.bad_request(message)


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
        api_flag = os.getenv('DASHBOARD_API_ENABLED', 'true').strip().lower()
        dashboard_api_enabled = api_flag in ('1', 'true', 'yes', 'on')
        return render_template(
            'dashboard.html',
            user=current_user,
            dashboard_api_enabled=dashboard_api_enabled,
        )
    @app.route('/api/system/health')
    @token_required
    def system_health(current_user):
        state = dashboard.connection_state or 'Connected'
        api_online = state == 'Connected'
        return responses.ok({
            'status': 'ok' if api_online else 'offline',
            'api_online': api_online,
            'connection_state': state,
            'user': current_user.get('username'),
        })
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

    @app.route('/forgot-password')
    def forgot_password_page():
        # Always show forgot password page, even if user has a token
        return render_template('forgot_password.html')
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
    
    # Static pages routes
    @app.route('/privacy')
    def privacy_page():
        return render_template('privacy.html')
    
    @app.route('/terms')
    def terms_page():
        return render_template('terms.html')
    
    @app.route('/docs')
    def docs_page():
        return render_template('docs.html')
    
    @app.route('/support')
    def support_page():
        return render_template('support.html')
    @app.route('/api/dashboard/data')
    @token_required
    def dashboard_data(current_user):
        global dashboard
        data = dashboard.get_dashboard_data()
        data['connection_state'] = dashboard.connection_state
        # previously we masked IP addresses for non-admin users; the requirement
        # now is to display the source IP in full, so we simply return the data
        # as-is. snippet/payload may still be hidden by the frontend if desired.
        return responses.ok(data)
    from app import config as _cfg
    INTERNAL_SECRET = _cfg.internal_secret()
    if not INTERNAL_SECRET:
        import logging as _log
        _log.getLogger(__name__).error('[CONFIG] INTERNAL_API_SECRET not set')

    def require_internal_secret(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if not INTERNAL_SECRET:
                return responses.error('Internal auth not configured', status=503)
            
            # 1. IP Restriction (Only localhost for internal APIs)
            remote_ip = request.headers.get('X-Forwarded-For', request.remote_addr) or ''
            remote_ip = remote_ip.split(',')[0].strip()
            if remote_ip not in ('127.0.0.1', 'localhost'):
                return responses.forbidden('Forbidden: External access denied')

            # 2. HMAC Verify: signature = hmac(secret, timestamp)
            timestamp = request.headers.get('X-Internal-Timestamp', '')
            signature = request.headers.get('X-Internal-Token', '') # legacy header name
            
            if not timestamp or not signature:
                return responses.unauthorized('Missing internal auth headers')
            
            # Verify timestamp is within 5 minutes (prevent replay)
            try:
                ts_int = float(timestamp)
                if abs(time.time() - ts_int) > 300:
                    return responses.unauthorized('Internal auth expired')
            except (ValueError, TypeError):
                return responses.bad_request('Invalid timestamp')

            expected = hmac.new(
                key=INTERNAL_SECRET.encode(),
                msg=timestamp.encode(),
                digestmod='sha256'
            ).hexdigest()

            if not secrets.compare_digest(signature, expected):
                return responses.forbidden('Invalid internal signature')

            return f(*args, **kwargs)
        return decorated

    @app.route('/api/dashboard/threat', methods=['POST'])
    @csrf.exempt
    @require_internal_secret
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
        return responses.ok({'status': 'logged'})
    @app.route('/api/dashboard/stats', methods=['POST'])
    @require_internal_secret 
    def update_stats():
        global dashboard
        data = request.get_json()
        if 'total_requests' in data:
            dashboard.stats['total_requests'] = data['total_requests']
        if 'blocked_requests' in data:
            dashboard.stats['blocked_requests'] = data['blocked_requests']
        if 'rate_limit_hits' in data:
            dashboard.stats['rate_limit_hits'] = data['rate_limit_hits']
        return responses.ok({'status': 'updated'})
    @app.route('/api/dashboard/reset', methods=['POST'])
    @admin_required
    def reset_stats(current_user):
        from app.services.dashboard_services import AnalyticsService
        from app.services.audit_service import AuditService
        
        try:
            # Service handles the multi-repository clearing logic
            AnalyticsService.reset_all_data()
            
            # Audit log via Service
            AuditService.log_action(current_user.get('user_id'), "Reset Stats", "Dashboard and DB Clear", details="System-wide reset performed.")
            
            return responses.ok({'status': 'stats_reset', 'message': 'All stats and logs cleared'})
        except Exception as e:
            return responses.server_error(str(e))

    @app.route('/api/user')
    @token_required
    def get_current_user(current_user):
        """Return current user information for permission checks"""
        return responses.ok({
            'username': current_user.get('username'),
            'role': current_user.get('role'),
            'email': current_user.get('email', '')
        })
    @app.route('/api/ml/stats')
    @admin_required
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
            return responses.ok(stats)
        except FileNotFoundError as e:
            # can't load model/vectorizer but we still want indicator values returned
            indicators = dashboard.compute_attack_indicators()
            return responses.ok({
                "status": "error",
                "message": f"Model file not found: {e}",
                "attack_indicators": indicators
            })
        except Exception as e:
            # on any other failure, return error flag but still include indicators
            indicators = dashboard.compute_attack_indicators()
            return responses.ok({
                "status": "error",
                "message": str(e),
                "attack_indicators": indicators
            })
    @app.route('/incidents')
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
                            user=current_user,
                            active_page='incidents')
    @app.route('/incident/<id>')
    @admin_required
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
        return responses.ok(incidents_data)
    @app.route('/api/incident/<id>')
    @admin_required
    def get_incident_details(current_user, id):
        global dashboard
        if id not in dashboard.incidents:
            return responses.not_found()
        return responses.ok(dashboard.incidents[id].__dict__)
    @app.route('/api/incident/<id>/action', methods=['POST'])
    @admin_required
    def incident_action(current_user, id):
        from app.services.dashboard_services import IncidentService
        
        data = request.get_json()
        action = data.get('action')
        comment = data.get('comment', '')
        
        # Use service to coordinate incident actions and logging
        success, message = IncidentService.perform_action(id, action, current_user['username'], comment)
        if success:
            return responses.ok({'message': message})
        else:
            return responses.error(message)
    @app.route('/api/incident/<id>/export')
    @admin_required
    def export_incident(current_user, id):
        global dashboard
        if id not in dashboard.incidents:
            return responses.not_found()
        return responses.ok(dashboard.incidents[id].__dict__)
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
        return responses.ok(dist)
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

        grouped_criticals = set()
        for l in attack_logs:
            # Strictly use the 85+ score threshold for high alerts (matches /api/high-threats)
            if calculate_threat_score(l) >= 85:
                grouped_criticals.add((l.get("ip"), l.get("attack_type"), l.get("endpoint")))

        critical_count = len(grouped_criticals)

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
            'ml-detection': 'ML Detection',
            'csrf': 'CSRF',
            'ssrf': 'SSRF',
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
            'ML Detection': 'Anomalies detected by machine learning model',
            'CSRF': 'Cross-Site Request Forgery attempts — missing or invalid CSRF tokens on state-changing requests',
            'SSRF': 'Server-Side Request Forgery attempts — requests targeting internal IPs, metadata services, or dangerous protocols',
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
    @app.route('/threats-overview')
    @token_required
    def threats_overview_page(current_user):
        logs = getattr(g, "logs", dashboard.load_audit_log())
        stats = dashboard.get_dashboard_data().get('stats', {})

        # احسب عدد CSRF و SSRF من سجل التهديدات مباشرةً
        all_threats = dashboard.threat_log
        stats['csrf_attempts'] = sum(
            1 for t in all_threats
            if str(t.get('type', '')).upper() == 'CSRF'
        )
        stats['ssrf_attempts'] = sum(
            1 for t in all_threats
            if str(t.get('type', '')).upper() == 'SSRF'
        )

        return render_template(
            'threats_overview.html',
            stats=stats,
            user=current_user,
            active_page='threats-overview'
        )

    @app.route('/pricing')
    @token_required
    def pricing_page(current_user):
        return render_template(
            'pricing.html',
            user=current_user,
            active_page='pricing'
        )

    @app.route('/payment')
    @token_required
    def payment_page(current_user):
        plan = request.args.get('plan', 'Pro')
        price = request.args.get('price', '29')
        return render_template(
            'payment.html',
            user=current_user,
            plan=plan,
            price=price,
            active_page='pricing'
        )

    @app.route('/api/subscription/upgrade', methods=['POST'])
    @token_required
    def upgrade_subscription(current_user):
        data = request.get_json()
        new_plan = data.get('plan')
        if new_plan not in ['Free', 'Pro', 'Enterprise']:
            return jsonify({'success': False, 'message': 'Invalid plan'}), 400
        
        success, message = user_manager.update_user(current_user['username'], subscription=new_plan)
        if success:
            return responses.ok({'message': message})
        else:
            return responses.bad_request(message)


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
    @admin_required
    def ml_detections_page(current_user):
        # Keep this URL for compatibility, but render the exact same page
        # and layout used by /threats/sql-injection.
        return redirect(url_for('threats_page', category='ml-detection'))
    @app.route('/ml-performance')
    @admin_required
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
                'department': current_user.get('department', 'Security Analyst'),
                'subscription': current_user.get('subscription', 'ENTERPRISE'),
                'created_at': current_user.get('created_at', ''),
                'last_login': current_user.get('last_login', ''),
                'active_sessions': current_user.get('active_sessions', 1),
                'security_score': current_user.get('security_score', 85),
                'account_status': current_user.get('account_status', 'Active'),
                'avatar_url': current_user.get('avatar_url')
            }
        })
    @app.route('/api/profile/activity')
    @token_required
    def get_profile_activity(current_user):
        """Return user activity data"""
        # Mock activity data - replace with real data from your logs
        return jsonify({
            'status': 'success',
            'stats': {
                'alerts_reviewed': 42,
                'incidents_resolved': 15,
                'investigations_created': 8,
                'threat_reports_generated': 3
            },
            'activity_log': [
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
        if not data:
            return jsonify({'status': 'error', 'message': 'No data provided'}), 400
        
        username = current_user.get('username')
        
        # Update user data
        # Whitelist only safe profile fields — EMAIL CHANGE MUST USE VERIFIED FLOW
        ALLOWED_PROFILE_FIELDS = {'full_name', 'department', 'phone'}
        update_data = {k: v for k, v in data.items() if k in ALLOWED_PROFILE_FIELDS}


        if 'password' in data and data['password']:
            is_valid_password, password_message = user_manager.validate_password_policy(data['password'])
            if not is_valid_password:
                return jsonify({'status': 'error', 'message': password_message}), 400
            update_data['password'] = data['password']
        
        # Update user in user manager
        success, message = user_manager.update_user(username, **update_data)
        
        if success:
            log_action(current_user, "Profile Updated", f"Updated profile information: {', '.join(update_data.keys())}")
            return jsonify({'status': 'success', 'message': 'Profile updated successfully'})
        else:
            return jsonify({'status': 'error', 'message': message or 'Failed to update profile'}), 400

    @app.route('/api/profile/request-email-change', methods=['POST'])
    @token_required
    def request_email_change(current_user):
        """Phase 1: Initiate email change by sending OTP to the new address"""
        data = request.get_json() or {}
        new_email = data.get('new_email', '').strip()
        
        if not new_email or '@' not in new_email:
            return jsonify({'status': 'error', 'message': 'Invalid new email address'}), 400
            
        username = current_user.get('username')
        user_id = current_user.get('user_id') or current_user.get('id')
        
        # Generate secure token
        token = secrets.token_urlsafe(16)
        token_hash = bcrypt.hashpw(token.encode(), bcrypt.gensalt()).decode()
        expiry = (datetime.now() + timedelta(minutes=5)).strftime('%Y-%m-%d %H:%M:%S')
        
        with _db.db_cursor() as cur:
            cur.execute("""
                UPDATE users 
                SET pending_email = ?, email_otp_hash = ?, email_otp_expiry = ?, email_otp_attempts = 0 
                WHERE user_id = ?
            """, (new_email, token_hash, expiry, user_id))
            
        # Send OTP to NEW email
        try:
            subject = "Confirm Your New Email Address"
            body = f"Your confirmation token for updating your email is: {token}\nThis token will expire in 5 minutes."
            msg = MIMEText(body)
            msg['Subject'] = subject
            msg['From'] = SMTP_EMAIL
            msg['To'] = new_email

            with smtplib.SMTP_SSL('smtp.gmail.com', 465) as server:
                server.login(SMTP_EMAIL, SMTP_PASSWORD)
                server.sendmail(SMTP_EMAIL, [new_email], msg.as_string())
            
            log_action(current_user, "Email Change Requested", f"OTP sent to {new_email}")
            return jsonify({'status': 'success', 'message': 'Confirmation token sent to your new email'})
        except Exception as e:
            logger.error(f"Failed to send email change OTP: {e}")
            return jsonify({'status': 'error', 'message': 'Failed to send confirmation token'}), 500

    @app.route('/api/profile/confirm-email-change', methods=['POST'])
    @token_required
    def confirm_email_change(current_user):
        """Phase 2: Verify OTP and finalize the email change"""
        data = request.get_json() or {}
        token = data.get('token', '').strip()
        
        if not token:
            return jsonify({'status': 'error', 'message': 'Confirmation token is required'}), 400
            
        user_id = current_user.get('user_id') or current_user.get('id')
        
        with _db.db_cursor() as cur:
            cur.execute("SELECT email, pending_email, email_otp_hash, email_otp_expiry, email_otp_attempts FROM users WHERE user_id = ?", (user_id,))
            record = cur.fetchone()
            
        if not record or not record['pending_email']:
            return jsonify({'status': 'error', 'message': 'No pending email change found'}), 400
            
        if record['email_otp_attempts'] >= 5:
            return jsonify({'status': 'error', 'message': 'Too many failed attempts. Please request a new token.'}), 429
            
        # Verify Token
        if not bcrypt.checkpw(token.encode(), record['email_otp_hash'].encode()):
            with _db.db_cursor() as cur:
                cur.execute("UPDATE users SET email_otp_attempts = email_otp_attempts + 1 WHERE user_id = ?", (user_id,))
            return jsonify({'status': 'error', 'message': 'Invalid confirmation token'}), 400
            
        # Check Expiry
        if datetime.now() > datetime.strptime(record['email_otp_expiry'], '%Y-%m-%d %H:%M:%S'):
            return jsonify({'status': 'error', 'message': 'Confirmation token has expired'}), 400
            
        # Success: Swap Email
        new_email = record['pending_email']
        with _db.db_cursor() as cur:
            cur.execute("""
                UPDATE users 
                SET email = ?, pending_email = NULL, email_otp_hash = NULL, email_otp_expiry = NULL, email_otp_attempts = 0 
                WHERE user_id = ?
            """, (new_email, user_id))
            
        log_action(current_user, "Email Changed", f"Changed from {record['email']} to {new_email}")
        return jsonify({'status': 'success', 'message': 'Email updated successfully'})

    @app.route('/api/profile/change-password', methods=['POST'])

    @token_required
    def change_password_profile(current_user):
        """Change user password"""
        data = request.get_json() or {}
        current_password = data.get('current_password')
        new_password = data.get('new_password')
        username = current_user.get('username')

        if not current_password or not new_password:
            return jsonify({'status': 'error', 'message': 'Current and new password are required'}), 400

        if not user_manager.verify_password(username, current_password):
            return jsonify({'status': 'error', 'message': 'Current password is incorrect'}), 400

        success, message = user_manager.change_password(username, new_password)
        if not success:
            return jsonify({'status': 'error', 'message': message}), 400

        log_action(current_user, "Password Changed", "User changed their password")
        return jsonify({'status': 'success', 'message': message})
    @app.route('/api/profile/logout-session', methods=['POST'])
    @token_required
    def logout_session(current_user):
        """Logout a specific session"""
        session_id = request.get_json().get('session_id')
        log_action(current_user, "Session Revoked", f"Revoked session: {session_id}")
        return jsonify({'status': 'success', 'message': 'Session revoked successfully'})

    @app.route('/api/profile/avatar', methods=['POST'])
    @token_required
    def upload_avatar(current_user):
        import magic  # python-magic: validates actual file bytes, not just extension

        # ── Security Constants ─────────────────────────────────
        MAX_UPLOAD_BYTES = 2 * 1024 * 1024         # 2 MB hard limit
        ALLOWED_EXTS     = {'.png', '.jpg', '.jpeg', '.gif', '.webp'}
        ALLOWED_MIMES    = {
            'image/png', 'image/jpeg', 'image/gif', 'image/webp'
        }

        file = request.files.get('avatar')
        if not file or file.filename == '':
            return jsonify({'error': 'No file provided'}), 400

        # 1. Extension whitelist
        filename = secure_filename(file.filename)
        ext = os.path.splitext(filename)[1].lower()
        if ext not in ALLOWED_EXTS:
            return jsonify({'error': f'File extension not allowed. Permitted: {", ".join(ALLOWED_EXTS)}'}), 400

        # 2. Size limit — read into memory up to MAX+1 bytes to detect oversized files
        #    without buffering the entire upload first.
        chunk = file.read(MAX_UPLOAD_BYTES + 1)
        if len(chunk) > MAX_UPLOAD_BYTES:
            return jsonify({'error': f'File too large. Maximum allowed size is 2 MB.'}), 413
        file.seek(0)

        # 3. True MIME validation via libmagic (reads binary file signature)
        detected_mime = magic.from_buffer(chunk, mime=True)
        if detected_mime not in ALLOWED_MIMES:
            logger.warning(
                f"[UPLOAD] Blocked upload from {current_user.get('username')}: "
                f"extension={ext}, detected MIME={detected_mime}"
            )
            return jsonify({'error': f'File content does not match a permitted image type (detected: {detected_mime})'}), 400

        # 4. Save with a randomised, user-scoped filename (no path traversal possible)
        upload_dir = Path(current_app.root_path) / 'static' / 'uploads' / 'avatars'
        upload_dir.mkdir(parents=True, exist_ok=True)
        new_filename = f"{secure_filename(current_user['username'])}_{int(time.time())}{ext}"
        file.seek(0)
        file.save(str(upload_dir / new_filename))

        avatar_url = url_for('static', filename=f'uploads/avatars/{new_filename}')
        user_manager.update_user(current_user.get('username'), avatar_url=avatar_url)
        log_action(current_user, "Avatar Upload", f"Uploaded avatar: {new_filename} ({detected_mime})")

        return jsonify({'status': 'success', 'avatar_url': avatar_url})


    # ============================================================
    # SETTINGS PAGE
    # ============================================================
    @app.route('/settings')
    @admin_required
    def settings_page(current_user):
        """Settings page for system configuration"""
        return render_template('settings.html', user=current_user)
    
    @app.route('/api/settings', methods=['GET'])
    @admin_required
    def get_settings(current_user):
        """Get current system settings"""
        # Load settings from a config file or database
        settings = {
            'general': {
                'site_name': 'VIREX Security',
                'timezone': 'UTC',
                'language': 'en',
                'date_format': 'YYYY-MM-DD',
            },
            'security': {
                'session_timeout': 30,
                'max_login_attempts': 5,
                'password_expiry_days': 90,
                'require_2fa': False,
            },
            'notifications': {
                'email_alerts': True,
                'slack_integration': False,
                'alert_threshold': 'medium',
            },
            'ml_model': {
                'auto_retrain': True,
                'confidence_threshold': 0.85,
                'model_version': '2.1.0',
            },
            'api': {
                'rate_limit': 1000,
                'api_key_expiry_days': 365,
                'cors_enabled': False,
            }
        }
        return jsonify(settings)
    
    @app.route('/api/settings', methods=['POST'])
    @admin_required
    def update_settings(current_user):
        """Update system settings (Admin only)"""
        data = request.get_json()
        # Here you would save settings to database or config file
        log_action(current_user, "Settings Updated", f"Updated system settings")
        return jsonify({'status': 'success', 'message': 'Settings updated successfully'})

    # ============================================================
    # USER MANAGER (Admin Only)
    # ============================================================
    @app.route('/user-manager')
    @admin_required
    def user_manager_page(current_user):
        """User management page for admins"""
        return render_template('user_manager.html', user=current_user)
    
    @app.route('/api/users', methods=['GET'])
    @admin_required
    def get_users(current_user):
        """Get all users with their activity"""
        users = user_manager.get_all_users()
        
        # Get user activities from audit log
        audit_logs = dashboard.load_audit_log()
        user_activities = {}
        
        for log in audit_logs:
            username = log.get('username')
            if username and username not in user_activities:
                user_activities[username] = {
                    'actions': 0,
                    'last_action': None,
                    'actions_list': []
                }
            
            if username:
                user_activities[username]['actions'] += 1
                user_activities[username]['actions_list'].append({
                    'action': log.get('action', 'Unknown'),
                    'timestamp': log.get('timestamp'),
                    'details': log.get('details', '')
                })
                if not user_activities[username]['last_action']:
                    user_activities[username]['last_action'] = log.get('timestamp')
        
        # Combine user data with activities
        users_with_activity = []
        for user in users:
            username = user.get('username')
            activity = user_activities.get(username, {
                'actions': 0,
                'last_action': None,
                'actions_list': []
            })
            
            users_with_activity.append({
                **user,
                'total_actions': activity['actions'],
                'last_action': activity['last_action'],
                'recent_actions': activity['actions_list'][-10:]  # Last 10 actions
            })
        
        return jsonify({'users': users_with_activity})
    
    @app.route('/api/users/<user_id>', methods=['GET'])
    @admin_required
    def get_user_details(current_user, user_id):
        """Get detailed information about a specific user"""
        user = user_manager.get_user_by_id(user_id)
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        # Get all actions by this user
        audit_logs = dashboard.load_audit_log()
        user_actions = [log for log in audit_logs if log.get('username') == user.get('username')]
        
        return jsonify({
            'user': user,
            'actions': user_actions[-50:]  # Last 50 actions
        })
    
    @app.route('/api/users/<user_id>/toggle-status', methods=['POST'])
    @admin_required
    def toggle_user_status(current_user, user_id):
        """Activate or deactivate a user"""
        user = user_manager.get_user_by_id(user_id)
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        new_status = 'inactive' if user.get('status') == 'active' else 'active'
        # Update user status in database
        user_manager.update_user(user.get('username'), status=new_status)
        log_action(current_user, "User Status Changed", f"Changed {user.get('username')} status to {new_status}")
        
        return jsonify({'status': 'success', 'new_status': new_status})
    
    @app.route('/api/users/<user_id>/change-role', methods=['POST'])
    @admin_required
    def change_user_role(current_user, user_id):
        """Change user role"""
        data = request.get_json()
        new_role = data.get('role')
        
        valid_roles = ['admin', 'user', 'viewer']
        if not new_role or new_role not in valid_roles:
            return jsonify({'error': f'Invalid role. Must be one of: {", ".join(valid_roles)}'}), 400
        
        user = user_manager.get_user_by_id(user_id)
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        # Update user role
        user_manager.update_user(user.get('username'), role=new_role)
        log_action(current_user, "User Role Changed", f"Changed {user.get('username')} role to {new_role}")
        
        return jsonify({'status': 'success', 'new_role': new_role})
    
    @app.route('/api/users/<user_id>', methods=['DELETE'])
    @admin_required
    def delete_user(current_user, user_id):
        """Delete a user"""
        user = user_manager.get_user_by_id(user_id)
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        if user.get('username') == current_user.get('username'):
            return jsonify({'error': 'Cannot delete your own account'}), 400
        
        # Delete user
        user_manager.delete_user(user.get('username'))
        log_action(current_user, "User Deleted", f"Deleted user {user.get('username')}")
        
        return jsonify({'status': 'success', 'message': 'User deleted successfully'})
    
    @app.route('/api/users', methods=['POST'])
    @admin_required
    def create_user(current_user):
        """Create a new user"""
        try:
            data = request.get_json()
            username = data.get('username')
            email = data.get('email')
            password = data.get('password')
            role = data.get('role', 'viewer')
            
            if not username or not email or not password:
                return jsonify({'error': 'Username, email, and password are required'}), 400
            
            # Check if user already exists
            existing_user = user_manager.get_user(username)
            if existing_user:
                return jsonify({'error': 'Username already exists'}), 400
            
            # Create new user
            new_user = user_manager.create_user(
                username=username,
                password=password,
                email=email,
                role=role
            )
            
            log_action(current_user, "User Created", f"Created new user: {username} with role: {role}")
            
            return jsonify({
                'status': 'success',
                'message': 'User created successfully',
                'user': new_user
            })
        except Exception as e:
            print(f"Error creating user: {e}")
            return jsonify({'error': str(e)}), 500

    @app.route('/critical')
    @token_required
    def critical_page(current_user):
        return render_template('critical.html', user=current_user)
    @app.route('/api/high-threats')
    @token_required
    def get_high_threats(current_user):
        """Get high level threats with dynamic scoring (threshold >= 85)"""
        grouped_threats = {}
        logs = dashboard.load_audit_log()
        
        for threat in logs:
            if threat.get('type', 'Clean') == 'Clean' and threat.get('attack_type', 'Clean') == 'Clean':
                continue
            
            threat_score = calculate_threat_score(threat)
            # Only include threats that meet the strict 85+ score threshold
            if threat_score >= 85:
                ip = threat.get('ip', 'Unknown')
                attack_type = threat.get('attack_type', 'Unknown')
                endpoint = threat.get('endpoint', 'Unknown')
                key = (ip, attack_type, endpoint)
                
                if key not in grouped_threats:
                    threat_with_score = threat.copy()
                    threat_with_score['threat_score'] = threat_score
                    threat_with_score['ml_confidence'] = int(threat.get('confidence', 0) * 100)
                    threat_with_score['frequency'] = dashboard.ip_tracker.get(ip, 1)
                    threat_with_score['status'] = determine_threat_status(threat)
                    grouped_threats[key] = threat_with_score
                else:
                    # Update existing group with latest occurrence data
                    existing = grouped_threats[key]
                    if existing.get('threat_score', 0) < threat_score:
                        existing['threat_score'] = threat_score
                        existing['ml_confidence'] = int(threat.get('confidence', 0) * 100)
                    existing['timestamp'] = threat.get('timestamp', existing.get('timestamp'))
                    existing['frequency'] = dashboard.ip_tracker.get(ip, 1)

        critical_threats = list(grouped_threats.values())
        
        # Assign Threat IDs
        for idx, threat in enumerate(critical_threats):
            threat['threat_id'] = f"THR-{idx + 1:03d}"
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

    # ============================================================
    # BLACKLIST MANAGEMENT (Admin Only)
    # ============================================================
    @app.route('/blacklist')
    @admin_required
    def blacklist_page(current_user):
        """Blacklist management page for admins"""
        return render_template('blacklist.html', user=current_user)
    
    @app.route('/api/blacklist', methods=['GET'])
    @admin_required
    def get_blacklist(current_user):
        """Get all blacklist entries"""
        try:
            project_root = Path(__file__).parent.parent.parent
            blacklist_file = project_root / 'data' / 'blacklist.json'
            if blacklist_file.exists():
                with open(blacklist_file, 'r') as f:
                    blacklist = json.load(f)
            else:
                blacklist = []
            
            return jsonify({'blacklist': blacklist})
        except Exception as e:
            print(f"Error loading blacklist: {e}")
            return jsonify({'blacklist': []})
    
    @app.route('/api/blacklist', methods=['POST'])
    @admin_required
    def add_blacklist(current_user):
        """Add new entry to blacklist"""
        try:
            data = request.get_json()
            blacklist_type = data.get('type')
            value = data.get('value')
            reason = data.get('reason')
            status = data.get('status', 'active')
            
            if not blacklist_type or not value or not reason:
                return jsonify({'error': 'Type, value, and reason are required'}), 400
            
            # Load existing blacklist
            project_root = Path(__file__).parent.parent.parent
            blacklist_file = project_root / 'data' / 'blacklist.json'
            if blacklist_file.exists():
                with open(blacklist_file, 'r') as f:
                    blacklist = json.load(f)
            else:
                blacklist = []
            
            # Generate new ID
            new_id = max([item.get('id', 0) for item in blacklist], default=0) + 1
            
            # Create new entry
            new_entry = {
                'id': new_id,
                'type': blacklist_type,
                'value': value,
                'reason': reason,
                'status': status,
                'added_by': current_user.get('username'),
                'date_added': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }
            
            blacklist.append(new_entry)
            
            # Save blacklist
            blacklist_file.parent.mkdir(parents=True, exist_ok=True)
            with open(blacklist_file, 'w') as f:
                json.dump(blacklist, f, indent=2)
            
            log_action(current_user, "Blacklist Entry Added", f"Added {blacklist_type}: {value}")
            
            return jsonify({'status': 'success', 'message': 'Added to blacklist successfully', 'entry': new_entry})
        except Exception as e:
            print(f"Error adding to blacklist: {e}")
            return jsonify({'error': str(e)}), 500
    
    @app.route('/api/blacklist/<int:entry_id>', methods=['PUT'])
    @admin_required
    def update_blacklist(current_user, entry_id):
        """Update blacklist entry"""
        try:
            data = request.get_json()
            
            # Load existing blacklist
            project_root = Path(__file__).parent.parent.parent
            blacklist_file = project_root / 'data' / 'blacklist.json'
            if not blacklist_file.exists():
                return jsonify({'error': 'Blacklist not found'}), 404
            
            with open(blacklist_file, 'r') as f:
                blacklist = json.load(f)
            
            # Find and update entry
            entry = next((item for item in blacklist if item.get('id') == entry_id), None)
            if not entry:
                return jsonify({'error': 'Entry not found'}), 404
            
            # Update fields
            if 'reason' in data:
                entry['reason'] = data['reason']
            if 'status' in data:
                entry['status'] = data['status']
            
            entry['updated_by'] = current_user.get('username')
            entry['date_updated'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            
            # Save blacklist
            with open(blacklist_file, 'w') as f:
                json.dump(blacklist, f, indent=2)
            
            log_action(current_user, "Blacklist Entry Updated", f"Updated entry ID: {entry_id}")
            
            return jsonify({'status': 'success', 'message': 'Blacklist entry updated successfully'})
        except Exception as e:
            print(f"Error updating blacklist: {e}")
            return jsonify({'error': str(e)}), 500
    
    @app.route('/api/blacklist/<int:entry_id>', methods=['DELETE'])
    @admin_required
    def delete_blacklist(current_user, entry_id):
        """Delete blacklist entry"""
        try:
            # Load existing blacklist
            project_root = Path(__file__).parent.parent.parent
            blacklist_file = project_root / 'data' / 'blacklist.json'
            if not blacklist_file.exists():
                return jsonify({'error': 'Blacklist not found'}), 404
            
            with open(blacklist_file, 'r') as f:
                blacklist = json.load(f)
            
            # Find and remove entry
            entry = next((item for item in blacklist if item.get('id') == entry_id), None)
            if not entry:
                return jsonify({'error': 'Entry not found'}), 404
            
            blacklist = [item for item in blacklist if item.get('id') != entry_id]
            
            # Save blacklist
            with open(blacklist_file, 'w') as f:
                json.dump(blacklist, f, indent=2)
            
            log_action(current_user, "Blacklist Entry Deleted", f"Deleted {entry.get('type')}: {entry.get('value')}")
            
            return jsonify({'status': 'success', 'message': 'Blacklist entry deleted successfully'})
        except Exception as e:
            print(f"Error deleting blacklist: {e}")
            return jsonify({'error': str(e)}), 500

    @app.after_request
    def add_security_headers(response):
        """Global security headers to harden the application"""
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['X-XSS-Protection'] = '1; mode=block'
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
        response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        
        # Strict Content Security Policy
        csp = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
            "style-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com https://fonts.googleapis.com https://cdn.jsdelivr.net; "
            "font-src 'self' https://cdnjs.cloudflare.com https://fonts.gstatic.com; "
            "img-src 'self' data: *; "
            "connect-src 'self';"
        )
        response.headers['Content-Security-Policy'] = csp
        return response

    # ── Attack History Page ───────────────────────────────────

    @app.route('/attack-history')
    @token_required
    def attack_history_page(current_user):
        return render_template('attack_history.html', user=current_user)

    return app
def calculate_threat_score(threat):
    """Calculate threat score based on multiple factors (0-100)"""
    score = 100 # Base score increased to 100 to allow High-severity threats (85) to reach 85+
    # Severity multiplier
    severity_map = {'Low': 0.5, 'Medium': 0.7, 'High': 0.85, 'Critical': 1.0}
    raw_severity = str(threat.get('severity', 'High')).title()
    score *= severity_map.get(raw_severity, 0.85)
    # ML detection boost
    if threat.get('ml_detected'):
        score += 25
    # Confidence boost
    confidence = threat.get('confidence', 0)
    score += confidence * 10
    # Blocked incident boost (increased to 35 to ensure High-severity blocked threats hit 85+)
    if threat.get('blocked'):
        score += 35
    return min(int(score), 100) # Cap at 100
def is_recent(timestamp_str):
    """Check if timestamp is within last 24 hours"""
    try:
        threat_time = datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S")
        now = datetime.now()
        return (now - threat_time).total_seconds() < 86400 # 24 hours
    except (ValueError, TypeError):
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
    except (ValueError, TypeError):
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
    _debug = os.getenv('FLASK_DEBUG', 'false').lower() == 'true'
    app.run(host='127.0.0.1', port=8070, debug=_debug, use_reloader=False)