"""
Dashboard Routes - Flask application and route handlers for SIEM Dashboard
"""
from functools import wraps
import os
import hmac
from venv import logger
from werkzeug.utils import secure_filename

from flask import Flask, current_app, render_template, jsonify, request, redirect, url_for, g, send_from_directory
import json
import time
from datetime import datetime, timedelta
import threading
from pathlib import Path
from collections import defaultdict
from functools import wraps
import jwt
import secrets
from app.dashboard.services import SecurityDashboard
from app.dashboard.services import SecurityDashboard
from app.dashboard.metrics import calculate_threat_score, is_recent, determine_threat_status, run_timeline_updates
from app.chatbot import SecurityChatbot
from app.auth import login_user, logout_user, user_manager, Role, token_required, admin_required, require_role
from app.api.responses import ok, created, bad_request, unauthorized, forbidden, not_found, conflict, rate_limited, server_error, paginated

# Dashboard services and chatbot initialization
dashboard = SecurityDashboard()
security_bot = SecurityChatbot(dashboard)


def create_dashboard_app():
    # ── Initialization ────────────────────────────────────────
    import random, smtplib
    from email.mime.text import MIMEText
    from app import database as _db
    from app import config as _cfg
    
    # Paths & Folders
    project_root = Path(__file__).parent.parent
    template_folder = str(project_root / 'templates')
    static_folder = str(project_root / 'static')
    
    if not os.path.exists(template_folder):
        cwd = Path.cwd()
        template_folder = str(cwd / 'app' / 'templates')
        static_folder = str(cwd / 'app' / 'static')
    
    print(f"Debug - Template folder: {template_folder}")
    print(f"Debug - Static folder: {static_folder}")
    print(f"Debug - Template folder exists: {os.path.exists(template_folder)}")
    print(f"Debug - signup.html exists: {os.path.exists(os.path.join(template_folder, 'signup.html'))}")
    
    app = Flask(__name__, template_folder=template_folder, static_folder=static_folder)
    
    # Config & Secrets
    app.config['SECRET_KEY'] = dashboard.secret_key
    SMTP_EMAIL    = os.getenv('SMTP_EMAIL')
    SMTP_PASSWORD = _cfg.smtp_password()
    SECRET_KEY    = _cfg.secret_key()
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
    SKIP_PREFIXES = ('/static/', '/api/dashboard/', '/api/system/', '/favicon', '/api/auth/', '/api/critical-threats', '/api/chat', '/api/ml/', '/api/user', '/api/incidents', '/api/critical')
    # Dashboard internal pages - should not be counted as traffic
    SKIP_EXACT = {
        '/dashboard', '/critical', '/blocked', '/blocked_page', '/incidents',
        '/requests', '/profile', '/ml-detections',
        '/threats/sql-injection', '/threats/xss',
        '/threats/ml-detection', '/threats/brute-force',
        '/threats/scanner', '/threats/rate-limit',
        '/login', '/signup', '/',
        '/privacy', '/terms', '/docs', '/support',
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
            return unauthorized('Missing credentials')
        resp, status = login_user(auth.get('username'), auth.get('password'))
        if status == 200:
            user = user_manager.get_user(auth.get('username'))
            from app.database import log_audit
            user_id = user.get('id') if user else None
            ip = request.headers.get('X-Forwarded-For', request.remote_addr) or 'Unknown'
            ip = ip.split(',')[0].strip()
            if user_id:
                log_audit(user_id, "Login", ip)
        return resp, status
    @app.route('/api/auth/signup', methods=['POST'])
    def signup():
        auth = request.get_json()
        if not auth or not auth.get('username') or not auth.get('password'):
            return bad_request('Missing username or password')
        
        username = auth.get('username').strip()
        password = auth.get('password')
        full_name = auth.get('fullName', '').strip()
        email = auth.get('email', '').strip()
        phone = auth.get('phone', '').strip()
        department = auth.get('department', '').strip()
        
        # Validation
        if len(username) < 3:
            return bad_request('Username must be at least 3 characters')
            
        if not full_name:
            return bad_request('Full name is required')
            
        if not email:
            return bad_request('Email is required')
            
        # Basic email validation
        import re
        email_pattern = r'^[^\s@]+@[^\s@]+\.[^\s@]+$'
        if not re.match(email_pattern, email):
            return bad_request('Please enter a valid email address')
            
        if not phone:
            return bad_request('Phone number is required')
            
        if not department:
            return bad_request('Department is required')
        
        is_valid_password, password_message = user_manager.validate_password_policy(password)
        if not is_valid_password:
            return bad_request(password_message)
            
        # Check if user already exists
        if user_manager.get_user(username):
            return conflict('Username already exists')
            
        # Add new user with USER role and additional info
        success, message = user_manager.add_user(username, password, Role.USER)
        if success:
            # Update user with additional information
            user_manager.update_user(username, 
                                  full_name=full_name,
                                  email=email,
                                  department=department,
                                  phone=phone)
            
            # Log the new user creation
            new_user = user_manager.get_user(username)
            log_action(new_user, "Account Created", f"Full name: {full_name}, Email: {email}")
<<<<<<< HEAD
            return jsonify({'message': 'Account created successfully'}), 201
        else:
            return jsonify({'message': message}), 400
=======
<<<<<<< HEAD
            return jsonify({'message': 'Account created successfully'}), 201
        else:
            return jsonify({'message': message}), 400
=======
            return created(message='Account created successfully')
        else:
            return bad_request(message)
>>>>>>> 4c5ae8566bbeb2af6ffddd6da0dc25f97d5a40fa
>>>>>>> 29c1406ff0d33cca29bb3c738f3c070c695be578
    @app.route('/api/auth/logout')
    def logout():
        token = request.cookies.get('auth_token')
        if token:
            try:
                data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
                user = user_manager.get_user(data['user'])
                if user:
                    log_action(user, "Logout")
            except Exception:
                pass
        return logout_user()
    # ── Forgot Password / OTP ─────────────────────────────────
<<<<<<< HEAD
=======
<<<<<<< HEAD
>>>>>>> 29c1406ff0d33cca29bb3c738f3c070c695be578
    import random, smtplib
    from email.mime.text import MIMEText
    from app import database as _db

    SMTP_EMAIL    = os.getenv('SMTP_EMAIL')
    from app import config as _cfg
    SMTP_PASSWORD = _cfg.smtp_password()
    SECRET_KEY    = _cfg.secret_key()

    otp_request_tracker = {}
<<<<<<< HEAD
=======
=======


>>>>>>> 4c5ae8566bbeb2af6ffddd6da0dc25f97d5a40fa
>>>>>>> 29c1406ff0d33cca29bb3c738f3c070c695be578

    @app.route('/api/request-reset-otp', methods=['POST'])
    def request_reset_otp():
        data       = request.get_json(silent=True) or {}
        identifier = (data.get('identifier') or data.get('username') or '').strip()
        if not identifier:
<<<<<<< HEAD
=======
<<<<<<< HEAD
>>>>>>> 29c1406ff0d33cca29bb3c738f3c070c695be578
            return jsonify({'error': 'Username or email required'}), 400
            
        current_time = time.time()
        requests_history = otp_request_tracker.get(identifier, [])
        requests_history = [t for t in requests_history if current_time - t < 600]
        
        if len(requests_history) >= 3:
            return jsonify({"error": "Too many requests. Try again later."}), 429
            
        requests_history.append(current_time)
        otp_request_tracker[identifier] = requests_history
<<<<<<< HEAD
=======
=======
            return bad_request('Username or email required')
            
        # Persistent rate limit check (3 requests per 10 minutes)
        request_count = _db.get_otp_request_count(identifier, 600)
        if request_count >= 3:
            return rate_limited("Too many requests. Try again later.")
            
        _db.log_otp_request(identifier)
>>>>>>> 4c5ae8566bbeb2af6ffddd6da0dc25f97d5a40fa
>>>>>>> 29c1406ff0d33cca29bb3c738f3c070c695be578
        
        # دور بالـ username أو الـ email
        user = user_manager.get_user(identifier)
        if not user:
            all_users = user_manager.get_all_users()
            user = next((u for u in all_users if u.get('email','').lower() == identifier.lower()), None)
        if not user:
<<<<<<< HEAD
=======
<<<<<<< HEAD
>>>>>>> 29c1406ff0d33cca29bb3c738f3c070c695be578
            return jsonify({"message": "If that email is registered, a reset link was sent."}), 200
        user_id = user.get('user_id') or user.get('id')
        email   = user.get('email')
        if not email:
            return jsonify({"message": "If that email is registered, a reset link was sent."}), 200
<<<<<<< HEAD
=======
=======
            return ok(message="If that email is registered, a reset link was sent.")
        user_id = user.get('user_id') or user.get('id')
        email   = user.get('email')
        if not email:
            return ok(message="If that email is registered, a reset link was sent.")
>>>>>>> 4c5ae8566bbeb2af6ffddd6da0dc25f97d5a40fa
>>>>>>> 29c1406ff0d33cca29bb3c738f3c070c695be578
        otp = str(secrets.randbelow(900000) + 100000) 
        import hashlib
        otp_hash = hashlib.sha256(otp.encode()).hexdigest()
        expiry = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time() + 300))
        with _db.db_cursor() as cur:
            cur.execute('DELETE FROM password_resets WHERE user_id = ?', (user_id,))
            cur.execute('INSERT INTO password_resets (user_id, otp, otp_expiry, used) VALUES (?,?,?,0)',
                        (user_id, otp_hash, expiry))
        try:
            # Simple OTP email sender using smtplib
            def send_otp_email(to_email, otp):
                subject = "Your Password Reset OTP"
                body = f"Your OTP for password reset is: {otp}\nThis code will expire in 5 minutes."
                msg = MIMEText(body)
                msg['Subject'] = subject
                msg['From'] = SMTP_EMAIL
                msg['To'] = to_email

                with smtplib.SMTP_SSL('smtp.gmail.com', 465) as server:
                    server.login(SMTP_EMAIL, SMTP_PASSWORD)
                    server.sendmail(SMTP_EMAIL, [to_email], msg.as_string())

            send_otp_email(email, otp)
        except Exception as e:
            logger.error(f"OTP email failed: {e}")
<<<<<<< HEAD
=======
<<<<<<< HEAD
>>>>>>> 29c1406ff0d33cca29bb3c738f3c070c695be578
            return jsonify({'error': 'Failed to deliver OTP'}), 500

        return jsonify({
            'message': 'OTP sent to registered email'
        }), 200
<<<<<<< HEAD
=======
=======
            return server_error('Failed to deliver OTP')

        return ok(message='OTP sent to registered email')
>>>>>>> 4c5ae8566bbeb2af6ffddd6da0dc25f97d5a40fa
>>>>>>> 29c1406ff0d33cca29bb3c738f3c070c695be578

    @app.route('/api/verify-reset-otp', methods=['POST'])
    def verify_reset_otp():
        data     = request.get_json(silent=True) or {}
        user_id  = data.get('user_id')
        otp      = data.get('otp', '').strip()
        new_pass = data.get('new_password', '').strip()
        if not user_id or not otp or not new_pass:
<<<<<<< HEAD
=======
<<<<<<< HEAD
>>>>>>> 29c1406ff0d33cca29bb3c738f3c070c695be578
            return jsonify({'error': 'user_id, otp and new_password required'}), 400
            
        with _db.db_cursor() as cur:
            try:
                cur.execute('ALTER TABLE password_resets ADD COLUMN otp_attempts INTEGER DEFAULT 0')
            except Exception:
                pass
            
<<<<<<< HEAD
=======
=======
            return bad_request('user_id, otp and new_password required')
            
        with _db.db_cursor() as cur:
>>>>>>> 4c5ae8566bbeb2af6ffddd6da0dc25f97d5a40fa
>>>>>>> 29c1406ff0d33cca29bb3c738f3c070c695be578
            cur.execute('SELECT * FROM password_resets WHERE user_id = ? AND used = 0', (user_id,))
            record = cur.fetchone()
            
        if not record:
<<<<<<< HEAD
=======
<<<<<<< HEAD
>>>>>>> 29c1406ff0d33cca29bb3c738f3c070c695be578
            return jsonify({'error': 'No OTP requested for this user'}), 400
            
        if record.get('otp_attempts', 0) >= 5:
            return jsonify({'error': 'Too many attempts. Request a new OTP.'}), 429
<<<<<<< HEAD
=======
=======
            return bad_request('No OTP requested for this user')
            
        if record.get('otp_attempts', 0) >= 5:
            return rate_limited('Too many attempts. Request a new OTP.')
>>>>>>> 4c5ae8566bbeb2af6ffddd6da0dc25f97d5a40fa
>>>>>>> 29c1406ff0d33cca29bb3c738f3c070c695be578
            
        import hashlib
        incoming_hash = hashlib.sha256(str(otp).encode()).hexdigest()
        if not hmac.compare_digest(record['otp'], incoming_hash):
            with _db.db_cursor() as cur:
                cur.execute('UPDATE password_resets SET otp_attempts = COALESCE(otp_attempts, 0) + 1 WHERE user_id = ?', (user_id,))
<<<<<<< HEAD
            return jsonify({'error': 'Invalid OTP'}), 400
=======
<<<<<<< HEAD
            return jsonify({'error': 'Invalid OTP'}), 400
=======
            return bad_request('Invalid OTP')
>>>>>>> 4c5ae8566bbeb2af6ffddd6da0dc25f97d5a40fa
>>>>>>> 29c1406ff0d33cca29bb3c738f3c070c695be578
            
        if time.strftime('%Y-%m-%d %H:%M:%S') > record['otp_expiry']:
            with _db.db_cursor() as cur:
                cur.execute('UPDATE password_resets SET otp_attempts = 0 WHERE user_id = ?', (user_id,))
<<<<<<< HEAD
=======
<<<<<<< HEAD
>>>>>>> 29c1406ff0d33cca29bb3c738f3c070c695be578
            return jsonify({'error': 'OTP expired'}), 400
            
        user = _db.get_user_by_id(user_id)
        if not user:
            return jsonify({'error': 'User not found'}), 404
        ok, msg = user_manager.change_password(user['username'], new_pass)
        if not ok:
            return jsonify({'error': msg}), 400
        with _db.db_cursor() as cur:
            cur.execute('UPDATE password_resets SET used = 1, otp_attempts = 0 WHERE user_id = ?', (user_id,))
        return jsonify({'message': 'Password reset successfully'}), 200
<<<<<<< HEAD
=======
=======
            return bad_request('OTP expired')
            
        user = _db.get_user_by_id(user_id)
        if not user:
            return not_found('User not found')
        ok_change, msg = user_manager.change_password(user['username'], new_pass)
        if not ok_change:
            return bad_request(msg)
        with _db.db_cursor() as cur:
            cur.execute('UPDATE password_resets SET used = 1, otp_attempts = 0 WHERE user_id = ?', (user_id,))
        return ok(message='Password reset successfully')
>>>>>>> 4c5ae8566bbeb2af6ffddd6da0dc25f97d5a40fa
>>>>>>> 29c1406ff0d33cca29bb3c738f3c070c695be578

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
<<<<<<< HEAD
        return jsonify({
=======
<<<<<<< HEAD
        return jsonify({
=======
        return ok(data={
>>>>>>> 4c5ae8566bbeb2af6ffddd6da0dc25f97d5a40fa
>>>>>>> 29c1406ff0d33cca29bb3c738f3c070c695be578
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
<<<<<<< HEAD
        return jsonify(data)
=======
<<<<<<< HEAD
        return jsonify(data)
=======
        return ok(data=data)
>>>>>>> 4c5ae8566bbeb2af6ffddd6da0dc25f97d5a40fa
>>>>>>> 29c1406ff0d33cca29bb3c738f3c070c695be578
    from app import config as _cfg
    INTERNAL_SECRET = _cfg.internal_secret()
    if not INTERNAL_SECRET:
        import logging as _log
        _log.getLogger(__name__).error('[CONFIG] INTERNAL_API_SECRET not set')

    def require_internal_secret(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if not INTERNAL_SECRET:
<<<<<<< HEAD
=======
<<<<<<< HEAD
>>>>>>> 29c1406ff0d33cca29bb3c738f3c070c695be578
                return jsonify({'error': 'Internal auth not configured'}), 503
            token = request.headers.get('X-Internal-Token', '')
            if not secrets.compare_digest(token, INTERNAL_SECRET):
                return jsonify({'error': 'Forbidden'}), 403
<<<<<<< HEAD
=======
=======
                return server_error('Internal auth not configured')
            token = request.headers.get('X-Internal-Token', '')
            if not secrets.compare_digest(token, INTERNAL_SECRET):
                return forbidden('Forbidden')
>>>>>>> 4c5ae8566bbeb2af6ffddd6da0dc25f97d5a40fa
>>>>>>> 29c1406ff0d33cca29bb3c738f3c070c695be578
            return f(*args, **kwargs)
        return decorated
    @app.route('/api/dashboard/threat', methods=['POST'])
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
<<<<<<< HEAD
        return jsonify({'status': 'logged'})
=======
<<<<<<< HEAD
        return jsonify({'status': 'logged'})
=======
        return ok(message='logged')
>>>>>>> 4c5ae8566bbeb2af6ffddd6da0dc25f97d5a40fa
>>>>>>> 29c1406ff0d33cca29bb3c738f3c070c695be578
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
<<<<<<< HEAD
        return jsonify({'status': 'updated'})
=======
<<<<<<< HEAD
        return jsonify({'status': 'updated'})
=======
        return ok(message='updated')
>>>>>>> 4c5ae8566bbeb2af6ffddd6da0dc25f97d5a40fa
>>>>>>> 29c1406ff0d33cca29bb3c738f3c070c695be578
    @app.route('/api/dashboard/reset', methods=['POST'])
    @admin_required
    def reset_stats(current_user):
        global dashboard
        try:
            log_action(current_user, "Reset Stats", "Cleared all memory stats and audit logs")
            # Reset in-memory stats
            for key in dashboard.stats:
                dashboard.stats[key] = 0
            dashboard.ip_tracker.clear()
            dashboard.recent_threats = []
            dashboard.timeline_data.clear()
            dashboard.incidents.clear()
            # Clear the DB threat logs
            from app import database as _db
            _db.clear_threat_logs()
            # Clear the JSON audit log
            try:
                with open(dashboard.audit_log_path, 'w') as f:
                    json.dump([], f)
            except Exception as e:
                print(f"[-] Error clearing audit log: {e}")
<<<<<<< HEAD
=======
<<<<<<< HEAD
>>>>>>> 29c1406ff0d33cca29bb3c738f3c070c695be578
            return jsonify({'status': 'stats_reset', 'message': 'All stats and logs cleared'})
        except Exception as e:
            print(f"[-] Reset error: {e}")
            return jsonify({'status': 'error', 'message': str(e)}), 500
<<<<<<< HEAD
=======
=======
            return ok(data={'status': 'stats_reset'}, message='All stats and logs cleared')
        except Exception as e:
            print(f"[-] Reset error: {e}")
            return server_error(str(e))
>>>>>>> 4c5ae8566bbeb2af6ffddd6da0dc25f97d5a40fa
>>>>>>> 29c1406ff0d33cca29bb3c738f3c070c695be578

    @app.route('/api/user')
    @token_required
    def get_current_user(current_user):
        """Return current user information for permission checks"""
<<<<<<< HEAD
        return jsonify({
=======
<<<<<<< HEAD
        return jsonify({
=======
        return ok(data={
>>>>>>> 4c5ae8566bbeb2af6ffddd6da0dc25f97d5a40fa
>>>>>>> 29c1406ff0d33cca29bb3c738f3c070c695be578
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
<<<<<<< HEAD
=======
<<<<<<< HEAD
>>>>>>> 29c1406ff0d33cca29bb3c738f3c070c695be578
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
<<<<<<< HEAD
=======
=======
            return ok(data=stats)
        except FileNotFoundError as e:
            # can't load model/vectorizer but we still want indicator values returned
            indicators = dashboard.compute_attack_indicators()
            return ok(data={
                "status": "error",
                "message": f"Model file not found: {e}",
                "attack_indicators": indicators
            })
        except Exception as e:
            # on any other failure, return error flag but still include indicators
            indicators = dashboard.compute_attack_indicators()
            return ok(data={
                "status": "error",
                "message": str(e),
                "attack_indicators": indicators
            })
>>>>>>> 4c5ae8566bbeb2af6ffddd6da0dc25f97d5a40fa
>>>>>>> 29c1406ff0d33cca29bb3c738f3c070c695be578
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
<<<<<<< HEAD
        return jsonify(incidents_data)
=======
<<<<<<< HEAD
        return jsonify(incidents_data)
=======
        return paginated(incidents_data)
>>>>>>> 4c5ae8566bbeb2af6ffddd6da0dc25f97d5a40fa
>>>>>>> 29c1406ff0d33cca29bb3c738f3c070c695be578
    @app.route('/api/incident/<id>')
    @admin_required
    def get_incident_details(current_user, id):
        global dashboard
        if id not in dashboard.incidents:
<<<<<<< HEAD
            return jsonify({'error': 'Not found'}), 404
        return jsonify(dashboard.incidents[id].__dict__)
=======
<<<<<<< HEAD
            return jsonify({'error': 'Not found'}), 404
        return jsonify(dashboard.incidents[id].__dict__)
=======
            return not_found('Incident not found')
        return ok(data=dashboard.incidents[id].__dict__)
>>>>>>> 4c5ae8566bbeb2af6ffddd6da0dc25f97d5a40fa
>>>>>>> 29c1406ff0d33cca29bb3c738f3c070c695be578
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
<<<<<<< HEAD
        return jsonify({'status': 'success' if success else 'error', 'message': message})
=======
<<<<<<< HEAD
        return jsonify({'status': 'success' if success else 'error', 'message': message})
=======
        return ok(data={'status': 'success' if success else 'error'}, message=message)
>>>>>>> 4c5ae8566bbeb2af6ffddd6da0dc25f97d5a40fa
>>>>>>> 29c1406ff0d33cca29bb3c738f3c070c695be578
    @app.route('/api/incident/<id>/export')
    @admin_required
    def export_incident(current_user, id):
        global dashboard
        if id not in dashboard.incidents:
<<<<<<< HEAD
            return jsonify({'error': 'Not found'}), 404
        return jsonify(dashboard.incidents[id].__dict__)
=======
<<<<<<< HEAD
            return jsonify({'error': 'Not found'}), 404
        return jsonify(dashboard.incidents[id].__dict__)
=======
            return not_found('Incident not found')
        return ok(data=dashboard.incidents[id].__dict__)
>>>>>>> 4c5ae8566bbeb2af6ffddd6da0dc25f97d5a40fa
>>>>>>> 29c1406ff0d33cca29bb3c738f3c070c695be578
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
<<<<<<< HEAD
        return jsonify(dist)
=======
<<<<<<< HEAD
        return jsonify(dist)
=======
        return ok(data=dist)
>>>>>>> 4c5ae8566bbeb2af6ffddd6da0dc25f97d5a40fa
>>>>>>> 29c1406ff0d33cca29bb3c738f3c070c695be578
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
<<<<<<< HEAD
=======
<<<<<<< HEAD
>>>>>>> 29c1406ff0d33cca29bb3c738f3c070c695be578
            return jsonify({'success': False, 'message': 'Invalid plan'}), 400
        
        success, message = user_manager.update_user(current_user['username'], subscription=new_plan)
        return jsonify({'success': success, 'message': message})
<<<<<<< HEAD
=======
=======
            return bad_request('Invalid plan')
        
        success, message = user_manager.update_user(current_user['username'], subscription=new_plan)
        return ok(message=message) if success else bad_request(message)
>>>>>>> 4c5ae8566bbeb2af6ffddd6da0dc25f97d5a40fa
>>>>>>> 29c1406ff0d33cca29bb3c738f3c070c695be578


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
<<<<<<< HEAD
        return jsonify({
            'status': 'success',
=======
<<<<<<< HEAD
        return jsonify({
            'status': 'success',
=======
        return ok(data={
>>>>>>> 4c5ae8566bbeb2af6ffddd6da0dc25f97d5a40fa
>>>>>>> 29c1406ff0d33cca29bb3c738f3c070c695be578
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
<<<<<<< HEAD
        return jsonify({
            'status': 'success',
=======
<<<<<<< HEAD
        return jsonify({
            'status': 'success',
=======
        return ok(data={
>>>>>>> 4c5ae8566bbeb2af6ffddd6da0dc25f97d5a40fa
>>>>>>> 29c1406ff0d33cca29bb3c738f3c070c695be578
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
<<<<<<< HEAD
        return jsonify({
            'status': 'success',
=======
<<<<<<< HEAD
        return jsonify({
            'status': 'success',
=======
        return ok(data={
>>>>>>> 4c5ae8566bbeb2af6ffddd6da0dc25f97d5a40fa
>>>>>>> 29c1406ff0d33cca29bb3c738f3c070c695be578
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
<<<<<<< HEAD
            return jsonify({'status': 'error', 'message': 'No data provided'}), 400
=======
<<<<<<< HEAD
            return jsonify({'status': 'error', 'message': 'No data provided'}), 400
=======
            return bad_request('No data provided')
>>>>>>> 4c5ae8566bbeb2af6ffddd6da0dc25f97d5a40fa
>>>>>>> 29c1406ff0d33cca29bb3c738f3c070c695be578
        
        username = current_user.get('username')
        
        # Update user data
        # Whitelist only safe profile fields — never accept role/status from user
        ALLOWED_PROFILE_FIELDS = {'full_name', 'email', 'department', 'phone'}
        update_data = {k: v for k, v in data.items() if k in ALLOWED_PROFILE_FIELDS}

        if 'password' in data and data['password']:
            is_valid_password, password_message = user_manager.validate_password_policy(data['password'])
            if not is_valid_password:
<<<<<<< HEAD
                return jsonify({'status': 'error', 'message': password_message}), 400
=======
<<<<<<< HEAD
                return jsonify({'status': 'error', 'message': password_message}), 400
=======
                return bad_request(password_message)
>>>>>>> 4c5ae8566bbeb2af6ffddd6da0dc25f97d5a40fa
>>>>>>> 29c1406ff0d33cca29bb3c738f3c070c695be578
            update_data['password'] = data['password']
        
        # Update user in user manager
        success, message = user_manager.update_user(username, **update_data)
        
        if success:
            log_action(current_user, "Profile Updated", f"Updated profile information: {', '.join(update_data.keys())}")
<<<<<<< HEAD
            return jsonify({'status': 'success', 'message': 'Profile updated successfully'})
        else:
            return jsonify({'status': 'error', 'message': message or 'Failed to update profile'}), 400
=======
<<<<<<< HEAD
            return jsonify({'status': 'success', 'message': 'Profile updated successfully'})
        else:
            return jsonify({'status': 'error', 'message': message or 'Failed to update profile'}), 400
=======
            return ok(message='Profile updated successfully')
        else:
            return bad_request(message or 'Failed to update profile')
>>>>>>> 4c5ae8566bbeb2af6ffddd6da0dc25f97d5a40fa
>>>>>>> 29c1406ff0d33cca29bb3c738f3c070c695be578
    @app.route('/api/profile/change-password', methods=['POST'])
    @token_required
    def change_password_profile(current_user):
        """Change user password"""
        data = request.get_json() or {}
        current_password = data.get('current_password')
        new_password = data.get('new_password')
        username = current_user.get('username')

        if not current_password or not new_password:
<<<<<<< HEAD
=======
<<<<<<< HEAD
>>>>>>> 29c1406ff0d33cca29bb3c738f3c070c695be578
            return jsonify({'status': 'error', 'message': 'Current and new password are required'}), 400

        if not user_manager.verify_password(username, current_password):
            return jsonify({'status': 'error', 'message': 'Current password is incorrect'}), 400

        success, message = user_manager.change_password(username, new_password)
        if not success:
            return jsonify({'status': 'error', 'message': message}), 400

        log_action(current_user, "Password Changed", "User changed their password")
        return jsonify({'status': 'success', 'message': message})
<<<<<<< HEAD
=======
=======
            return bad_request('Current and new password are required')

        if not user_manager.verify_password(username, current_password):
            return bad_request('Current password is incorrect')

        success, message = user_manager.change_password(username, new_password)
        if not success:
            return bad_request(message)

        log_action(current_user, "Password Changed", "User changed their password")
        return ok(message=message)
>>>>>>> 4c5ae8566bbeb2af6ffddd6da0dc25f97d5a40fa
>>>>>>> 29c1406ff0d33cca29bb3c738f3c070c695be578
    @app.route('/api/profile/logout-session', methods=['POST'])
    @token_required
    def logout_session(current_user):
        """Logout a specific session"""
        session_id = request.get_json().get('session_id')
        log_action(current_user, "Session Revoked", f"Revoked session: {session_id}")
<<<<<<< HEAD
        return jsonify({'status': 'success', 'message': 'Session revoked successfully'})
=======
<<<<<<< HEAD
        return jsonify({'status': 'success', 'message': 'Session revoked successfully'})
=======
        return ok(message='Session revoked successfully')
>>>>>>> 4c5ae8566bbeb2af6ffddd6da0dc25f97d5a40fa
>>>>>>> 29c1406ff0d33cca29bb3c738f3c070c695be578

    @app.route('/api/profile/avatar', methods=['POST'])
    @token_required
    def upload_avatar(current_user):
<<<<<<< HEAD
=======
<<<<<<< HEAD
>>>>>>> 29c1406ff0d33cca29bb3c738f3c070c695be578
        import imghdr
        ALLOWED_EXTS  = {'.png', '.jpg', '.jpeg', '.gif', '.bmp'}
        ALLOWED_MAGIC = {'png', 'jpeg', 'gif', 'bmp'}

        file = request.files.get('avatar')
        if not file or file.filename == '':
            return jsonify({'error': 'No file'}), 400

        filename = secure_filename(file.filename)
        ext = os.path.splitext(filename)[1].lower()
        if ext not in ALLOWED_EXTS:
            return jsonify({'error': 'Invalid file type'}), 400

        header = file.read(512); file.seek(0)
        if imghdr.what(None, h=header) not in ALLOWED_MAGIC:
            return jsonify({'error': 'Invalid image content'}), 400

        upload_dir = Path(current_app.root_path) / 'static' / 'uploads' / 'avatars'
        upload_dir.mkdir(parents=True, exist_ok=True)
        new_filename = f"{current_user['username']}_{int(time.time())}{ext}"
        file.save(str(upload_dir / new_filename))
        avatar_url = url_for('static', filename=f'uploads/avatars/{new_filename}')
        user_manager.update_user(current_user.get('username'), avatar_url=avatar_url)
        log_action(current_user, "Avatar Upload", "User uploaded a new profile picture")
                
        return jsonify({'status': 'success', 'avatar_url': avatar_url})
<<<<<<< HEAD
=======
=======
        import magic
        ALLOWED_MIME = {'image/png', 'image/jpeg', 'image/gif', 'image/webp'}
        MAX_SIZE = 512 * 1024  # 512 KB

        file = request.files.get('avatar')
        if not file or file.filename == '':
            return bad_request('No file')

        # Enforce file size limit
        file.seek(0, os.SEEK_END)
        size = file.tell()
        file.seek(0)
        if size > MAX_SIZE:
            return bad_request('File too large (max 512KB)')

        filename = secure_filename(file.filename)
        ext = os.path.splitext(filename)[1].lower()
        if ext not in {'.png', '.jpg', '.jpeg', '.gif', '.webp'}:
            return bad_request('Invalid file extension')

        # Replace deprecated imghdr with python-magic
        header = file.read(2048)
        file.seek(0)
        mime = magic.from_buffer(header, mime=True)
        if mime not in ALLOWED_MIME:
            return bad_request(f'Invalid image type: {mime}')

        # Save to private directory outside web root
        upload_dir = Path(current_app.root_path).parent / 'private_uploads' / 'avatars'
        upload_dir.mkdir(parents=True, exist_ok=True)
        
        new_filename = f"{current_user['username']}_{int(time.time())}{ext}"
        file.save(str(upload_dir / new_filename))
        
        # New authenticated URL
        avatar_url = f"/api/avatar/{new_filename}"
        user_manager.update_user(current_user.get('username'), avatar_url=avatar_url)
        log_action(current_user, "Avatar Upload", f"User uploaded a new profile picture: {new_filename}")
                
        return ok(data={'avatar_url': avatar_url})

    @app.route('/api/avatar/<filename>')
    @token_required
    def serve_avatar(current_user, filename):
        """Serve avatar from private storage with authentication."""
        # Optional: Security check to ensure the user can only see their own or authorized avatars
        # For simplicity in this SIEM, we'll allow seeing any authenticated avatar if needed,
        # but the prompt suggested restricting to the user's specific filename.
        # Let's check if the filename starts with the user's username OR is the one in their profile.
        
        # But wait, in a dashboard, admins might need to see others' avatars.
        # For now, let's stick to the prompt's recommendation for strictness:
        # "Ensures users can only access their own files"
        if not filename.startswith(current_user['username'] + '_') and current_user.get('role') != 'admin':
            return forbidden('Forbidden')

        upload_dir = Path(current_app.root_path).parent / 'private_uploads' / 'avatars'
        if not (upload_dir / filename).exists():
             return not_found('File not found')

        return send_from_directory(str(upload_dir), filename)

>>>>>>> 4c5ae8566bbeb2af6ffddd6da0dc25f97d5a40fa
>>>>>>> 29c1406ff0d33cca29bb3c738f3c070c695be578

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
<<<<<<< HEAD
        return jsonify(settings)
=======
<<<<<<< HEAD
        return jsonify(settings)
=======
        return ok(data=settings)
>>>>>>> 4c5ae8566bbeb2af6ffddd6da0dc25f97d5a40fa
>>>>>>> 29c1406ff0d33cca29bb3c738f3c070c695be578
    
    @app.route('/api/settings', methods=['POST'])
    @admin_required
    def update_settings(current_user):
        """Update system settings (Admin only)"""
        data = request.get_json()
        # Here you would save settings to database or config file
        log_action(current_user, "Settings Updated", f"Updated system settings")
<<<<<<< HEAD
        return jsonify({'status': 'success', 'message': 'Settings updated successfully'})
=======
<<<<<<< HEAD
        return jsonify({'status': 'success', 'message': 'Settings updated successfully'})
=======
        return ok(message='Settings updated successfully')
>>>>>>> 4c5ae8566bbeb2af6ffddd6da0dc25f97d5a40fa
>>>>>>> 29c1406ff0d33cca29bb3c738f3c070c695be578

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
        
<<<<<<< HEAD
        return jsonify({'users': users_with_activity})
=======
<<<<<<< HEAD
        return jsonify({'users': users_with_activity})
=======
        return ok(data={'users': users_with_activity})
>>>>>>> 4c5ae8566bbeb2af6ffddd6da0dc25f97d5a40fa
>>>>>>> 29c1406ff0d33cca29bb3c738f3c070c695be578
    
    @app.route('/api/users/<user_id>', methods=['GET'])
    @admin_required
    def get_user_details(current_user, user_id):
        """Get detailed information about a specific user"""
        user = user_manager.get_user_by_id(user_id)
        if not user:
<<<<<<< HEAD
            return jsonify({'error': 'User not found'}), 404
=======
<<<<<<< HEAD
            return jsonify({'error': 'User not found'}), 404
=======
            return not_found('User not found')
>>>>>>> 4c5ae8566bbeb2af6ffddd6da0dc25f97d5a40fa
>>>>>>> 29c1406ff0d33cca29bb3c738f3c070c695be578
        
        # Get all actions by this user
        audit_logs = dashboard.load_audit_log()
        user_actions = [log for log in audit_logs if log.get('username') == user.get('username')]
        
<<<<<<< HEAD
        return jsonify({
=======
<<<<<<< HEAD
        return jsonify({
=======
        return ok(data={
>>>>>>> 4c5ae8566bbeb2af6ffddd6da0dc25f97d5a40fa
>>>>>>> 29c1406ff0d33cca29bb3c738f3c070c695be578
            'user': user,
            'actions': user_actions[-50:]  # Last 50 actions
        })
    
    @app.route('/api/users/<user_id>/toggle-status', methods=['POST'])
    @admin_required
    def toggle_user_status(current_user, user_id):
        """Activate or deactivate a user"""
        user = user_manager.get_user_by_id(user_id)
        if not user:
<<<<<<< HEAD
            return jsonify({'error': 'User not found'}), 404
=======
<<<<<<< HEAD
            return jsonify({'error': 'User not found'}), 404
=======
            return not_found('User not found')
>>>>>>> 4c5ae8566bbeb2af6ffddd6da0dc25f97d5a40fa
>>>>>>> 29c1406ff0d33cca29bb3c738f3c070c695be578
        
        new_status = 'inactive' if user.get('status') == 'active' else 'active'
        # Update user status in database
        user_manager.update_user(user.get('username'), status=new_status)
        log_action(current_user, "User Status Changed", f"Changed {user.get('username')} status to {new_status}")
        
<<<<<<< HEAD
        return jsonify({'status': 'success', 'new_status': new_status})
=======
<<<<<<< HEAD
        return jsonify({'status': 'success', 'new_status': new_status})
=======
        return ok(data={'new_status': new_status})
>>>>>>> 4c5ae8566bbeb2af6ffddd6da0dc25f97d5a40fa
>>>>>>> 29c1406ff0d33cca29bb3c738f3c070c695be578
    
    @app.route('/api/users/<user_id>/change-role', methods=['POST'])
    @admin_required
    def change_user_role(current_user, user_id):
        """Change user role"""
        data = request.get_json()
        new_role = data.get('role')
        
        valid_roles = ['admin', 'user', 'viewer']
        if not new_role or new_role not in valid_roles:
<<<<<<< HEAD
=======
<<<<<<< HEAD
>>>>>>> 29c1406ff0d33cca29bb3c738f3c070c695be578
            return jsonify({'error': f'Invalid role. Must be one of: {", ".join(valid_roles)}'}), 400
        
        user = user_manager.get_user_by_id(user_id)
        if not user:
            return jsonify({'error': 'User not found'}), 404
<<<<<<< HEAD
=======
=======
            return bad_request(f'Invalid role. Must be one of: {", ".join(valid_roles)}')
        
        user = user_manager.get_user_by_id(user_id)
        if not user:
            return not_found('User not found')
>>>>>>> 4c5ae8566bbeb2af6ffddd6da0dc25f97d5a40fa
>>>>>>> 29c1406ff0d33cca29bb3c738f3c070c695be578
        
        # Update user role
        user_manager.update_user(user.get('username'), role=new_role)
        log_action(current_user, "User Role Changed", f"Changed {user.get('username')} role to {new_role}")
        
<<<<<<< HEAD
        return jsonify({'status': 'success', 'new_role': new_role})
=======
<<<<<<< HEAD
        return jsonify({'status': 'success', 'new_role': new_role})
=======
        return ok(data={'new_role': new_role})
>>>>>>> 4c5ae8566bbeb2af6ffddd6da0dc25f97d5a40fa
>>>>>>> 29c1406ff0d33cca29bb3c738f3c070c695be578
    
    @app.route('/api/users/<user_id>', methods=['DELETE'])
    @admin_required
    def delete_user(current_user, user_id):
        """Delete a user"""
        user = user_manager.get_user_by_id(user_id)
        if not user:
<<<<<<< HEAD
=======
<<<<<<< HEAD
>>>>>>> 29c1406ff0d33cca29bb3c738f3c070c695be578
            return jsonify({'error': 'User not found'}), 404
        
        if user.get('username') == current_user.get('username'):
            return jsonify({'error': 'Cannot delete your own account'}), 400
<<<<<<< HEAD
=======
=======
            return not_found('User not found')
        
        if user.get('username') == current_user.get('username'):
            return bad_request('Cannot delete your own account')
>>>>>>> 4c5ae8566bbeb2af6ffddd6da0dc25f97d5a40fa
>>>>>>> 29c1406ff0d33cca29bb3c738f3c070c695be578
        
        # Delete user
        user_manager.delete_user(user.get('username'))
        log_action(current_user, "User Deleted", f"Deleted user {user.get('username')}")
        
<<<<<<< HEAD
        return jsonify({'status': 'success', 'message': 'User deleted successfully'})
=======
<<<<<<< HEAD
        return jsonify({'status': 'success', 'message': 'User deleted successfully'})
=======
        return ok(message='User deleted successfully')
>>>>>>> 4c5ae8566bbeb2af6ffddd6da0dc25f97d5a40fa
>>>>>>> 29c1406ff0d33cca29bb3c738f3c070c695be578
    
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
<<<<<<< HEAD
                return jsonify({'error': 'Username, email, and password are required'}), 400
=======
<<<<<<< HEAD
                return jsonify({'error': 'Username, email, and password are required'}), 400
=======
                return bad_request('Username, email, and password are required')
>>>>>>> 4c5ae8566bbeb2af6ffddd6da0dc25f97d5a40fa
>>>>>>> 29c1406ff0d33cca29bb3c738f3c070c695be578
            
            # Check if user already exists
            existing_user = user_manager.get_user(username)
            if existing_user:
<<<<<<< HEAD
                return jsonify({'error': 'Username already exists'}), 400
=======
<<<<<<< HEAD
                return jsonify({'error': 'Username already exists'}), 400
=======
                return bad_request('Username already exists')
>>>>>>> 4c5ae8566bbeb2af6ffddd6da0dc25f97d5a40fa
>>>>>>> 29c1406ff0d33cca29bb3c738f3c070c695be578
            
            # Create new user
            new_user = user_manager.create_user(
                username=username,
                password=password,
                email=email,
                role=role
            )
            
            log_action(current_user, "User Created", f"Created new user: {username} with role: {role}")
            
<<<<<<< HEAD
=======
<<<<<<< HEAD
>>>>>>> 29c1406ff0d33cca29bb3c738f3c070c695be578
            return jsonify({
                'status': 'success',
                'message': 'User created successfully',
                'user': new_user
            })
        except Exception as e:
            print(f"Error creating user: {e}")
            return jsonify({'error': str(e)}), 500
<<<<<<< HEAD
=======
=======
            return created(data={'user': new_user}, message='User created successfully')
        except Exception as e:
            print(f"Error creating user: {e}")
            return server_error(str(e))
>>>>>>> 4c5ae8566bbeb2af6ffddd6da0dc25f97d5a40fa
>>>>>>> 29c1406ff0d33cca29bb3c738f3c070c695be578

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
<<<<<<< HEAD
        return jsonify({
=======
<<<<<<< HEAD
        return jsonify({
=======
        return ok(data={
>>>>>>> 4c5ae8566bbeb2af6ffddd6da0dc25f97d5a40fa
>>>>>>> 29c1406ff0d33cca29bb3c738f3c070c695be578
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
<<<<<<< HEAD
=======
<<<<<<< HEAD
>>>>>>> 29c1406ff0d33cca29bb3c738f3c070c695be578
            return jsonify({'error': 'Message required'}), 400
        print(f"[NLP] Chat request from {current_user['username']} ({current_user['role']}): {message}")
        response_text = security_bot.generate_response(message, incident_id, page_context, history, role=current_user['role'])
        return jsonify({
<<<<<<< HEAD
=======
=======
            return bad_request('Message required')
        print(f"[NLP] Chat request from {current_user['username']} ({current_user['role']}): {message}")
        response_text = security_bot.generate_response(message, incident_id, page_context, history, role=current_user['role'])
        return ok(data={
>>>>>>> 4c5ae8566bbeb2af6ffddd6da0dc25f97d5a40fa
>>>>>>> 29c1406ff0d33cca29bb3c738f3c070c695be578
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
            
<<<<<<< HEAD
=======
<<<<<<< HEAD
>>>>>>> 29c1406ff0d33cca29bb3c738f3c070c695be578
            return jsonify({'blacklist': blacklist})
        except Exception as e:
            print(f"Error loading blacklist: {e}")
            return jsonify({'blacklist': []})
<<<<<<< HEAD
=======
=======
            return ok(data={'blacklist': blacklist})
        except Exception as e:
            print(f"Error loading blacklist: {e}")
            return ok(data={'blacklist': []})
>>>>>>> 4c5ae8566bbeb2af6ffddd6da0dc25f97d5a40fa
>>>>>>> 29c1406ff0d33cca29bb3c738f3c070c695be578
    
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
<<<<<<< HEAD
                return jsonify({'error': 'Type, value, and reason are required'}), 400
=======
<<<<<<< HEAD
                return jsonify({'error': 'Type, value, and reason are required'}), 400
=======
                return bad_request('Type, value, and reason are required')
>>>>>>> 4c5ae8566bbeb2af6ffddd6da0dc25f97d5a40fa
>>>>>>> 29c1406ff0d33cca29bb3c738f3c070c695be578
            
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
            
<<<<<<< HEAD
=======
<<<<<<< HEAD
>>>>>>> 29c1406ff0d33cca29bb3c738f3c070c695be578
            return jsonify({'status': 'success', 'message': 'Added to blacklist successfully', 'entry': new_entry})
        except Exception as e:
            print(f"Error adding to blacklist: {e}")
            return jsonify({'error': str(e)}), 500
<<<<<<< HEAD
=======
=======
            return created(data={'entry': new_entry}, message='Added to blacklist successfully')
        except Exception as e:
            print(f"Error adding to blacklist: {e}")
            return server_error(str(e))
>>>>>>> 4c5ae8566bbeb2af6ffddd6da0dc25f97d5a40fa
>>>>>>> 29c1406ff0d33cca29bb3c738f3c070c695be578
    
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
<<<<<<< HEAD
                return jsonify({'error': 'Blacklist not found'}), 404
=======
<<<<<<< HEAD
                return jsonify({'error': 'Blacklist not found'}), 404
=======
                return not_found('Blacklist not found')
>>>>>>> 4c5ae8566bbeb2af6ffddd6da0dc25f97d5a40fa
>>>>>>> 29c1406ff0d33cca29bb3c738f3c070c695be578
            
            with open(blacklist_file, 'r') as f:
                blacklist = json.load(f)
            
            # Find and update entry
            entry = next((item for item in blacklist if item.get('id') == entry_id), None)
            if not entry:
<<<<<<< HEAD
                return jsonify({'error': 'Entry not found'}), 404
=======
<<<<<<< HEAD
                return jsonify({'error': 'Entry not found'}), 404
=======
                return not_found('Entry not found')
>>>>>>> 4c5ae8566bbeb2af6ffddd6da0dc25f97d5a40fa
>>>>>>> 29c1406ff0d33cca29bb3c738f3c070c695be578
            
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
            
<<<<<<< HEAD
=======
<<<<<<< HEAD
>>>>>>> 29c1406ff0d33cca29bb3c738f3c070c695be578
            return jsonify({'status': 'success', 'message': 'Blacklist entry updated successfully'})
        except Exception as e:
            print(f"Error updating blacklist: {e}")
            return jsonify({'error': str(e)}), 500
<<<<<<< HEAD
=======
=======
            return ok(message='Blacklist entry updated successfully')
        except Exception as e:
            print(f"Error updating blacklist: {e}")
            return server_error(str(e))
>>>>>>> 4c5ae8566bbeb2af6ffddd6da0dc25f97d5a40fa
>>>>>>> 29c1406ff0d33cca29bb3c738f3c070c695be578
    
    @app.route('/api/blacklist/<int:entry_id>', methods=['DELETE'])
    @admin_required
    def delete_blacklist(current_user, entry_id):
        """Delete blacklist entry"""
        try:
            # Load existing blacklist
            project_root = Path(__file__).parent.parent.parent
            blacklist_file = project_root / 'data' / 'blacklist.json'
            if not blacklist_file.exists():
<<<<<<< HEAD
                return jsonify({'error': 'Blacklist not found'}), 404
=======
<<<<<<< HEAD
                return jsonify({'error': 'Blacklist not found'}), 404
=======
                return not_found('Blacklist not found')
>>>>>>> 4c5ae8566bbeb2af6ffddd6da0dc25f97d5a40fa
>>>>>>> 29c1406ff0d33cca29bb3c738f3c070c695be578
            
            with open(blacklist_file, 'r') as f:
                blacklist = json.load(f)
            
            # Find and remove entry
            entry = next((item for item in blacklist if item.get('id') == entry_id), None)
            if not entry:
<<<<<<< HEAD
                return jsonify({'error': 'Entry not found'}), 404
=======
<<<<<<< HEAD
                return jsonify({'error': 'Entry not found'}), 404
=======
                return not_found('Entry not found')
>>>>>>> 4c5ae8566bbeb2af6ffddd6da0dc25f97d5a40fa
>>>>>>> 29c1406ff0d33cca29bb3c738f3c070c695be578
            
            blacklist = [item for item in blacklist if item.get('id') != entry_id]
            
            # Save blacklist
            with open(blacklist_file, 'w') as f:
                json.dump(blacklist, f, indent=2)
            
            log_action(current_user, "Blacklist Entry Deleted", f"Deleted {entry.get('type')}: {entry.get('value')}")
            
<<<<<<< HEAD
=======
<<<<<<< HEAD
>>>>>>> 29c1406ff0d33cca29bb3c738f3c070c695be578
            return jsonify({'status': 'success', 'message': 'Blacklist entry deleted successfully'})
        except Exception as e:
            print(f"Error deleting blacklist: {e}")
            return jsonify({'error': str(e)}), 500
<<<<<<< HEAD
=======
=======
            return ok(message='Blacklist entry deleted successfully')
        except Exception as e:
            print(f"Error deleting blacklist: {e}")
            return server_error(str(e))
>>>>>>> 4c5ae8566bbeb2af6ffddd6da0dc25f97d5a40fa
>>>>>>> 29c1406ff0d33cca29bb3c738f3c070c695be578

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
    app.run(host='0.0.0.0', port=8070, debug=_debug, use_reloader=False)