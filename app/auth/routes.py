import time
import jwt
import secrets
from datetime import datetime, timedelta
from collections import defaultdict
from flask import Blueprint, request, jsonify, make_response, current_app

from app.auth import user_manager, Role
from app.api.persistence import load_blocked_ips, save_blocked_ips, append_user_attack
from app.api.security import calculate_severity
from app import config as _cfg

auth_bp = Blueprint('auth_bp', __name__)

brute_force_tracker = defaultdict(list)
BRUTE_FORCE_LIMIT = 5
BRUTE_FORCE_WINDOW = 60
BRUTE_FORCE_BLOCK_TIME = 300

def _get_real_ip():
    TRUSTED_PROXIES = {"127.0.0.1", "10.0.0.1"}
    if request.remote_addr in TRUSTED_PROXIES:
        xff = request.headers.get("X-Forwarded-For", "")
        if xff:
            return xff.split(",")[0].strip()
    return request.remote_addr

@auth_bp.route("/api/auth/login", methods=["POST"])
def login():
    data = request.get_json() or {}
    username = data.get("username")
    password = data.get("password")
    
    if not username or not password:
        return jsonify({'message': 'Missing credentials'}), 401

    ip = _get_real_ip()
    now = time.time()
    
    security = getattr(current_app, "security_manager", None)
    blocked_ips = getattr(current_app, "blocked_ips", None)
    if blocked_ips is None:
        blocked_ips = load_blocked_ips()
        current_app.blocked_ips = blocked_ips

    # Check persisted blocked IPs
    if ip in blocked_ips:
        if now < blocked_ips[ip]:
            remaining = int(blocked_ips[ip] - now)
            if security:
                security.blocked_requests += 1
            try:
                request.is_attack = True
            except Exception:
                pass
            return jsonify({"error": f"IP blocked for {remaining} seconds"}), 429
        else:
            del blocked_ips[ip]
            save_blocked_ips(blocked_ips)

    verified_user = user_manager.verify_password(username, password)
    if verified_user:
        brute_force_tracker[ip] = []
        jti = secrets.token_hex(16)
        token = jwt.encode({
            "user": username,
            "role": verified_user.get("role", "user"),
            "exp": datetime.utcnow() + timedelta(hours=8),
            "iat": datetime.utcnow(),
            "jti": jti,
        }, current_app.config["SECRET_KEY"], algorithm="HS256")
        
        try:
            from app.auth.auth import _register_session
            user_id = verified_user.get("user_id") or verified_user.get("id")
            if user_id:
                _register_session(user_id, jti)
        except Exception:
            pass
            
        try:
            from app.database import log_audit
            user_id = verified_user.get("user_id") or verified_user.get("id")
            if user_id:
                log_audit(user_id, "Login", ip)
        except Exception:
            pass

        resp = make_response(jsonify({"message": "Login successful"}))
        resp.set_cookie("auth_token", token, httponly=True,
                      secure=_cfg.cookie_secure(), samesite="Lax", max_age=8*3600)
        return resp, 200
    else:
        try:
            request.is_attack = True
        except Exception:
            pass
        attempts = [t for t in brute_force_tracker[ip] if now - t < BRUTE_FORCE_WINDOW]
        attempts.append(now)
        brute_force_tracker[ip] = attempts
        
        if security:
            security.brute_force_count += 1
            security._persist_stats()

        if len(attempts) >= BRUTE_FORCE_LIMIT:
            try:
                severity = calculate_severity("Brute Force", endpoint=request.path, ip_hit_count=len(attempts))
                should_block = severity in ("Critical", "High")
                append_user_attack(
                    ip, "Brute Force", ip,
                    request.path, request.method, severity, blocked=should_block,
                )
            except Exception:
                pass
            blocked_ips[ip] = now + BRUTE_FORCE_BLOCK_TIME
            save_blocked_ips(blocked_ips)
            return jsonify({"error": "Too many attempts. Try later."}), 429

        return jsonify({"error": "Invalid credentials"}), 401

@auth_bp.route('/api/auth/signup', methods=['POST'])
def signup():
    auth = request.get_json()
    if not auth or not auth.get('username') or not auth.get('password'):
        return jsonify({'message': 'Missing username or password'}), 400
    
    username = auth.get('username').strip()
    password = auth.get('password')
    full_name = auth.get('fullName', '').strip()
    email = auth.get('email', '').strip()
    phone = auth.get('phone', '').strip()
    department = auth.get('department', '').strip()
    
    if len(username) < 3:
        return jsonify({'message': 'Username must be at least 3 characters'}), 400
    if not full_name:
        return jsonify({'message': 'Full name is required'}), 400
    if not email:
        return jsonify({'message': 'Email is required'}), 400
        
    import re
    email_pattern = r'^[^\s@]+@[^\s@]+\.[^\s@]+$'
    if not re.match(email_pattern, email):
        return jsonify({'message': 'Please enter a valid email address'}), 400
        
    if not phone:
        return jsonify({'message': 'Phone number is required'}), 400
    if not department:
        return jsonify({'message': 'Department is required'}), 400
    
    is_valid_password, password_message = user_manager.validate_password_policy(password)
    if not is_valid_password:
        return jsonify({'message': password_message}), 400
        
    if user_manager.get_user(username):
        return jsonify({'message': 'Username already exists'}), 409
        
    success, message = user_manager.add_user(username, password, Role.USER)
    if success:
        user_manager.update_user(username, full_name=full_name, email=email, department=department, phone=phone)
        try:
            from app.database import log_audit
            new_user = user_manager.get_user(username)
            user_id = new_user.get("user_id") or new_user.get("id")
            if user_id:
                ip = _get_real_ip()
                log_audit(user_id, "Account Created", ip)
        except Exception:
            pass
        return jsonify({'message': 'Account created successfully'}), 201
    else:
        return jsonify({'message': message}), 400

@auth_bp.route('/api/auth/logout', methods=['GET', 'POST'])
def logout():
    try:
        from app.database import log_audit
        token = request.cookies.get('auth_token')
        if token:
            data = jwt.decode(token, current_app.config['SECRET_KEY'], algorithms=["HS256"])
            user = user_manager.get_user(data['user'])
            if user:
                user_id = user.get("user_id") or user.get("id")
                ip = _get_real_ip()
                if user_id:
                    log_audit(user_id, "Logout", ip)
    except Exception:
        pass
        
    from app.auth import logout_user
    return logout_user()
