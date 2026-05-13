"""
API Routes - Flask application and route handlers
"""
from datetime import datetime, timedelta
import time
import os
import logging
from collections import defaultdict
from flask import Flask, current_app, make_response, request, jsonify
from flask_cors import CORS

os.environ.setdefault("RATE_LIMIT_WINDOW", "60")
os.environ.setdefault("RATE_LIMIT_MAX", "100")

_total_requests_count = 0

def get_total_requests():
    global _total_requests_count
    return _total_requests_count
from dotenv import load_dotenv
import jwt
import secrets
from app.api.security import SimpleSecurityManager
from app.api import services
from app.auth import user_manager
from app.auth.decorators import admin_required, token_required
from app.security import new_request_id, is_trivial, is_business_relevant
from app import config as _cfg

try:
    from detections import detect_csrf, detect_ssrf
    _CSRF_SSRF_ENABLED = True
except ImportError:
    _CSRF_SSRF_ENABLED = False
    import warnings
    warnings.warn("[VIREX] detections package not found — CSRF/SSRF disabled", stacklevel=1)

load_dotenv()
logger = logging.getLogger(__name__)


TRUSTED_PROXIES = {"127.0.0.1", "10.0.0.1"}   # add your proxy IPs

def _get_real_ip():
    if request.remote_addr in TRUSTED_PROXIES:
        xff = request.headers.get("X-Forwarded-For", "")
        if xff:
            return xff.split(",")[0].strip()
    return request.remote_addr

# Or use Werkzeug's ProxyFix middleware:


def create_api_app():
    from werkzeug.middleware.proxy_fix import ProxyFix
    app = Flask(__name__)
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1)
    app.config['SECRET_KEY'] = os.getenv("SECRET_KEY", "")
    from app import database as db



    # ── Config ────────────────────────────────────────────────
    app.config["MAX_CONTENT_LENGTH"] = int(os.getenv("MAX_CONTENT_LENGTH", str(1 * 1024 * 1024)))

    allowed_origins      = os.getenv("ALLOWED_ORIGINS", "http://127.0.0.1:3000,http://localhost:3000")
    allowed_origins_list = [o.strip() for o in allowed_origins.split(",") if o.strip()]
    CORS(app, resources={r"/api/*": {"origins": allowed_origins_list}})

    security = SimpleSecurityManager()

    # ── Brute force tracker (+ persistent blocked_ips) ────────
    brute_force_tracker = defaultdict(list)
    BRUTE_FORCE_LIMIT      = 5
    BRUTE_FORCE_WINDOW     = 60
    BRUTE_FORCE_BLOCK_TIME = 300

    # Load persisted blocked IPs on startup
    from app.api.persistence import load_blocked_ips, save_blocked_ips
    blocked_ips = load_blocked_ips()

    # ── In-memory IP block cache ──────────────────────────────
    ip_cache = {}
    BLOCK_CACHE_DURATION = 30  # 30 seconds

    def _block_ip(ip):
        ip_cache[ip] = time.time()

    def _is_ip_blocked(ip):
        if ip in ip_cache:
            elapsed = time.time() - ip_cache[ip]
            if elapsed < BLOCK_CACHE_DURATION:
                return True
            del ip_cache[ip]
        return False

    @app.before_request
    def before_request():
        global _total_requests_count
        request.request_id = new_request_id()
        if is_trivial(request):
            return

        client_ip = _get_real_ip()

        # ── Layer 0: In-memory IP block check ──────────────
        if _is_ip_blocked(client_ip):
            return jsonify({"error": "IP blocked"}), 429

        _total_requests_count += 1

        is_business = is_business_relevant(request)

        # Count ALL business-relevant requests (blocked or not)
        if is_business:
            security.total_requests += 1

        # ── Layer 1: Rate Limiting ────────────────────────────
        if not security.check_rate_limit(client_ip):
            security.blocked_requests += 1
            security._persist_stats()
            try:
                from app.api.persistence import append_user_attack
                from app.api.security import calculate_severity, should_block_attack, should_block_attack
                severity = calculate_severity("Rate Limit", endpoint=request.path)
                should_block = should_block_attack("Rate Limit", endpoint=request.path)
                append_user_attack(
                    client_ip, "Rate Limit Exceeded", client_ip,
                    request.path, request.method, severity, blocked=should_block,
                )
            except Exception:
                pass
            _block_ip(client_ip)
            return jsonify({"error": "Rate limit exceeded"}), 429

        # ── Layer 2: Scanner Detection (sensitive paths) ──────
        sensitive_paths = ["/wp-admin", "/phpmyadmin", "/.env",
                           "/etc/passwd", "/.git",
                           "/.svn", "/.htaccess", "/server-status", "/wp-login"]
        normalized_path = request.path.lower()
        if any(normalized_path.startswith(p) for p in sensitive_paths):
            from app.api.security import calculate_severity, should_block_attack
            severity = calculate_severity("Scanner", endpoint=request.path)
            security.blocked_requests += 1
            security._persist_stats()
            try:
                from app.api.persistence import append_user_attack
                append_user_attack(
                    client_ip, "Scanner", client_ip,
                    request.path, request.method, "Low", blocked=False,
                    description=f"Sensitive path probe: {request.path}",
                )
            except Exception:
                pass
            return jsonify({"error": "Not Found"}), 404

        # ── Layer 3: Content Scan (SQLi, XSS, CMDi, Path Traversal + ML) ──
        data_to_scan = {}
        if request.args:
            data_to_scan.update(request.args.to_dict())
        if request.is_json:
            try:
                j = request.get_json(silent=True)
                if j and isinstance(j, dict):
                    data_to_scan.update(j)
            except Exception:
                pass
        if request.form:
            data_to_scan.update(request.form.to_dict())
        if request.files:
            for field, fobj in request.files.items():
                data_to_scan[f"_file_name_{field}"]     = fobj.filename or ""
                data_to_scan[f"_file_mimetype_{field}"] = fobj.content_type or ""

        if data_to_scan:
            safe, msg = security.check_request_security(data_to_scan, client_ip)
            if not safe:
                security.blocked_requests += 1
                security._persist_stats()
                return jsonify({"error": msg}), 400

        # ── Layer 4: SSRF Detection (URL patterns in body/params) ──
        if _CSRF_SSRF_ENABLED and data_to_scan:
            _ssrf_result = detect_ssrf({
                "method": request.method, "path": request.path,
                "headers": dict(request.headers),
                "body": request.get_json(silent=True) or {},
                "query_params": request.args.to_dict(),
                "cookies": request.cookies.to_dict(),
                "ip": client_ip, "user_agent": request.user_agent.string,
            })
            if _ssrf_result["detected"]:
                from app.api.security import calculate_severity, should_block_attack
                severity = calculate_severity("SSRF", endpoint=request.path)
                security.blocked_requests += 1
                security._persist_stats()
                try:
                    from app.api.persistence import append_user_attack
                    should_block = severity in ("Critical", "High")
                    append_user_attack(
                        client_ip, "SSRF", client_ip,
                        request.path, request.method, severity, blocked=should_block,
                        description=f"[SSRF] {_ssrf_result['reason']}",
                    )
                except Exception:
                    pass
                return jsonify({"error": "SSRF attempt blocked",
                                "reason": _ssrf_result["reason"]}), 403
        elif not _CSRF_SSRF_ENABLED and data_to_scan:
            # SSRF Fallback: basic private IP check in request data
            import re
            _ssrf_indicators = False
            _ssrf_reason = ""
            _data_str = str(data_to_scan)
            if re.search(r'(127\.0\.0\.1|localhost|169\.254\.169\.254|192\.168\.|10\.|172\.(1[6-9]|2[0-9]|3[01])\.)', _data_str, re.IGNORECASE):
                _ssrf_indicators = True
                _ssrf_reason = "Private IP address detected in request (fallback)"
            if _ssrf_indicators:
                security.blocked_requests += 1
                security._persist_stats()
                try:
                    from app.api.persistence import append_user_attack
                    from app.api.security import calculate_severity, should_block_attack
                    severity = calculate_severity("SSRF", endpoint=request.path)
                    should_block = severity in ("Critical", "High")
                    append_user_attack(
                        client_ip, "SSRF", client_ip,
                        request.path, request.method, severity, blocked=should_block,
                    )
                except Exception:
                    pass
                return jsonify({"error": "SSRF attempt blocked (fallback)",
                                "reason": _ssrf_reason}), 403

        # ── Layer 5: CSRF Detection ───────────────────────────
        # Check CSRF for all state-changing requests (POST/PUT/DELETE/PATCH)
        # regardless of auth token - CSRF tokens should be present for all
        # state-changing operations to prevent cross-site request forgery.
        # Skip CSRF check for requests with JWT Bearer token (API clients).
        _auth_header = request.headers.get("Authorization", "") or request.headers.get("X-API-Key", "")
        if _CSRF_SSRF_ENABLED and request.method in ("POST", "PUT", "DELETE", "PATCH") and not _auth_header.startswith("Bearer "):
            _csrf_result = detect_csrf({
                "method": request.method, "path": request.path,
                "headers": dict(request.headers),
                "body": request.get_json(silent=True) or {},
                "query_params": request.args.to_dict(),
                "cookies": request.cookies.to_dict(),
                "ip": client_ip, "user_agent": request.user_agent.string,
            })
            if _csrf_result["detected"]:
                from app.api.security import calculate_severity, should_block_attack
                severity = calculate_severity("CSRF", endpoint=request.path)
                security.blocked_requests += 1
                security._persist_stats()
                try:
                    from app.api.persistence import append_user_attack
                    should_block = severity in ("Critical", "High")
                    append_user_attack(
                        client_ip, "CSRF", client_ip,
                        request.path, request.method, severity, blocked=should_block,
                        description=f"[CSRF] {_csrf_result['reason']}",
                    )
                except Exception:
                    pass
                return jsonify({"error": "CSRF validation failed",
                                "reason": _csrf_result["reason"]}), 403

        security._persist_stats()

        # ── Layer 5b: CSRF Fallback (when detections module not available) ──
        if not _CSRF_SSRF_ENABLED and request.method in ("POST", "PUT", "DELETE", "PATCH") and not _auth_header.startswith("Bearer "):
            # Basic CSRF token check as fallback
            token_header = (request.headers.get("X-CSRF-Token", "") or
                           request.headers.get("X-XSRF-TOKEN", "") or
                           request.headers.get("X-CSRFToken", "") or
                           request.headers.get("csrf-token", ""))
            token_cookie = (request.cookies.get("csrftoken", "") or
                          request.cookies.get("XSRF-TOKEN", "") or
                          request.cookies.get("csrf_token", "") or
                          request.cookies.get("_csrf", ""))
            if not token_header and not token_cookie:
                security.blocked_requests += 1
                security._persist_stats()
                try:
                    from app.api.persistence import append_user_attack
                    from app.api.security import calculate_severity, should_block_attack
                    severity = calculate_severity("CSRF", endpoint=request.path)
                    should_block = severity in ("Critical", "High")
                    append_user_attack(
                        client_ip, "CSRF", client_ip,
                        request.path, request.method, severity, blocked=should_block,
                    )
                except Exception:
                    pass
                return jsonify({"error": "CSRF validation failed (fallback)",
                                "reason": "Missing CSRF token"}), 403

    @app.after_request
    def after_request(response):
        response.headers["X-Content-Type-Options"]    = "nosniff"
        response.headers["X-Frame-Options"]           = "DENY"
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        response.headers["Content-Security-Policy"]   = "default-src 'self'"
        response.headers["Referrer-Policy"]           = "strict-origin-when-cross-origin"
        return response

    # ── Basic Routes ──────────────────────────────────────────
    @app.route("/")
    def index():
        return {"status": "running", "message": "API Security System Active",
                "security_level": "high", "version": "2.0.0"}

    @app.route("/health")
    def health():
        return jsonify({"status": "healthy"}), 200

    @app.route("/health/detailed")
    @token_required
    @admin_required
    def health_detailed(current_user):
        return {"status": "healthy", "uptime": time.time() - security.start_time,
                "total_requests": security.total_requests,
                "blocked_requests": security.blocked_requests}

    @app.route("/api/health")
    def api_health():
        return jsonify({"connected": True, "status": "healthy", "timestamp": time.time()})

    @app.route("/api/data", methods=["POST"])
    def api_data():
        return jsonify({"message": "Data accepted", "id": int(time.time()),
                        "processed_at": time.time()}), 201

    # ── Data Routes ───────────────────────────────────────────
    @app.route("/api/users", methods=["GET"])
    @token_required
    @admin_required
    def get_users_route(current_user):
      q = request.args.get("search", "")
      results = services.get_users(q if q else None)
      return jsonify({"users": results})

    @app.route("/api/orders", methods=["GET"])
    @token_required
    def get_orders_route(current_user):
        user_filter = request.args.get("user", "")
        results = services.get_orders(current_user["username"])
        services.log_request("/api/orders", "GET", _get_real_ip(), 200, user_filter)
        return jsonify({"orders": results, "total": len(results)})

    @app.route("/api/products", methods=["GET"])
    @token_required
    def get_products_route(current_user):
        cat = request.args.get("category", "")
        q   = request.args.get("search", "")
        results = services.get_products(cat if cat else None, q if q else None)
        services.log_request("/api/products", "GET", _get_real_ip(), 200, q or cat)
        return jsonify({"products": results, "total": len(results)})

    @app.route("/api/orders", methods=["POST"])
    @token_required
    def create_order_route(current_user):
        data = request.get_json() or {}
        new_order = services.create_order(
        current_user["username"],
        data.get("product"),
        data.get("price")
    )
        return jsonify({"order": new_order}), 201

    @app.route("/api/logs", methods=["GET"])
    @token_required
    @admin_required
    def get_logs_route(current_user):
        logs = services.get_request_logs()
        return jsonify({"logs": logs, "total": len(logs)})

    # ── Auth ──────────────────────────────────────────────────
    @app.route("/api/login", methods=["POST"])
    def login():
        data     = request.get_json() or {}
        username = data.get("username")
        password = data.get("password")
        ip       = _get_real_ip()
        now      = time.time()

        # Check persisted blocked IPs
        if ip in blocked_ips:
            if now < blocked_ips[ip]:
                remaining = int(blocked_ips[ip] - now)
                security.blocked_requests += 1
                return jsonify({"error": f"IP blocked for {remaining} seconds"}), 429
            else:
                del blocked_ips[ip]
                save_blocked_ips(blocked_ips)

        verified_user = user_manager.verify_password(username, password) if username and password else None
        if verified_user:
            brute_force_tracker[ip] = []
            # Mint and return JWT — same as dashboard's login_user()
            jti = secrets.token_hex(16)
            token = jwt.encode({
                "user": username,
                "role": verified_user["role"],
                "exp": datetime.utcnow() + timedelta(hours=8),
                "iat": datetime.utcnow(),
                "jti": jti,
            }, current_app.config["SECRET_KEY"], algorithm="HS256")
            # Register session for revocation support
            try:
                from app.auth.auth import _register_session
                user_id = verified_user.get("user_id") or verified_user.get("id")
                if user_id:
                    _register_session(user_id, jti)
            except Exception:
                pass  # session persistence failure must not block login
            resp = make_response(jsonify({"message": "Login successful"}))
            resp.set_cookie("auth_token", token, httponly=True,
                          secure=_cfg.cookie_secure(), samesite="Lax", max_age=8*3600)
            return resp, 200
        else:
            attempts = [t for t in brute_force_tracker[ip] if now - t < BRUTE_FORCE_WINDOW]
            attempts.append(now)
            brute_force_tracker[ip] = attempts
            security.brute_force_count += 1
            security._persist_stats()

            if len(attempts) >= BRUTE_FORCE_LIMIT:
                try:
                    from app.api.persistence import append_user_attack
                    from app.api.security import calculate_severity, should_block_attack
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
                _block_ip(ip)
                return jsonify({"error": "Too many attempts. Try later."}), 429

            return jsonify({"error": "Invalid credentials"}), 401
    # ── Attack History Endpoints ──────────────────────────────
    @app.route("/api/my-attacks", methods=["GET"])
    @token_required
    def get_my_attacks(current_user):   # ← accept injected user from decorator
      user_key = current_user["username"]  # always from verified token
      
      # If requested all attacks and user is admin
      if request.args.get("user") == "all" and current_user["role"] == "admin":
          from app import database as db
          attacks = db.get_threat_logs(limit=1000)
          # Convert 'created_at' to 'timestamp' and 'attack_type' to 'type' for frontend compatibility
          for a in attacks:
              if 'created_at' in a and 'timestamp' not in a:
                  a['timestamp'] = a['created_at']
              if 'attack_type' in a and 'type' not in a:
                  a['type'] = a['attack_type']
          return jsonify({"user": "all", "attacks": attacks})
          
      attacks = db.get_user_attacks(user_key)
      # Convert 'created_at' to 'timestamp' and 'attack_type' to 'type' for frontend compatibility
      for a in attacks:
          if 'created_at' in a and 'timestamp' not in a:
              a['timestamp'] = a['created_at']
          if 'attack_type' in a and 'type' not in a:
              a['type'] = a['attack_type']
              
      return jsonify({"user": user_key, "attacks": attacks})

    @app.route("/api/clear-attacks", methods=["DELETE"])
    @token_required
    @admin_required
    def clear_attacks(current_user):
        from app.api.persistence import clear_all_attacks, clear_user_attacks
        if request.args.get("all") == "true":
            if current_user["role"] != "admin":
                return jsonify({"error": "Admin only"}), 403
            clear_all_attacks()
            return jsonify({"message": "All cleared"})
        # Always use the identity from the verified token
        clear_user_attacks(current_user["username"])
        return jsonify({"message": "Cleared"})

    # ── Security Stats ────────────────────────────────────────
    @app.route("/api/security/stats", methods=["GET"])
    @token_required
    @admin_required
    def get_security_stats(current_user):
        from app.ml.inference import get_ml_stats
        return jsonify({
            "total_requests":       security.total_requests,
            "blocked_requests":     security.blocked_requests,
            "sql_injection_count":  security.sql_injection_count,
            "xss_count":            security.xss_count,
            "cmd_injection_count":  security.cmd_injection_count,
            "path_traversal_count": security.path_traversal_count,
            "brute_force_count":    security.brute_force_count,
            "rate_limit_hits":      security.rate_limit_hits,
            "ml_detections":        security.ml_detections,
            "ml_monitor_count":     security.ml_monitor_count,
            "uptime":               time.time() - security.start_time,
            "ml_engine":            get_ml_stats(),
        })

    @app.route("/api/security/ml/feedback", methods=["GET"])
    @token_required
    @admin_required
    def get_ml_feedback(current_user):
        from app.api.persistence import get_ml_detections
        data = get_ml_detections(limit=100)
        return jsonify({"feedback": data, "total": len(data)})

    return app
