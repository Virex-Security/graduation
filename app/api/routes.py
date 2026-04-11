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
from dotenv import load_dotenv
import jwt
import secrets
from app.api.security import SimpleSecurityManager
from app.api import services, responses
from app.auth import user_manager
from app.auth.decorators import admin_required, token_required
from app.security import new_request_id, is_trivial, is_business_relevant

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

    @app.before_request
    def before_request():
        from app.services.threat_service import ThreatService
        threat_service = ThreatService()
        
        request.request_id = new_request_id()
        if is_trivial(request):
            return

        client_ip = _get_real_ip()
        
        # 1. Rate Limiting (Service-layer)
        if not threat_service.check_rate_limit(client_ip, request.path):
            return responses.rate_limited("Rate limit exceeded")

        # 2. Scanner & Metadata Detection (Service-layer)
        safe, msg = threat_service.scan_request_context(client_ip, request.path, request.method, request.request_id)
        if not safe:
            return responses.not_found(msg)

        # 3. CSRF & SSRF Validation
        if _CSRF_SSRF_ENABLED and request.method in ("POST", "PUT", "DELETE", "PATCH"):
            _csrf_result = detect_csrf({
                "method": request.method, "path": request.path,
                "headers": dict(request.headers),
                "body": request.get_json(silent=True) or {},
                "query_params": request.args.to_dict(),
                "cookies": request.cookies.to_dict(),
                "ip": client_ip, "user_agent": request.user_agent.string,
            })
            if _csrf_result["detected"]:
                return responses.forbidden("CSRF validation failed", data={"reason": _csrf_result["reason"]})

        if _CSRF_SSRF_ENABLED:
            _ssrf_result = detect_ssrf({
                "method": request.method, "path": request.path,
                "headers": dict(request.headers),
                "body": request.get_json(silent=True) or {},
                "query_params": request.args.to_dict(),
                "cookies": request.cookies.to_dict(),
                "ip": client_ip, "user_agent": request.user_agent.string,
            })
            if _ssrf_result["detected"]:
                return responses.forbidden("SSRF attempt blocked", data={"reason": _ssrf_result["reason"]})

        # 4. Content Security Scan
        data_to_scan = {}
        if request.args: data_to_scan.update(request.args.to_dict())
        if request.is_json:
            try:
                j = request.get_json(silent=True)
                if j and isinstance(j, dict): data_to_scan.update(j)
            except Exception: pass
        if request.form: data_to_scan.update(request.form.to_dict())
        if request.files:
            for field, fobj in request.files.items():
                data_to_scan[f"_file_name_{field}"] = fobj.filename or ""
                data_to_scan[f"_file_mimetype_{field}"] = fobj.content_type or ""

        if data_to_scan:
            safe, msg = threat_service.scan_request_data(data_to_scan, client_ip, request.path, request.method, request.request_id)
            if not safe:
                return responses.bad_request(msg)

        if not request_blocked and is_business:
            security.total_requests += 1
            security._persist_stats()

    @app.after_request
    def after_request(response):
        response.headers["X-Content-Type-Options"]    = "nosniff"
        response.headers["X-Frame-Options"]           = "DENY"
        response.headers["X-XSS-Protection"]          = "1; mode=block"
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        response.headers["Referrer-Policy"]           = "strict-origin-when-cross-origin"
        
        csp = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
            "style-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com https://fonts.googleapis.com; "
            "font-src 'self' https://cdnjs.cloudflare.com https://fonts.gstatic.com; "
            "img-src 'self' data: *; "
            "connect-src 'self';"
        )
        response.headers["Content-Security-Policy"] = csp
        return response


    # ── Basic Routes ──────────────────────────────────────────
    @app.route("/")
    def index():
        return responses.ok({"status": "running", "message": "API Security System Active",
                             "security_level": "high", "version": "2.0.0"})

    @app.route("/health")
    def health():
        return responses.ok({"status": "healthy"})

    @app.route("/health/detailed")
    @token_required
    @admin_required
    def health_detailed(current_user):
        return responses.ok({
            "status": "healthy",
            "total_requests": security.total_requests,
            "blocked_requests": security.blocked_requests
        })

    @app.route("/api/health")
    def api_health():
        return responses.ok({"connected": True, "status": "healthy", "timestamp": time.time()})

    @app.route("/api/data", methods=["POST"])
    def api_data():
        return responses.created({"id": int(time.time()), "processed_at": time.time()})

    # ── Data Routes ───────────────────────────────────────────
    @app.route("/api/users", methods=["GET"])
    @token_required
    @admin_required
    def get_users_route(current_user):
      q = request.args.get("search", "")
      results = services.get_users(q if q else None)
      return responses.ok({"users": results})

    @app.route("/api/orders", methods=["GET"])
    @token_required
    def get_orders_route(current_user):
        user_filter = request.args.get("user", "")
        results = services.get_orders(current_user["username"])
        services.log_request("/api/orders", "GET", _get_real_ip(), 200, user_filter)
        return responses.ok({"orders": results, "total": len(results)})

    @app.route("/api/products", methods=["GET"])
    @token_required
    def get_products_route(current_user):
        cat = request.args.get("category", "")
        q   = request.args.get("search", "")
        results = services.get_products(cat if cat else None, q if q else None)
        services.log_request("/api/products", "GET", _get_real_ip(), 200, q or cat)
        return responses.ok({"products": results, "total": len(results)})

    @app.route("/api/orders", methods=["POST"])
    @token_required
    def create_order_route(current_user):
        data = request.get_json() or {}
        new_order = services.create_order(
        current_user["username"],
        data.get("product"),
        data.get("price")
    )
        return responses.created({"order": new_order})

    @app.route("/api/logs", methods=["GET"])
    @token_required
    @admin_required
    def get_logs_route(current_user):
        logs = services.get_request_logs()
        return responses.ok({"logs": logs, "total": len(logs)})

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
                return responses.rate_limited(f"IP blocked for {remaining} seconds")
            else:
                del blocked_ips[ip]
                save_blocked_ips(blocked_ips)

        verified_user = user_manager.verify_password(username, password) if username and password else None
        if verified_user:
          brute_force_tracker[ip] = []
          # Mint and return JWT — same as dashboard's login_user()
          token = jwt.encode({
              "user": username,
              "role": verified_user["role"],
              "exp": datetime.utcnow() + timedelta(hours=8),
              "iat": datetime.utcnow(),
              "jti": secrets.token_hex(16),   # for revocation
          }, current_app.config["SECRET_KEY"], algorithm="HS256")
          resp = make_response(responses.ok({"message": "Login successful"})[0])
          from app import config as _cfg
          resp.set_cookie("auth_token", token, httponly=True,
                        secure=_cfg.cookie_secure(), samesite="Lax", max_age=8*3600)
          return resp, 200
        else:
              # Brute force tracking
              attempts = [t for t in brute_force_tracker[ip]
              if now - t < BRUTE_FORCE_WINDOW]
              attempts.append(now)
              brute_force_tracker[ip] = attempts
              security.brute_force_count += 1

              if len(attempts) >= BRUTE_FORCE_LIMIT:
                  blocked_ips[ip] = now + BRUTE_FORCE_BLOCK_TIME
                  save_blocked_ips(blocked_ips)
                  return responses.rate_limited("Too many attempts. Try later.")

              return responses.unauthorized("Invalid credentials")
    # ── Attack History Endpoints ──────────────────────────────
    @app.route("/api/my-attacks", methods=["GET"])
    @token_required
    def get_my_attacks(current_user):   # ← accept injected user from decorator
      user_key = current_user["username"]  # always from verified token
      attacks = get_user_attacks(user_key)
      return responses.ok({"user": user_key, "attacks": attacks})

    @app.route("/api/clear-attacks", methods=["DELETE"])
    @token_required
    @admin_required
    def clear_attacks(current_user):
        from app.api.persistence import clear_all_attacks, clear_user_attacks
        if request.args.get("all") == "true":
            if current_user["role"] != "admin":
                return responses.forbidden("Admin only")
            clear_all_attacks()
            return responses.ok({"message": "All cleared"})
        # Always use the identity from the verified token
        clear_user_attacks(current_user["username"])
        return responses.ok({"message": "Cleared"})

    # ── Security Stats ────────────────────────────────────────
    @app.route("/api/security/stats", methods=["GET"])
    @token_required
    @admin_required
    def get_security_stats(current_user):
        from app.ml.inference import get_ml_stats
        return responses.ok({
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
        return responses.ok({"feedback": data, "total": len(data)})

    return app
