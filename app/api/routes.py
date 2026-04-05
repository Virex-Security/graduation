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
<<<<<<< HEAD
from app.api import services
from app.auth import user_manager
from app.auth.decorators import admin_required, token_required
from app.security import new_request_id, is_trivial, is_business_relevant
=======
from app import database as db, config as virex_config
from app.auth import user_manager
from app.auth.decorators import admin_required, token_required
from app.security import new_request_id, is_trivial, is_business_relevant
from app.api.responses import ok, created, bad_request, unauthorized, forbidden, not_found, rate_limited, paginated
>>>>>>> 4c5ae8566bbeb2af6ffddd6da0dc25f97d5a40fa

try:
    from detections import detect_csrf, detect_ssrf
    _CSRF_SSRF_ENABLED = True
except ImportError:
    _CSRF_SSRF_ENABLED = False
    import warnings
    warnings.warn("[VIREX] detections package not found — CSRF/SSRF disabled", stacklevel=1)

load_dotenv()
logger = logging.getLogger(__name__)


<<<<<<< HEAD
TRUSTED_PROXIES = {"127.0.0.1", "10.0.0.1"}   # add your proxy IPs

def _get_real_ip():
    if request.remote_addr in TRUSTED_PROXIES:
        xff = request.headers.get("X-Forwarded-For", "")
        if xff:
            return xff.split(",")[0].strip()
    return request.remote_addr
=======
def _get_real_ip():
    """
    Securely detects the client's real IP address.
    If the immediate remote_addr is in TRUSTED_PROXIES, we trust the 
    X-Forwarded-For header and parse it FROM RIGHT TO LEFT to find 
    the first non-proxy IP.
    """
    trusted = virex_config.trusted_proxies()
    remote_ip = request.remote_addr

    if remote_ip not in trusted:
        return remote_ip

    xff = request.headers.get("X-Forwarded-For", "")
    if not xff:
        return remote_ip

    # Parse XFF from right to left
    # Spoofing check: header might be "SPOOFED_IP, REAL_CLINET_IP"
    # Proxy appends the IP it sees: "SPOOFED_IP, REAL_CLINET_IP, PROXY_IP"
    ips = [ip.strip() for ip in xff.split(",") if ip.strip()]
    for ip in reversed(ips):
        if ip not in trusted:
            return ip

    return remote_ip

>>>>>>> 4c5ae8566bbeb2af6ffddd6da0dc25f97d5a40fa

# Or use Werkzeug's ProxyFix middleware:


def create_api_app():
<<<<<<< HEAD
    from werkzeug.middleware.proxy_fix import ProxyFix
    app = Flask(__name__)
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1)
    from app import database as db


=======
    app = Flask(__name__)
    
    from flask_wtf.csrf import CSRFProtect
    csrf = CSRFProtect(app)
    
    from werkzeug.middleware.proxy_fix import ProxyFix
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1)
>>>>>>> 4c5ae8566bbeb2af6ffddd6da0dc25f97d5a40fa

    # ── Config ────────────────────────────────────────────────
    app.config["MAX_CONTENT_LENGTH"] = int(os.getenv("MAX_CONTENT_LENGTH", str(1 * 1024 * 1024)))

    allowed_origins      = os.getenv("ALLOWED_ORIGINS", "http://127.0.0.1:3000,http://localhost:3000")
    allowed_origins_list = [o.strip() for o in allowed_origins.split(",") if o.strip()]
    CORS(app, resources={r"/api/*": {"origins": allowed_origins_list}})

<<<<<<< HEAD
    security = SimpleSecurityManager()

    # ── Brute force tracker (+ persistent blocked_ips) ────────
    brute_force_tracker = defaultdict(list)
    BRUTE_FORCE_LIMIT      = 5
    BRUTE_FORCE_WINDOW     = 60
    BRUTE_FORCE_BLOCK_TIME = 300

    # Load persisted blocked IPs on startup
    from app.api.persistence import load_blocked_ips, save_blocked_ips
=======
    # Extensions / Dependencies
    from app import database as db
    from app.api.persistence import load_blocked_ips, save_blocked_ips
    security = SimpleSecurityManager()

    BRUTE_FORCE_LIMIT      = 5
    BRUTE_FORCE_WINDOW     = 300  # 5 minutes
    BRUTE_FORCE_BLOCK_TIME = 900  # 15 minutes

    # Load persisted blocked IPs on startup
>>>>>>> 4c5ae8566bbeb2af6ffddd6da0dc25f97d5a40fa
    blocked_ips = load_blocked_ips()

    @app.before_request
    def before_request():
        request.request_id = new_request_id()
        if is_trivial(request):
            return

        client_ip = _get_real_ip()
        is_business = is_business_relevant(request)
        request_blocked = False

        # 3a. Rate Limiting
        if not security.check_rate_limit(client_ip):
            security.blocked_requests += 1
            security._persist_stats()
<<<<<<< HEAD
            return jsonify({"error": "Rate limit exceeded"}), 429
=======
            return rate_limited("Rate limit exceeded")
>>>>>>> 4c5ae8566bbeb2af6ffddd6da0dc25f97d5a40fa

        # 3b. Scanner Detection
        sensitive_paths = ["/admin", "/wp-admin", "/phpmyadmin", "/.env",
                           "/config", "/backup", "/etc/passwd"]
        normalized_path = request.path.lower()
        if any(normalized_path.startswith(p) for p in sensitive_paths):
            security.log_to_dashboard(
                "Scanner", client_ip,
                f"Sensitive path: {request.path}", "Medium",
                endpoint=request.path, method=request.method,
                detection_type="Scanner", blocked=True,
                request_id=getattr(request, "request_id", ""),
            )
            security.blocked_requests += 1
            security._persist_stats()
<<<<<<< HEAD
            return jsonify({"error": "Not Found"}), 404
=======
            return not_found("Sensitive path access attempted")
>>>>>>> 4c5ae8566bbeb2af6ffddd6da0dc25f97d5a40fa

        # 3c. CSRF
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
<<<<<<< HEAD
                security.blocked_requests += 1
                security._persist_stats()
                return jsonify({"error": "CSRF validation failed",
                                "reason": _csrf_result["reason"]}), 403
=======
                security._persist_stats()
                return forbidden(f"CSRF validation failed: {_csrf_result['reason']}")
>>>>>>> 4c5ae8566bbeb2af6ffddd6da0dc25f97d5a40fa

        # 3d. SSRF
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
<<<<<<< HEAD
                security.blocked_requests += 1
                security._persist_stats()
                return jsonify({"error": "SSRF attempt blocked",
                                "reason": _ssrf_result["reason"]}), 403
=======
                security._persist_stats()
                return forbidden(f"SSRF attempt blocked: {_ssrf_result['reason']}")
>>>>>>> 4c5ae8566bbeb2af6ffddd6da0dc25f97d5a40fa

        # 3e. Content Scan — JSON + Form + Files metadata
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
<<<<<<< HEAD
                return jsonify({"error": msg}), 400
=======
                return bad_request(msg)
>>>>>>> 4c5ae8566bbeb2af6ffddd6da0dc25f97d5a40fa

        if not request_blocked and is_business:
            security.total_requests += 1
            security._persist_stats()

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
<<<<<<< HEAD
        return {"status": "running", "message": "API Security System Active",
                "security_level": "high", "version": "2.0.0"}

    @app.route("/health")
    def health():
        return jsonify({"status": "healthy"}), 200
=======
        return ok(data={"status": "running", "security_level": "high", "version": "2.0.0"}, 
                  message="API Security System Active")

    @app.route("/health")
    def health():
        return ok(data={"status": "healthy"})
>>>>>>> 4c5ae8566bbeb2af6ffddd6da0dc25f97d5a40fa

    @app.route("/health/detailed")
    @token_required
    @admin_required
    def health_detailed(current_user):
<<<<<<< HEAD
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
=======
        return ok(data={
            "status": "healthy", 
            "uptime": time.time() - security.start_time,
            "total_requests": security.total_requests,
            "blocked_requests": security.blocked_requests
        })

    @app.route("/api/health")
    def api_health():
        return ok(data={"connected": True, "status": "healthy", "timestamp": time.time()})

    @app.route("/api/data", methods=["POST"])
    def api_data():
        return created(data={"id": int(time.time()), "processed_at": time.time()}, 
                       message="Data accepted")
>>>>>>> 4c5ae8566bbeb2af6ffddd6da0dc25f97d5a40fa

    # ── Data Routes ───────────────────────────────────────────
    @app.route("/api/users", methods=["GET"])
    @token_required
    @admin_required
    def get_users_route(current_user):
      q = request.args.get("search", "")
      results = services.get_users(q if q else None)
<<<<<<< HEAD
      return jsonify({"users": results})
=======
      return ok(data={"users": results})
>>>>>>> 4c5ae8566bbeb2af6ffddd6da0dc25f97d5a40fa

    @app.route("/api/orders", methods=["GET"])
    @token_required
    def get_orders_route(current_user):
        user_filter = request.args.get("user", "")
        results = services.get_orders(current_user["username"])
        services.log_request("/api/orders", "GET", _get_real_ip(), 200, user_filter)
<<<<<<< HEAD
        return jsonify({"orders": results, "total": len(results)})
=======
        return paginated(results)
>>>>>>> 4c5ae8566bbeb2af6ffddd6da0dc25f97d5a40fa

    @app.route("/api/products", methods=["GET"])
    @token_required
    def get_products_route(current_user):
        cat = request.args.get("category", "")
        q   = request.args.get("search", "")
        results = services.get_products(cat if cat else None, q if q else None)
        services.log_request("/api/products", "GET", _get_real_ip(), 200, q or cat)
<<<<<<< HEAD
        return jsonify({"products": results, "total": len(results)})
=======
        return paginated(results)
>>>>>>> 4c5ae8566bbeb2af6ffddd6da0dc25f97d5a40fa

    @app.route("/api/orders", methods=["POST"])
    @token_required
    def create_order_route(current_user):
        data = request.get_json() or {}
        new_order = services.create_order(
        current_user["username"],
        data.get("product"),
        data.get("price")
    )
<<<<<<< HEAD
        return jsonify({"order": new_order}), 201
=======
        return created(data={"order": new_order})
>>>>>>> 4c5ae8566bbeb2af6ffddd6da0dc25f97d5a40fa

    @app.route("/api/logs", methods=["GET"])
    @token_required
    @admin_required
    def get_logs_route(current_user):
        logs = services.get_request_logs()
<<<<<<< HEAD
        return jsonify({"logs": logs, "total": len(logs)})
=======
        return paginated(logs)
>>>>>>> 4c5ae8566bbeb2af6ffddd6da0dc25f97d5a40fa

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
<<<<<<< HEAD
                return jsonify({"error": f"IP blocked for {remaining} seconds"}), 429
=======
                return rate_limited(f"IP blocked for {remaining} seconds")
>>>>>>> 4c5ae8566bbeb2af6ffddd6da0dc25f97d5a40fa
            else:
                del blocked_ips[ip]
                save_blocked_ips(blocked_ips)

        verified_user = user_manager.verify_password(username, password) if username and password else None
<<<<<<< HEAD
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
          resp = make_response(jsonify({"message": "Login successful"}))
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
                  return jsonify({"error": "Too many attempts. Try later."}), 429

              return jsonify({"error": "Invalid credentials"}), 401
=======
        
        if verified_user:
            db.log_login_attempt(username, ip, True, user_id=verified_user.get("user_id"))
            # Mint and return JWT — same as dashboard's login_user()
            token = jwt.encode({
                "user": username,
                "role": verified_user["role"],
                "exp": datetime.utcnow() + timedelta(hours=8),
                "iat": datetime.utcnow(),
                "jti": secrets.token_hex(16),   # for revocation
            }, current_app.config["SECRET_KEY"], algorithm="HS256")
            
            resp_json, status = ok(message="Login successful")
            resp = make_response(resp_json)
            from app import config as _cfg
            resp.set_cookie("auth_token", token, httponly=True,
                          secure=_cfg.cookie_secure(), samesite="Strict", max_age=8*3600)
            return resp, 200
        else:
            # Brute force tracking using DB
            db.log_login_attempt(username, ip, False, reason="Invalid credentials")
            
            # Count recent failures for this IP OR Username
            recent_failures = db.get_recent_login_failures(username, BRUTE_FORCE_WINDOW)
            security.brute_force_count += 1
            
            if recent_failures >= BRUTE_FORCE_LIMIT:
                blocked_ips[ip] = now + BRUTE_FORCE_BLOCK_TIME
                save_blocked_ips(blocked_ips)
                return rate_limited("Too many failed attempts. Try again in 15 minutes.")

            return unauthorized("Invalid credentials")
>>>>>>> 4c5ae8566bbeb2af6ffddd6da0dc25f97d5a40fa
    # ── Attack History Endpoints ──────────────────────────────
    @app.route("/api/my-attacks", methods=["GET"])
    @token_required
    def get_my_attacks(current_user):   # ← accept injected user from decorator
      user_key = current_user["username"]  # always from verified token
      attacks = get_user_attacks(user_key)
<<<<<<< HEAD
      return jsonify({"user": user_key, "attacks": attacks})
=======
      return ok(data={"user": user_key, "attacks": attacks})
>>>>>>> 4c5ae8566bbeb2af6ffddd6da0dc25f97d5a40fa

    @app.route("/api/clear-attacks", methods=["DELETE"])
    @token_required
    @admin_required
    def clear_attacks(current_user):
        from app.api.persistence import clear_all_attacks, clear_user_attacks
        if request.args.get("all") == "true":
            if current_user["role"] != "admin":
<<<<<<< HEAD
                return jsonify({"error": "Admin only"}), 403
            clear_all_attacks()
            return jsonify({"message": "All cleared"})
        # Always use the identity from the verified token
        clear_user_attacks(current_user["username"])
        return jsonify({"message": "Cleared"})
=======
                return forbidden("Admin only")
            clear_all_attacks()
            return ok(message="All cleared")
        # Always use the identity from the verified token
        clear_user_attacks(current_user["username"])
        return ok(message="Cleared")
>>>>>>> 4c5ae8566bbeb2af6ffddd6da0dc25f97d5a40fa

    # ── Security Stats ────────────────────────────────────────
    @app.route("/api/security/stats", methods=["GET"])
    @token_required
    @admin_required
    def get_security_stats(current_user):
        from app.ml.inference import get_ml_stats
<<<<<<< HEAD
        return jsonify({
=======
        return ok(data={
>>>>>>> 4c5ae8566bbeb2af6ffddd6da0dc25f97d5a40fa
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
<<<<<<< HEAD
        return jsonify({"feedback": data, "total": len(data)})
=======
        return paginated(data)
>>>>>>> 4c5ae8566bbeb2af6ffddd6da0dc25f97d5a40fa

    return app
