"""
API Routes - Flask application and route handlers
"""
import time
import os
import logging
from collections import defaultdict
from flask import Flask, request, jsonify
from flask_cors import CORS
from dotenv import load_dotenv

from app.api.security import SimpleSecurityManager
from app.api import services
from app.auth import user_manager
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


def _get_real_ip():
    """Real client IP — handles X-Forwarded-For from Reverse Proxy."""
    xff = request.headers.get("X-Forwarded-For", "")
    if xff:
        return xff.split(",")[0].strip()
    return request.remote_addr


def create_api_app():
    app = Flask(__name__)

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
            return jsonify({"error": "Rate limit exceeded"}), 429

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
            return jsonify({"error": "Not Found"}), 404

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
                security.blocked_requests += 1
                security._persist_stats()
                return jsonify({"error": "CSRF validation failed",
                                "reason": _csrf_result["reason"]}), 403

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
                security.blocked_requests += 1
                security._persist_stats()
                return jsonify({"error": "SSRF attempt blocked",
                                "reason": _ssrf_result["reason"]}), 403

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
                return jsonify({"error": msg}), 400

        if not request_blocked and is_business:
            security.total_requests += 1
            security._persist_stats()

    @app.after_request
    def after_request(response):
        response.headers["X-Content-Type-Options"]    = "nosniff"
        response.headers["X-Frame-Options"]           = "DENY"
        response.headers["X-XSS-Protection"]          = "1; mode=block"
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
    def get_users_route():
        q = request.args.get("search", "")
        results = services.get_users(q if q else None)
        services.log_request("/api/users", "GET", _get_real_ip(), 200, q)
        return jsonify({"users": results, "total": len(results)})

    @app.route("/api/orders", methods=["GET"])
    def get_orders_route():
        user_filter = request.args.get("user", "")
        results = services.get_orders(user_filter if user_filter else None)
        services.log_request("/api/orders", "GET", _get_real_ip(), 200, user_filter)
        return jsonify({"orders": results, "total": len(results)})

    @app.route("/api/products", methods=["GET"])
    def get_products_route():
        cat = request.args.get("category", "")
        q   = request.args.get("search", "")
        results = services.get_products(cat if cat else None, q if q else None)
        services.log_request("/api/products", "GET", _get_real_ip(), 200, q or cat)
        return jsonify({"products": results, "total": len(results)})

    @app.route("/api/orders", methods=["POST"])
    def create_order_route():
        data = request.get_json() or {}
        new_order = services.create_order(data.get("user"), data.get("product"), data.get("price"))
        services.log_request("/api/orders", "POST", _get_real_ip(), 201, new_order["product"])
        return jsonify({"message": "Order created", "order": new_order}), 201

    @app.route("/api/logs", methods=["GET"])
    def get_logs_route():
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
            return jsonify({"message": "Login successful", "role": verified_user["role"]})
        else:
            attempts = [t for t in brute_force_tracker[ip] if now - t < BRUTE_FORCE_WINDOW]
            attempts.append(now)
            brute_force_tracker[ip] = attempts
            security.brute_force_count += 1

            if len(attempts) >= BRUTE_FORCE_LIMIT:
                blocked_ips[ip] = now + BRUTE_FORCE_BLOCK_TIME
                save_blocked_ips(blocked_ips)   # ← persist!
                security.log_to_dashboard(
                    "Brute Force", ip,
                    f"Multiple failed logins ({len(attempts)}): {username}",
                    "Critical", endpoint=request.path, method=request.method,
                    snippet=f"user:{username} attempts:{len(attempts)}",
                    detection_type="Brute Force", blocked=True,
                    request_id=getattr(request, "request_id", ""),
                )
                return jsonify({"error": f"Too many attempts. Blocked {BRUTE_FORCE_BLOCK_TIME}s"}), 429

            return jsonify({"error": "Invalid credentials",
                            "attempts_remaining": BRUTE_FORCE_LIMIT - len(attempts)}), 401

    # ── Attack History Endpoints ──────────────────────────────
    @app.route("/api/my-attacks", methods=["GET"])
    def get_my_attacks():
        """
        GET /api/my-attacks?user=<username>
        لو مفيش user param → يرجع بناءً على الـ IP
        """
        from app.api.persistence import get_user_attacks
        user_key = request.args.get("user") or _get_real_ip()
        attacks  = get_user_attacks(user_key)
        return jsonify({
            "user":    user_key,
            "attacks": attacks,
            "total":   len(attacks),
        })

    @app.route("/api/clear-attacks", methods=["DELETE"])
    def clear_attacks():
        """DELETE /api/clear-attacks?user=<username>  (أو all=true لمسح الكل)"""
        from app.api.persistence import clear_user_attacks, clear_all_attacks
        if request.args.get("all") == "true":
            clear_all_attacks()
            return jsonify({"message": "All attack history cleared"})
        user_key = request.args.get("user") or _get_real_ip()
        clear_user_attacks(user_key)
        return jsonify({"message": f"Attack history cleared for {user_key}"})

    # ── Security Stats ────────────────────────────────────────
    @app.route("/api/security/stats", methods=["GET"])
    def get_security_stats():
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
    def get_ml_feedback():
        from app.api.persistence import get_ml_detections
        data = get_ml_detections(limit=100)
        return jsonify({"feedback": data, "total": len(data)})

    return app
