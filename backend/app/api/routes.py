"""
API Routes - Flask application and route handlers

This module implements a 7-layer inline reverse proxy WAF.
Clean requests are proxied to TARGET_EXTERNAL_SITE; attacks are blocked.
"""
from datetime import datetime, timedelta
import time
import os
import logging
from collections import defaultdict
from urllib.parse import urljoin
# pyrefly: ignore [missing-import]
from flask import Flask, Response, current_app, make_response, request, jsonify
from flask_cors import CORS

os.environ.setdefault("RATE_LIMIT_WINDOW", "10")
os.environ.setdefault("RATE_LIMIT_MAX", "5")

# pyrefly: ignore [missing-import]
from dotenv import load_dotenv
# pyrefly: ignore [missing-import]
import jwt
import secrets
from app.api.security import SimpleSecurityManager
from app.api import services
from app.auth import user_manager
from app.auth.decorators import admin_only, login_required
from app.security import new_request_id, is_trivial
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

_total_requests_count = 0
_normal_requests_count = 0

def _get_real_ip():
    if request.remote_addr in TRUSTED_PROXIES:
        xff = request.headers.get("X-Forwarded-For", "")
        if xff:
            return xff.split(",")[0].strip()
    return request.remote_addr

# Or use Werkzeug's ProxyFix middleware:


def create_api_app():
    # pyrefly: ignore [missing-import]
    from werkzeug.middleware.proxy_fix import ProxyFix
    app = Flask(__name__)
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1)
    app.config['SECRET_KEY'] = os.getenv("SECRET_KEY", "")
    from app import database as db



    # ── Config ────────────────────────────────────────────────
    app.config["MAX_CONTENT_LENGTH"] = int(os.getenv("MAX_CONTENT_LENGTH", str(1 * 1024 * 1024)))

    allowed_origins      = os.getenv("ALLOWED_ORIGINS", "http://127.0.0.1:3000,http://localhost:3000")
    allowed_origins_list = [o.strip() for o in allowed_origins.split(",") if o.strip()]
    CORS(app, resources={r"/api/*": {"origins": allowed_origins_list}}, supports_credentials=True, methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"])

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
    BLOCK_CACHE_DURATION = 120  # 120 seconds

    def _block_ip(ip):
        ip_cache[ip] = time.time()

    def _is_ip_blocked(ip):
        if ip in ip_cache:
            elapsed = time.time() - ip_cache[ip]
            if elapsed < BLOCK_CACHE_DURATION:
                return True
            del ip_cache[ip]
        return False

    app.security_manager = security
    app.block_ip_fn = _block_ip

    from app.auth.routes import auth_bp
    app.register_blueprint(auth_bp)

    # ── White-listed local management routes ─────────────────
    # These paths bypass WAF scanning and proxying entirely.
    # Flask handles them locally (health checks, dashboard,
    # auth endpoints, static assets, and the root index).
    _LOCAL_ROUTES = (
        "/health", "/api/dashboard/", "/dashboard", "/auth", "/static",
        "/api/auth", "/api/user", "/critical", "/blocked", "/blocked_page",
        "/incidents", "/incidents_list", "/requests", "/profile", "/ml-detections",
        "/ml-performance", "/threats", "/login", "/signup", "/logout",
        "/forbidden", "/privacy", "/terms", "/docs", "/support",
        "/attack-history", "/threats-overview", "/user-manager", "/settings",
        "/notifications", "/pricing", "/payment", "/blacklist", "/api/"
    )

    @app.before_request
    def before_request():
        if request.method == "OPTIONS":
            return Response("OK", status=200)

        global _total_requests_count, _normal_requests_count
        request.request_id = new_request_id()

        # ══════════════════════════════════════════════════════
        # STEP 0: Skip trivial noise (health probes, static
        #         assets, dashboard internals).  These are NOT
        #         counted in any metric — they are monitoring
        #         overhead, not real traffic.
        # ══════════════════════════════════════════════════════
        if is_trivial(request):
            return
            
        EXCLUDED_PATHS = ['/static/', '/favicon.ico', '/assets/', '/dist/', '/api/health']
        for path in EXCLUDED_PATHS:
            if request.path.startswith(path):
                return # اخرج من الفحص فوراً ومتحسبش أي حاجة

        # ══════════════════════════════════════════════════════
        # STEP 1 — IMMEDIATE TOTAL INCREMENT (before anything)
        #
        # Every single hit on port 5000 that isn't monitoring
        # noise is counted here.  This runs BEFORE IP-block,
        # rate-limit, WAF, or proxy logic — guaranteeing the
        # SIEM "Total Requests" counter is always accurate.
        # ══════════════════════════════════════════════════════
        _total_requests_count += 1
        security.total_requests += 1

        request.is_attack = False
        client_ip = _get_real_ip()

        actual_path = request.headers.get("X-Original-URI", request.path).split('?')[0]
        actual_method = request.headers.get("X-Original-Method", request.method)

        # ══════════════════════════════════════════════════════
        # STEP 2 — WHITE-LISTED LOCAL ROUTE BYPASS
        #
        # Management/API routes served by Flask itself.
        # They skip WAF content scanning AND proxying,
        # eliminating false-positives on internal traffic.
        # The root "/" is also handled locally.
        # ══════════════════════════════════════════════════════
        if actual_path == "/" or actual_path == "/login" or any(actual_path.startswith(p) for p in _LOCAL_ROUTES):
            # Let Flask dispatch to its own route handlers.
            # Metrics are already incremented above.
            return

        # ──────────────────────────────────────────────────────
        # Everything below is EXTERNAL traffic headed for the
        # upstream target site.  It must survive ALL security
        # layers before being proxied.
        #
        # SAFETY NET: The entire WAF pipeline is wrapped in
        # try/except.  If ANY layer crashes (DB, ML, regex,
        # persistence), we fail-closed with 403 Forbidden
        # instead of leaking a 500 Internal Server Error.
        # ──────────────────────────────────────────────────────
        try:
            # ── Layer 0: In-memory IP block check ─────────────────
            if _is_ip_blocked(client_ip):
                request.is_attack = True
                security.blocked_requests += 1
                security._persist_stats()
                return jsonify({"error": "IP blocked"}), 429

            # ── Layer 1: Rate Limiting ────────────────────────────
            if not security.check_rate_limit(client_ip):
                security.blocked_requests += 1
                security._persist_stats()
                try:
                    from app.api.persistence import append_user_attack
                    from app.api.security import calculate_severity, should_block_attack
                    severity = calculate_severity("Rate Limit", endpoint=actual_path)
                    should_block = should_block_attack("Rate Limit", endpoint=actual_path)
                    append_user_attack(
                        client_ip, "Rate Limit Exceeded", client_ip,
                        actual_path, actual_method, severity, blocked=True,
                    )
                except Exception:
                    pass
                _block_ip(client_ip)
                return jsonify({"error": "Rate limit exceeded"}), 429

            # ── Layer 2: Scanner Detection (sensitive paths) ──────
            sensitive_paths = ["/wp-admin", "/phpmyadmin", "/.env",
                               "/etc/passwd", "/.git",
                               "/.svn", "/.htaccess", "/server-status", "/wp-login"]
            normalized_path = actual_path.lower()
            if any(normalized_path.startswith(p) for p in sensitive_paths):
                request.is_attack = True
                from app.api.security import calculate_severity, should_block_attack
                severity = calculate_severity("Scanner", endpoint=actual_path)
                security.blocked_requests += 1
                security._persist_stats()
                try:
                    from app.api.persistence import append_user_attack
                    append_user_attack(
                        client_ip, "Scanner", client_ip,
                        actual_path, actual_method, "Low", blocked=True,
                        description=f"Sensitive path probe: {actual_path}",
                    )
                except Exception:
                    pass
                return jsonify({"error": "Malicious request blocked by WAF", "blocked": True}), 403

            # ══════════════════════════════════════════════════════
            # Layer 3: FULL Content Scan  (SQLi, XSS, CMDi,
            #          Path Traversal + ML Model)
            #
            # CRITICAL: Extract from ALL attack surfaces and
            # ALWAYS run the scan — never skip on empty data.
            # ══════════════════════════════════════════════════════

            # ── 3a. Exhaustive data extraction ────────────────────
            data_to_scan = {}

            from urllib.parse import urlparse, parse_qs
            original_uri = request.headers.get("X-Original-URI", "")
            if original_uri:
                parsed_uri = urlparse(original_uri)
                if parsed_uri.query:
                    qs_dict = parse_qs(parsed_uri.query, keep_blank_values=True)
                    data_to_scan.update(qs_dict)

            # Query parameters  (?search=payload)
            if request.args:
                data_to_scan.update(request.args.to_dict(flat=False))

            # JSON body  (Content-Type: application/json)
            if request.is_json:
                try:
                    j = request.get_json(silent=True)
                    if j and isinstance(j, dict):
                        data_to_scan.update(j)
                    elif j and isinstance(j, list):
                        for idx, item in enumerate(j):
                            data_to_scan[f"_json_array_{idx}"] = item
                except Exception:
                    pass

            # Form-encoded body
            if request.form:
                data_to_scan.update(request.form.to_dict())

            # File uploads  (filename + MIME type can carry payloads)
            if request.files:
                for field, fobj in request.files.items():
                    data_to_scan[f"_file_name_{field}"]     = fobj.filename or ""
                    data_to_scan[f"_file_mimetype_{field}"] = fobj.content_type or ""

            # URL path itself  (/products/' UNION SELECT ...)
            if actual_path and actual_path != "/":
                data_to_scan["_url_path"] = actual_path

            # Raw query string  (catches payloads not parsed as key=value)
            # Use X-Original-URI to extract raw query if Nginx didn't pass it in subrequest
            original_uri = request.headers.get("X-Original-URI", "")
            if "?" in original_uri:
                data_to_scan["_raw_query"] = original_uri.split("?", 1)[1]
            elif request.query_string:
                data_to_scan["_raw_query"] = request.query_string.decode(
                    "utf-8", errors="replace"
                )

            # Security-sensitive headers
            _SCAN_HEADERS = ("User-Agent", "Referer", "Cookie", "Origin", "X-Forwarded-For")
            for hdr in _SCAN_HEADERS:
                val = request.headers.get(hdr)
                if val:
                    data_to_scan[f"_header_{hdr}"] = val

            # Raw body fallback  (non-JSON, non-form POST/PUT bodies)
            if (
                actual_method in ("POST", "PUT", "PATCH")
                and not request.is_json
                and not request.form
            ):
                try:
                    raw = request.get_data(as_text=True)
                    if raw and len(raw) < 10_000:
                        data_to_scan["_raw_body"] = raw
                except Exception:
                    pass

            # ── 3b. Run WAF scan unconditionally ──────────────────
            safe, msg = security.check_request_security(data_to_scan, client_ip, actual_path)
            if not safe:
                request.is_attack = True
                security.blocked_requests += 1
                security._persist_stats()
                logger.warning(
                    f"[WAF-BLOCK] {client_ip} → {actual_method} {actual_path} | {msg}"
                )
                
                try:
                    from app.api.persistence import append_user_attack
                    payload = request.query_string.decode("utf-8", errors="replace")
                    append_user_attack(
                        user_key=client_ip,
                        attack_type="SQLi",
                        ip=client_ip,
                        endpoint=actual_path,
                        method=actual_method,
                        severity="High",
                        blocked=True,
                        description=f"Malicious payload: {payload}"
                    )
                except Exception as e:
                    logger.error(f"Failed to log SQLi attack in routes: {e}")

                return jsonify({
                    "error": "Malicious content detected",
                    "blocked": True,
                }), 403

            # ── Layer 4: SSRF Detection ───────────────────────────
            if _CSRF_SSRF_ENABLED:
                _ssrf_result = detect_ssrf({
                    "method": actual_method, "path": actual_path,
                    "headers": dict(request.headers),
                    "body": request.get_json(silent=True) or {},
                    "query_params": request.args.to_dict(),
                    "cookies": request.cookies.to_dict(),
                    "ip": client_ip, "user_agent": request.user_agent.string,
                })
                if _ssrf_result["detected"]:
                    request.is_attack = True
                    from app.api.security import calculate_severity, should_block_attack
                    severity = calculate_severity("SSRF", endpoint=actual_path)
                    security.blocked_requests += 1
                    security._persist_stats()
                    try:
                        from app.api.persistence import append_user_attack
                        append_user_attack(
                            client_ip, "SSRF", client_ip,
                            actual_path, actual_method, severity, blocked=True,
                            description=f"[SSRF] {_ssrf_result['reason']}",
                        )
                    except Exception:
                        pass
                    return jsonify({"error": "SSRF attempt blocked",
                                    "reason": _ssrf_result["reason"]}), 403

            # ── Layer 5: CSRF Detection ───────────────────────────
            _auth_header = request.headers.get("Authorization", "") or request.headers.get("X-API-Key", "")
            _is_public_endpoint = any(actual_path.startswith(p) for p in (
                "/api/login", "/api/products", "/api/register", "/api/health",
            ))
            if (
                _CSRF_SSRF_ENABLED
                and actual_method in ("POST", "PUT", "DELETE", "PATCH")
                and not _auth_header.startswith("Bearer ")
                and not _is_public_endpoint
            ):
                _csrf_result = detect_csrf({
                    "method": actual_method, "path": actual_path,
                    "headers": dict(request.headers),
                    "body": request.get_json(silent=True) or {},
                    "query_params": request.args.to_dict(),
                    "cookies": request.cookies.to_dict(),
                    "ip": client_ip, "user_agent": request.user_agent.string,
                })
                if _csrf_result["detected"]:
                    request.is_attack = True
                    from app.api.security import calculate_severity, should_block_attack
                    severity = calculate_severity("CSRF", endpoint=actual_path)
                    security.blocked_requests += 1
                    security._persist_stats()
                    try:
                        from app.api.persistence import append_user_attack
                        append_user_attack(
                            client_ip, "CSRF", client_ip,
                            actual_path, actual_method, severity, blocked=True,
                            description="Missing or invalid CSRF token",
                        )
                    except Exception:
                        pass
                    return jsonify({"error": "CSRF validation failed",
                                    "reason": _csrf_result["reason"]}), 403

            # ══════════════════════════════════════════════════════
            # STEP 4 — ALL SECURITY LAYERS PASSED
            #
            # If the request reached this point without being blocked,
            # it is clean. Nginx will interpret a 2xx response as
            # authorization to forward the request to the upstream target.
            # ══════════════════════════════════════════════════════
            request.is_clean = True
            _normal_requests_count += 1
            security.log_normal_request(client_ip, actual_path, actual_method)
            security._persist_stats()

            # If this is a WAF inspection subrequest from Nginx, return 200 OK.
            if request.path == "/waf-inspect":
                return Response("OK", status=200)

        except Exception as exc:
            # ══════════════════════════════════════════════════════
            # FAIL-CLOSED: If any WAF layer crashes, block the
            # request with 403 rather than leaking a 500.
            # ══════════════════════════════════════════════════════
            logger.error(
                f"[WAF-ERROR] Unhandled exception during security scan — "
                f"BLOCKING request from {client_ip} → {actual_method} {actual_path}: {exc}",
                exc_info=True,
            )
            request.is_attack = True
            security.blocked_requests += 1
            try:
                security._persist_stats()
            except Exception:
                pass
            return jsonify({
                "error": "Request blocked by security policy",
                "blocked": True,
            }), 403

    @app.after_request
    def after_request(response):
        response.headers["X-Content-Type-Options"]    = "nosniff"
        # Removed X-Frame-Options to allow the React wrapper on 8070 to iframe the app
        # response.headers["X-Frame-Options"]           = "DENY"
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        response.headers["Content-Security-Policy"]   = "default-src 'self' 'unsafe-inline' 'unsafe-eval' data:; frame-ancestors 'self' http://localhost:8070 http://127.0.0.1:8070;"
        response.headers["Referrer-Policy"]           = "strict-origin-when-cross-origin"

        return response

    # ── Basic Routes ──────────────────────────────────────────
    @app.route("/waf-inspect", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"])
    def waf_inspect():
        # This route is the target for Nginx's auth_request directive.
        # If execution reaches here, the @app.before_request hook has
        # already scanned the request and found it clean.
        return Response("OK", status=200)

    @app.route("/")
    def index():
        return {"status": "running", "message": "API Security System Active",
                "security_level": "high", "version": "2.0.0"}

    @app.route("/health")
    def health():
        return jsonify({"status": "healthy"}), 200

    @app.route("/health/detailed")
    @admin_only
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
    @admin_only
    def get_users_route(current_user):
      q = request.args.get("search", "")
      results = services.get_users(q if q else None)
      return jsonify({"users": results})

    @app.route("/api/orders", methods=["GET"])
    @login_required
    def get_orders_route(current_user):
        user_filter = request.args.get("user", "")
        results = services.get_orders(current_user["username"])
        services.log_request("/api/orders", "GET", _get_real_ip(), 200, user_filter)
        return jsonify({"orders": results, "total": len(results)})

    @app.route("/api/products", methods=["GET"])
    @login_required
    def get_products_route(current_user):
        cat = request.args.get("category", "")
        q   = request.args.get("search", "")
        results = services.get_products(cat if cat else None, q if q else None)
        services.log_request("/api/products", "GET", _get_real_ip(), 200, q or cat)
        return jsonify({"products": results, "total": len(results)})

    @app.route("/api/orders", methods=["POST"])
    @login_required
    def create_order_route(current_user):
        data = request.get_json() or {}
        new_order = services.create_order(
        current_user["username"],
        data.get("product"),
        data.get("price")
    )
        return jsonify({"order": new_order}), 201

    @app.route("/api/logs", methods=["GET"])
    @admin_only
    def get_logs_route(current_user):
        logs = services.get_request_logs()
        return jsonify({"logs": logs, "total": len(logs)})

    # ── Auth ──────────────────────────────────────────────────
    # Note: Login logic has been centralized into app/auth/routes.py
    # ── Attack History Endpoints ──────────────────────────────
    @app.route("/api/my-attacks", methods=["GET"])
    @login_required
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
    @admin_only
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
    @admin_only
    def get_security_stats(current_user):
        from app.ml.inference import get_ml_stats
        return jsonify({
            "total_requests":       security.total_requests,
            "blocked_requests":     security.blocked_requests,
            "normal_request_count":  security.normal_request_count,
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

    @app.route("/api/security/requests", methods=["GET"])
    @login_required
    def get_security_requests(current_user):
        page = request.args.get("page", 1, type=int)
        limit = request.args.get("limit", 10, type=int)
        filter_type = request.args.get("filter", "all").lower().strip()
        offset = (page - 1) * limit

        from app import database as db
        with db.engine.connect() as conn:
            where_clause = ""
            params = {}
            if filter_type != "all" and filter_type != "":
                if filter_type == "clean":
                    where_clause = "WHERE LOWER(attack_type) IN ('clean', 'normal') OR attack_type IS NULL OR attack_type = ''"
                elif filter_type == "blocked":
                    # Check both boolean representations in DB (e.g. 1/0 or true/false)
                    where_clause = "WHERE blocked = 1 OR blocked = 'true'"
                elif filter_type == "sqli":
                    where_clause = "WHERE LOWER(attack_type) LIKE '%sql%'"
                elif filter_type == "xss":
                    where_clause = "WHERE LOWER(attack_type) LIKE '%xss%'"
                elif filter_type == "brute":
                    where_clause = "WHERE LOWER(attack_type) LIKE '%brute%' OR LOWER(attack_type) LIKE '%auth%'"
                elif filter_type == "scanner":
                    where_clause = "WHERE LOWER(attack_type) LIKE '%scan%'"
                elif filter_type == "ml":
                    where_clause = "WHERE LOWER(attack_type) LIKE '%ml%' OR LOWER(attack_type) LIKE '%anomaly%'"
                elif filter_type == "rate":
                    where_clause = "WHERE LOWER(attack_type) LIKE '%rate%' OR LOWER(attack_type) LIKE '%limit%'"
                elif filter_type == "csrf":
                    where_clause = "WHERE LOWER(attack_type) LIKE '%csrf%'"
                elif filter_type == "ssrf":
                    where_clause = "WHERE LOWER(attack_type) LIKE '%ssrf%'"
                elif filter_type == "path":
                    where_clause = "WHERE LOWER(attack_type) LIKE '%path%' OR LOWER(attack_type) LIKE '%traversal%'"
                else:
                    where_clause = "WHERE LOWER(attack_type) LIKE :filter_type"
                    params["filter_type"] = f"%{filter_type}%"

            total_count_query = f"SELECT COUNT(*) FROM threat_logs {where_clause}"
            total_count = conn.execute(db.text(total_count_query), params).scalar() or 0
            
            fetch_query = f"""
                SELECT * FROM threat_logs 
                {where_clause}
                ORDER BY threat_log_id DESC 
                LIMIT :limit OFFSET :offset
            """
            query_params = {**params, "limit": limit, "offset": offset}
            rows = conn.execute(db.text(fetch_query), query_params).mappings().all()
            
            requests_list = db._sanitize_list(rows)
            for r in requests_list:
                r['id'] = r.get('threat_log_id')
                r['timestamp'] = r.get('created_at')
                r['source_ip'] = r.get('ip_address')
                r['path'] = r.get('endpoint')
                r['is_threat'] = r.get('attack_type') != 'Clean' and r.get('attack_type') != 'Normal'
                # Deriving status code: if blocked, use 400 (or 429 for rate limit), else 200
                if r.get('blocked'):
                    r['status_code'] = 429 if r.get('attack_type') == 'Rate Limit' else 400
                else:
                    r['status_code'] = 200

            # Apply IP and payload masking for non-admin / non-analyst users
            if current_user.get("role") not in ("admin", "analyst"):
                for r in requests_list:
                    r['source_ip'] = "XXX.XXX.XXX.XXX"
                    r['ip_address'] = "XXX.XXX.XXX.XXX"
                    r['payload'] = "[HIDDEN]"
                    r['snippet'] = "[HIDDEN]"
                    r['description'] = "[HIDDEN]"

        import math
        total_pages = math.ceil(total_count / limit) if limit > 0 else 1
        
        return jsonify({
            "requests": requests_list,
            "totalCount": total_count,
            "totalPages": total_pages
        })

    @app.route("/api/security/reset", methods=["POST"])
    @admin_only
    def reset_security_stats(current_user):
        security.reset()
        return jsonify({"status": "reset", "message": "Security manager stats reset successfully"})

    @app.route("/api/security/ml/feedback", methods=["GET"])
    @admin_only
    def get_ml_feedback(current_user):
        from app.api.persistence import get_ml_detections
        data = get_ml_detections(limit=100)
        return jsonify({"feedback": data, "total": len(data)})

    return app
