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

load_dotenv()

logger = logging.getLogger(__name__)


def create_api_app():
    """Create and configure the API Flask application"""
    app = Flask(__name__)
    CORS(app, resources={r"/api/*": {"origins": "*"}})
    security = SimpleSecurityManager()
    
    # Brute force tracker: {ip: [timestamp, ...]}
    brute_force_tracker = defaultdict(list)
    BRUTE_FORCE_LIMIT = 5       # max failed attempts
    BRUTE_FORCE_WINDOW = 60     # seconds
    BRUTE_FORCE_BLOCK_TIME = 300  # block for 5 minutes
    blocked_ips = {}            # {ip: unblock_timestamp}
    
    @app.before_request
    def before_request():
        """
        Request Processing Pipeline:
        1. Filter trivial requests → Skip
        2. Validate business relevance → Continue
        3. Run security checks → Detect threats
        4. Decide: Block or Allow
        5. Log and update metrics
        
        Metrics Rules (Mutually Exclusive):
        - Blocked requests: NOT counted in total_requests
        - Allowed business requests: counted in total_requests
        - Attack types: counted separately (sql_detections, xss_detections, etc.)
        """
        request.request_id = new_request_id()
        # Step 1: Filter trivial requests
        if is_trivial(request):
            return  # Skip all processing and metrics
        
        # Step 2: Check business relevance
        is_business = is_business_relevant(request)
        
        # Step 3 & 4: Security checks (Rate Limit, Scanner, Content)
        request_blocked = False
        block_reason = None
        
        # 3a. Rate Limiting (Strict Rule)
        if not security.check_rate_limit(request.remote_addr):
            request_blocked = True
            block_reason = "Rate limit exceeded"
            security.blocked_requests += 1
            security.update_dashboard_stats()
            return jsonify({'error': block_reason}), 429

        # 3b. Scanner Detection
        sensitive_paths = ['/admin', '/wp-admin', '/phpmyadmin', '/.env', '/config', '/backup', '/etc/passwd']
        if any(path in request.path for path in sensitive_paths):
            request_blocked = True
            block_reason = "Scanner detected"
            security.log_to_dashboard(
                "Scanner",
                request.remote_addr,
                f"Accessed sensitive path: {request.path}",
                "Medium",
                endpoint=request.path,
                method=request.method,
                detection_type="Scanner",
                blocked=True,
                request_id=getattr(request, "request_id", "")
            )
            security.blocked_requests += 1
            security.update_dashboard_stats()
            return jsonify({"error": "Not Found"}), 404

        # 3c. Content Security Scan (SQLi, XSS, ML)
        data_to_scan = {}
        if request.args:
            data_to_scan.update(request.args.to_dict())
        if request.is_json:
            try:
                data = request.get_json()
                if data:
                    data_to_scan.update(data)
            except Exception:
                pass
        
        if data_to_scan:
            safe, msg = security.check_request_security(data_to_scan, request.remote_addr)
            if not safe:
                request_blocked = True
                block_reason = msg
                security.blocked_requests += 1
                security.update_dashboard_stats()
                return jsonify({'error': msg}), 400
        
        # Step 5: Update metrics for allowed requests
        # Count all non-blocked business-relevant requests
        if not request_blocked and is_business:
            security.total_requests += 1
        
        security.update_dashboard_stats()
    
    @app.after_request
    def after_request(response):
        # Add security headers
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['X-XSS-Protection'] = '1; mode=block'
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
        response.headers['Content-Security-Policy'] = "default-src 'self'"
        response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        return response
    
    # ── Basic Routes ────────────────────────────────────────
    
    @app.route('/')
    def index():
        return {
            'status': 'running',
            'message': 'API Security System Active',
            'security_level': 'high',
            'version': '1.1.0'
        }
    
    @app.route('/health')
    def health():
        return {
            'status': 'healthy',
            'uptime': time.time() - security.start_time,
            'total_requests': security.total_requests,
            'blocked_requests': security.blocked_requests
        }
    
    @app.route('/api/health')
    def api_health():
        return jsonify({
            'connected': True,
            'status': 'healthy',
            'timestamp': time.time()
        })
    
    @app.route('/api/data', methods=['POST'])
    def api_data():
        # Scanned in before_request
        return jsonify({
            'message': 'Data accepted',
            'id': int(time.time()),
            'processed_at': time.time()
        }), 201
    
    # ── Data API Routes ────────────────────────────────────
    
    @app.route('/api/users', methods=['GET'])
    def get_users_route():
        q = request.args.get('search', '')
        results = services.get_users(q if q else None)
        services.log_request('/api/users', 'GET', request.remote_addr, 200, q)
        return jsonify({'users': results, 'total': len(results)})

    @app.route('/api/orders', methods=['GET'])
    def get_orders_route():
        user_filter = request.args.get('user', '')
        results = services.get_orders(user_filter if user_filter else None)
        services.log_request('/api/orders', 'GET', request.remote_addr, 200, user_filter)
        return jsonify({'orders': results, 'total': len(results)})

    @app.route('/api/products', methods=['GET'])
    def get_products_route():
        cat = request.args.get('category', '')
        q = request.args.get('search', '')
        results = services.get_products(
            cat if cat else None,
            q if q else None
        )
        services.log_request('/api/products', 'GET', request.remote_addr, 200, q or cat)
        return jsonify({'products': results, 'total': len(results)})

    @app.route('/api/orders', methods=['POST'])
    def create_order_route():
        data = request.get_json() or {}
        new_order = services.create_order(
            data.get('user'),
            data.get('product'),
            data.get('price')
        )
        services.log_request('/api/orders', 'POST', request.remote_addr, 201, new_order['product'])
        return jsonify({'message': 'Order created', 'order': new_order}), 201

    @app.route('/api/logs', methods=['GET'])
    def get_logs_route():
        logs = services.get_request_logs()
        return jsonify({'logs': logs, 'total': len(logs)})
    
    # ── Authentication Route ──────────────────────────────
    
    @app.route('/api/login', methods=['POST'])
    def login():
        # Scanned in before_request
        data = request.get_json() or {}
        username = data.get('username')
        password = data.get('password')
        
        ip = request.remote_addr
        now = time.time()

        # Check if IP is currently blocked
        if ip in blocked_ips:
            if now < blocked_ips[ip]:
                remaining = int(blocked_ips[ip] - now)
                security.log_to_dashboard(
                    "Brute Force", ip,
                    f"Blocked IP tried to login: {username}",
                    "High",
                    endpoint=request.path, method=request.method,
                    snippet=f"user: {username}",
                    detection_type="Brute Force", blocked=True,
                    request_id=getattr(request, "request_id", "")
                )
                security.blocked_requests += 1
                security.update_dashboard_stats()
                return jsonify({'error': f'IP blocked for {remaining} seconds'}), 429
            else:
                del blocked_ips[ip]

        verified_user = user_manager.verify_password(username, password) if username and password else None
        if verified_user:
            # Reset failed attempts on success
            brute_force_tracker[ip] = []
            return jsonify({'message': 'Login successful', 'role': verified_user['role']})
        else:
            # Track failed attempt
            attempts = brute_force_tracker[ip]
            attempts = [t for t in attempts if now - t < BRUTE_FORCE_WINDOW]
            attempts.append(now)
            brute_force_tracker[ip] = attempts
            security.brute_force_count += 1

            if len(attempts) >= BRUTE_FORCE_LIMIT:
                # Block the IP
                blocked_ips[ip] = now + BRUTE_FORCE_BLOCK_TIME
                security.log_to_dashboard(
                    "Brute Force", ip,
                    f"Multiple failed login attempts ({len(attempts)}): {username}",
                    "Critical",
                    endpoint=request.path, method=request.method,
                    snippet=f"user: {username}, attempts: {len(attempts)}",
                    detection_type="Brute Force", blocked=True,
                    request_id=getattr(request, "request_id", "")
                )
                return jsonify({'error': f'Too many failed attempts. IP blocked for {BRUTE_FORCE_BLOCK_TIME} seconds'}), 429
            
            return jsonify({'error': 'Invalid credentials', 'attempts_remaining': BRUTE_FORCE_LIMIT - len(attempts)}), 401
    
    # ── Security Stats Route ──────────────────────────────
    
    @app.route('/api/security/stats', methods=['GET'])
    def get_security_stats():
        return jsonify({
            'total_requests': security.total_requests,
            'blocked_requests': security.blocked_requests,
            'sql_injection_count': security.sql_injection_count,
            'xss_count': security.xss_count,
            'brute_force_count': security.brute_force_count,
            'rate_limit_hits': security.rate_limit_hits,
            'ml_detections': security.ml_detections,
            'uptime': time.time() - security.start_time
        })

    return app
