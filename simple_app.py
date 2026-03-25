try:
    from app.security.filters import is_trivial, is_business_relevant
    from app.ml.inference import ml_detect
    from app.security.events import new_request_id, build_event
except ImportError:
    # Fallback to old structure
    from security.filters import is_trivial, is_business_relevant
    from ml.model import ml_detect
    from security.events import new_request_id, build_event

# ── CSRF / SSRF كاشفات التهديدات المتقدمة ──────────────────────────────────
try:
    from detections.csrf_rule import detect_csrf_rule
    from detections.ssrf_rule import detect_ssrf_rule
    _CSRF_SSRF_ENABLED = True
except ImportError:
    _CSRF_SSRF_ENABLED = False
    import warnings
    warnings.warn("[VIREX] detections package not found — CSRF/SSRF detection disabled", stacklevel=1)
from flask import Flask, request, jsonify
import time
import re
import logging
import requests
import threading
from collections import defaultdict, deque
import joblib
import os
from dotenv import load_dotenv
from models import user_manager
from flask_cors import CORS

load_dotenv("env")



# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class SimpleSecurityManager:
    """Simplified security manager for testing with ML integration"""

    def __init__(self):
        self.total_requests = 0
        self.blocked_requests = 0
        self.sql_injection_count = 0
        # track ML detections separately for metrics/logging
        self.ml_detections = 0
        self.xss_count = 0
        self.brute_force_count = 0
        self.rate_limit_hits = 0
        self.rate_limit_storage = defaultdict(deque)
        self.start_time = time.time()
        self.dashboard_url = os.getenv("DASHBOARD_URL", "http://127.0.0.1:8070")

        # Robust patterns
        self.sql_patterns = [
            r"(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|UNION|EXEC|TRUNCATE|GRANT|REVOKE)",
            r"(\bOR\b|\bAND\b).+(\=|\bLIKE\b|\bIN\b)",
            r"(--|#|/\*|\*/|;|@@|\bSLEEP\b|\bBENCHMARK\b|\bWAITFOR\b)",
            r"('|%27).+(\bOR\b|\bAND\b).+",
            r"UNION\s+SELECT",
        ]

        self.xss_patterns = [
            r"<script.*?>.*?</script>",
            r"javascript:",
            r"onerror\s*=",
            r"onload\s*=",
            r"onclick\s*=",
            r"<iframe.*?>",
            r"<svg.*?>",
            r"<img.*?onerror",
            r"<body.*?onload",
            r"alert\(.*\)",
        ]

        self.compiled_sql_patterns = [re.compile(p, re.IGNORECASE) for p in self.sql_patterns]
        self.compiled_xss_patterns = [re.compile(p, re.IGNORECASE) for p in self.xss_patterns]
      
    # ================= DASHBOARD =================
    def log_to_dashboard(
        self,
        threat_type,
        ip,
        description,
        severity="Medium",
        endpoint="",
        method="",
        snippet="",
        detection_type="Other",
        blocked=True,
        request_id="",
    ):
        def send_log():
            try:
                logger.debug(f"[TRACE] sending to dashboard request_id={request_id} type={threat_type} ip={ip}")
                requests.post(
                    f"{self.dashboard_url}/api/dashboard/threat",
                    json={
                        "type": threat_type,
                        "ip": ip,
                        "description": description,
                        "severity": severity,
                        "endpoint": endpoint,
                        "method": method,
                        "snippet": snippet,
                        "detection_type": detection_type,
                        "blocked": blocked,
                        "request_id": request_id,
                    },
                    timeout=2,
                )
            except Exception:
                pass

        threading.Thread(target=send_log, daemon=True).start()

    def update_dashboard_stats(self):
        # Disabled pushing local memory stats to dashboard
        # Dashboard recalculates its own accurate stats from siem_audit.json
        pass

    # ================= REGEX =================
    def detect_sql_injection(self, text, ip):
        for pattern in self.compiled_sql_patterns:
            if pattern.search(text):
                self.sql_injection_count += 1
                logger.info(f"[REGEX-SQLi] Blocked {ip} — {text[:80]}")
                logger.debug(f"[REGEX-SQL] raw_text='{text[:80]}'")
                self.log_to_dashboard(
                    "SQL Injection",
                    ip,
                    f"[REGEX] SQL Injection detected — pattern matched in: {text[:60]}",
                    "High",
                    endpoint=request.path,
                    method=request.method,
                    snippet=text[:100],
                    detection_type="Signature-based",
                    blocked=True,
                    request_id=getattr(request, "request_id", ""),
                )
                return True
        return False

    def detect_xss(self, text, ip):
        for pattern in self.compiled_xss_patterns:
            if pattern.search(text):
                self.xss_count += 1
                logger.info(f"[REGEX-XSS] Blocked {ip} — {text[:80]}")
                logger.debug(f"[REGEX-XSS] raw_text='{text[:80]}'")
                self.log_to_dashboard(
                    "XSS",
                    ip,
                    f"[REGEX] XSS detected — pattern matched in: {text[:60]}",
                    "High",
                    endpoint=request.path,
                    method=request.method,
                    snippet=text[:100],
                    detection_type="Signature-based",
                    blocked=True,
                    request_id=getattr(request, "request_id", ""),
                )
                return True
        return False

    # ================= RATE LIMIT =================
    def check_rate_limit(self, ip):
        now = time.time()
        q = self.rate_limit_storage[ip]

        # 10 second window
        while q and now - q[0] > 10:
            q.popleft()

        if len(q) >= 10:
            self.rate_limit_hits += 1
            logger.debug(f"[RATE] limit hit for ip={ip}")
            self.log_to_dashboard(
                "Rate Limit",
                ip,
                "Rate limit exceeded",
                "Medium",
                endpoint=request.path,
                method=request.method,
                detection_type="Rule-based",
                blocked=True,
                request_id=getattr(request, "request_id", ""),
            )
            return False

        q.append(now)
        return True

    # ================= MAIN SECURITY =================
    def check_request_security(self, data, ip, request_context):
        def classify_ml_attack(text):
            t = str(text)
            for patt in self.compiled_sql_patterns:
                if patt.search(t):
                    return "SQL Injection"
            for patt in self.compiled_xss_patterns:
                if patt.search(t):
                    return "XSS"
            if re.search(r"(password|login|user|admin)", t, re.IGNORECASE):
                return "Brute Force"
            return "Unknown"

        def scan_rules(value):
            if isinstance(value, dict):
                for v in value.values():
                    if not scan_rules(v):
                        return False
            elif isinstance(value, list):
                for item in value:
                    if not scan_rules(item):
                        return False
            elif value is not None:
                text = str(value)
                # Regex FIRST
                if self.detect_sql_injection(text, ip):
                    return False
                if self.detect_xss(text, ip):
                    return False
            return True

        if not scan_rules(data):
            return False, "Malicious content detected by Signature Rules"

        # ML FALLBACK
        # If we got here, all rule-based scans for SQLi/XSS passed. Support ML analysis on the whole body string.
        text_representation = str(data)
        is_mal, raw_pred = ml_detect(text_representation)
        if is_mal:
            # Here we can pass context to ML in the real implementation to distinguish CSRF/SSRF.
            # Using basic categorization for now based on prompt logic we will define.
            self.ml_detections += 1
            attack_label = classify_ml_attack(text_representation)
            detection_method = "ML Model"
            logger.info(f"[ML-MODEL] {attack_label} flagged for {ip} (raw={raw_pred})")

            self.log_to_dashboard(
                attack_label,
                ip,
                f"[ML] Anomaly detected — suspicious payload: {text_representation[:60]}",
                "High",
                endpoint=request_context.get("path", ""),
                method=request_context.get("method", ""),
                snippet=text_representation[:100],
                detection_type=detection_method,
                blocked=True,
                request_id=request_context.get("request_id", ""),
            )
            return False, "Malicious anomaly detected by ML"

        return True, "OK"
def create_simple_app():
    """Create a simple Flask app for testing"""
    import os
    from pathlib import Path
    
    # Set template and static folders to use refactored structure
    project_root = Path(__file__).parent
    template_folder = str(project_root / "app" / "templates")
    static_folder = str(project_root / "app" / "static")
    
    app = Flask(__name__, 
                template_folder=template_folder,
                static_folder=static_folder)
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

        # 3c. CSRF Detection — يفحص طلبات تغيير الحالة للتوكن المطلوب
        req_context = {
            "method":       request.method,
            "path":         request.path,
            "headers":      dict(request.headers),
            "body":         request.get_json(silent=True) or {},
            "query_params": request.args.to_dict(),
            "cookies":      request.cookies.to_dict(),
            "ip":           request.remote_addr,
            "user_agent":   request.user_agent.string,
            "request_id":   getattr(request, "request_id", ""),
        }

        if _CSRF_SSRF_ENABLED and request.method in ('POST', 'PUT', 'DELETE', 'PATCH'):
            _csrf_result = detect_csrf_rule(req_context)
            if _csrf_result["detected"]:
                security.log_to_dashboard(
                    "CSRF",
                    request.remote_addr,
                    f"[CSRF R-B] {_csrf_result['reason']}",
                    _csrf_result["severity"],
                    endpoint=request.path,
                    method=request.method,
                    snippet=str(_csrf_result.get("payload", ""))[:100],
                    detection_type="Signature-based",
                    blocked=True,
                    request_id=getattr(request, "request_id", ""),
                )
                security.blocked_requests += 1
                security.update_dashboard_stats()
                return jsonify({
                    "error":  "CSRF validation failed",
                    "reason": _csrf_result["reason"],
                }), 403

        # 3d. SSRF Detection — يفحص كل URLs في الطلب للكشف عن توجيهات داخلية
        if _CSRF_SSRF_ENABLED:
            _ssrf_result = detect_ssrf_rule(req_context)
            if _ssrf_result["detected"]:
                security.log_to_dashboard(
                    "SSRF",
                    request.remote_addr,
                    f"[SSRF R-B] {_ssrf_result['reason']}",
                    _ssrf_result["severity"],
                    endpoint=request.path,
                    method=request.method,
                    snippet=str(_ssrf_result.get("payload", ""))[:100],
                    detection_type="Signature-based",
                    blocked=True,
                    request_id=getattr(request, "request_id", ""),
                )
                security.blocked_requests += 1
                security.update_dashboard_stats()
                return jsonify({
                    "error":  "SSRF attempt blocked",
                    "reason": _ssrf_result["reason"],
                }), 403

        # 3e. Content Security Scan (SQLi, XSS) via Rules THEN ML
        data_to_scan = {}
        if request.args:
            data_to_scan.update(request.args.to_dict())
        if request.is_json:
            try:
                data = request.get_json()
                if data:
                    data_to_scan.update(data)
            except:
                pass
        
        if data_to_scan:
            safe, msg = security.check_request_security(data_to_scan, request.remote_addr, req_context)
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
    
    # ── FAKE DATABASE ──────────────────────────────────────
    FAKE_USERS = [
        {'id': 1,  'username': 'ahmed.hassan',   'email': 'ahmed@shop.com',   'role': 'admin',    'joined': '2024-01-10', 'orders': 14},
        {'id': 2,  'username': 'sara.ali',        'email': 'sara@shop.com',    'role': 'user',     'joined': '2024-02-15', 'orders': 8},
        {'id': 3,  'username': 'omar.khalid',     'email': 'omar@shop.com',    'role': 'user',     'joined': '2024-03-01', 'orders': 22},
        {'id': 4,  'username': 'lina.mostafa',    'email': 'lina@shop.com',    'role': 'user',     'joined': '2024-03-20', 'orders': 5},
        {'id': 5,  'username': 'karim.farouk',    'email': 'karim@shop.com',   'role': 'manager',  'joined': '2024-04-05', 'orders': 0},
        {'id': 6,  'username': 'nour.ibrahim',    'email': 'nour@shop.com',    'role': 'user',     'joined': '2024-05-12', 'orders': 17},
        {'id': 7,  'username': 'youssef.samir',   'email': 'youssef@shop.com', 'role': 'user',     'joined': '2024-06-08', 'orders': 3},
        {'id': 8,  'username': 'dina.ramadan',    'email': 'dina@shop.com',    'role': 'user',     'joined': '2024-07-19', 'orders': 11},
    ]

    FAKE_ORDERS = [
        {'id': 1001, 'user': 'sara.ali',      'product': 'iPhone 15 Pro',       'price': 1299.99, 'status': 'delivered', 'date': '2025-01-05'},
        {'id': 1002, 'user': 'omar.khalid',   'product': 'Samsung Galaxy S24',  'price': 999.00,  'status': 'shipped',   'date': '2025-01-08'},
        {'id': 1003, 'user': 'ahmed.hassan',  'product': 'MacBook Air M3',      'price': 1499.00, 'status': 'delivered', 'date': '2025-01-12'},
        {'id': 1004, 'user': 'lina.mostafa',  'product': 'AirPods Pro',         'price': 249.99,  'status': 'pending',   'date': '2025-01-15'},
        {'id': 1005, 'user': 'nour.ibrahim',  'product': 'Sony WH-1000XM5',     'price': 349.00,  'status': 'delivered', 'date': '2025-01-18'},
        {'id': 1006, 'user': 'youssef.samir', 'product': 'iPad Pro 12.9',       'price': 1099.00, 'status': 'shipped',   'date': '2025-01-20'},
        {'id': 1007, 'user': 'dina.ramadan',  'product': 'Dell XPS 15',         'price': 1799.00, 'status': 'processing','date': '2025-01-22'},
        {'id': 1008, 'user': 'omar.khalid',   'product': 'Apple Watch Ultra 2', 'price': 799.00,  'status': 'delivered', 'date': '2025-01-25'},
        {'id': 1009, 'user': 'sara.ali',      'product': 'Logitech MX Master 3','price': 99.99,   'status': 'pending',   'date': '2025-01-28'},
        {'id': 1010, 'user': 'ahmed.hassan',  'product': 'LG OLED 4K 55"',      'price': 1599.00, 'status': 'shipped',   'date': '2025-02-01'},
    ]

    FAKE_PRODUCTS = [
        {'id': 1, 'name': 'iPhone 15 Pro',        'category': 'phones',      'price': 1299.99, 'stock': 45},
        {'id': 2, 'name': 'Samsung Galaxy S24',   'category': 'phones',      'price': 999.00,  'stock': 30},
        {'id': 3, 'name': 'MacBook Air M3',        'category': 'laptops',     'price': 1499.00, 'stock': 20},
        {'id': 4, 'name': 'Sony WH-1000XM5',       'category': 'audio',       'price': 349.00,  'stock': 60},
        {'id': 5, 'name': 'iPad Pro 12.9',         'category': 'tablets',     'price': 1099.00, 'stock': 25},
        {'id': 6, 'name': 'Dell XPS 15',           'category': 'laptops',     'price': 1799.00, 'stock': 15},
        {'id': 7, 'name': 'AirPods Pro',           'category': 'audio',       'price': 249.99,  'stock': 80},
        {'id': 8, 'name': 'Apple Watch Ultra 2',   'category': 'wearables',   'price': 799.00,  'stock': 35},
        {'id': 9, 'name': 'LG OLED 4K 55"',        'category': 'displays',    'price': 1599.00, 'stock': 12},
        {'id': 10,'name': 'Logitech MX Master 3',  'category': 'accessories', 'price': 99.99,   'stock': 100},
    ]

    # In-memory request log (last 50)
    request_log = deque(maxlen=50)

    def log_request(endpoint, method, ip, status, payload=""):
        request_log.appendleft({
            'time':     time.strftime("%H:%M:%S"),
            'endpoint': endpoint,
            'method':   method,
            'ip':       ip,
            'status':   status,
            'payload':  str(payload)[:80] if payload else ""
        })

    # ── ENDPOINTS ───────────────────────────────────────────

    @app.route('/api/users', methods=['GET'])
    def get_users():
        q = request.args.get('search', '').lower()
        results = [u for u in FAKE_USERS if q in u['username'].lower() or q in u['email'].lower()] if q else FAKE_USERS
        log_request('/api/users', 'GET', request.remote_addr, 200, q)
        return jsonify({'users': results, 'total': len(results)})

    @app.route('/api/orders', methods=['GET'])
    def get_orders():
        user_filter = request.args.get('user', '')
        results = [o for o in FAKE_ORDERS if user_filter in o['user']] if user_filter else FAKE_ORDERS
        log_request('/api/orders', 'GET', request.remote_addr, 200, user_filter)
        return jsonify({'orders': results, 'total': len(results)})

    @app.route('/api/products', methods=['GET'])
    def get_products():
        cat = request.args.get('category', '').lower()
        q   = request.args.get('search', '').lower()
        results = FAKE_PRODUCTS
        if cat and cat != 'all':
            results = [p for p in results if p['category'] == cat]
        if q:
            results = [p for p in results if q in p['name'].lower()]
        log_request('/api/products', 'GET', request.remote_addr, 200, q or cat)
        return jsonify({'products': results, 'total': len(results)})

    @app.route('/api/orders', methods=['POST'])
    def create_order():
        data = request.get_json() or {}
        new_order = {
            'id':      1000 + len(FAKE_ORDERS) + 1,
            'user':    data.get('user', 'guest'),
            'product': data.get('product', 'Unknown'),
            'price':   data.get('price', 0),
            'status':  'pending',
            'date':    time.strftime("%Y-%m-%d")
        }
        FAKE_ORDERS.append(new_order)
        log_request('/api/orders', 'POST', request.remote_addr, 201, new_order['product'])
        return jsonify({'message': 'Order created', 'order': new_order}), 201

    @app.route('/api/logs', methods=['GET'])
    def get_logs():
        return jsonify({'logs': list(request_log), 'total': len(request_log)})
    
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
                    f"IP blocked after {BRUTE_FORCE_LIMIT} failed logins: {username}",
                    "High",
                    endpoint=request.path, method=request.method,
                    snippet=f"user: {username}",
                    detection_type="Brute Force", blocked=True,
                    request_id=getattr(request, "request_id", "")
                )
                security.blocked_requests += 1
                security.update_dashboard_stats()
                return jsonify({'error': 'Too many failed attempts. IP blocked for 5 minutes.'}), 429
            else:
                security.log_to_dashboard(
                    "Brute Force", ip,
                    f"Failed login attempt {len(attempts)}/{BRUTE_FORCE_LIMIT}: {username}",
                    "Medium",
                    endpoint=request.path, method=request.method,
                    snippet=f"user: {username}",
                    detection_type="Brute Force", blocked=False,
                    request_id=getattr(request, "request_id", "")
                )
            return jsonify({'error': 'Invalid credentials'}), 401
    
    @app.route('/api/security/stats')
    def security_stats():
        return jsonify({
            'total_requests': security.total_requests,
            'blocked_requests': security.blocked_requests,
            'sql_injection_attempts': security.sql_injection_count,
            'xss_attempts': security.xss_count,
            'brute_force_attempts': security.brute_force_count,
            'uptime': time.time() - security.start_time
        })
    
    return app

if __name__ == '__main__':
    print("🛡️ API Security System with ML Started")
    app = create_simple_app()
    api_port = int(os.getenv("API_PORT", 5000))
    app.run(host="0.0.0.0", port=api_port, debug=True)
